/**
 * Copyright 2010 Christian Liesch
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @file
 *
 * @Author christian liesch <liesch@gmx.ch>
 *
 * Implementation of the HTTP Test Tool ssl module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <openssl/ssl.h>
#include <openssl/pkcs12.h>
#include "module.h"

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include "ssl.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * ssl_module = "ssl_module";

typedef struct ssl_gconf_s {
  const char *certfile;
  const char *keyfile;
  const char *cafile;
} ssl_gconf_t;

typedef struct ssl_wconf_s {
  X509 *cert;
  EVP_PKEY *pkey;
  SSL_CTX *ssl_ctx;
  SSL_METHOD *meth;
  char *ssl_info;
  int refcount;
  const char *certfile;
  const char *keyfile;
  const char *cafile;
  const char *set_ca;
  const char *cipher_suite;
#define SSL_CONFIG_FLAGS_NONE 0
#define SSL_CONFIG_FLAGS_CERT_SET 1
#define SSL_CONFIG_FLAGS_TRACE 2
  int flags;
  apr_pool_t *msg_pool;
  apr_table_t *msgs;
  worker_t *msg_worker;
} ssl_wconf_t;

typedef struct ssl_sconf_s {
  int is_ssl;
  SSL *ssl;
  SSL_SESSION *sess;
} ssl_sconf_t;

typedef struct ssl_transport_s {
  SSL *ssl;
  /* need this for timeout settings */
  transport_t *tcp_transport;
  apr_interval_time_t tmo;
} ssl_transport_t;

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * Create ssl transport context
 * @param worker IN worker
 * @return ssl transport context
 */
static ssl_transport_t *ssl_get_transport(worker_t *worker, 
                                          ssl_sconf_t *sconfig) {
  apr_interval_time_t tmo;
  ssl_transport_t *ssl_transport = apr_pcalloc(worker->pbody, sizeof(*ssl_transport));
  ssl_transport->ssl = sconfig->ssl;
  ssl_transport->tcp_transport = worker->socket->transport;
  apr_socket_timeout_get(worker->socket->socket, &tmo);
  ssl_transport->tmo = apr_time_as_msec(tmo);

  return ssl_transport;
}

/**
 * Get ssl config from global 
 *
 * @param global IN global 
 * @return ssl config
 */
static ssl_gconf_t *ssl_get_global_config(global_t *global) {
  ssl_gconf_t *config = module_get_config(global->config, ssl_module);
  if (config == NULL) {
    config = apr_pcalloc(global->pool, sizeof(*config));
    module_set_config(global->config, apr_pstrdup(global->pool, ssl_module), config);
    config->certfile = RSA_SERVER_CERT;
    config->keyfile = RSA_SERVER_KEY;
  }
  return config;
}

/**
 * Get ssl config from worker
 *
 * @param worker IN worker
 * @return ssl config
 */
static ssl_wconf_t *ssl_get_worker_config(worker_t *worker) {
  ssl_wconf_t *config = module_get_config(worker->config, ssl_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, apr_pstrdup(worker->pbody, ssl_module), config);
  }
  return config;
}

/**
 * GET ssl socket config from socket
 *
 * @param worker IN worker
 * @return socket config
 */
static ssl_sconf_t *ssl_get_socket_config(worker_t *worker) {
  ssl_sconf_t *config;

  if (!worker || !worker->socket) {
    return NULL;
  }

  config = module_get_config(worker->socket->config, ssl_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->socket->config, apr_pstrdup(worker->pbody, ssl_module), config);
  }
  return config;
}

/**
 * worker ssl handshake client site
 *
 * @param worker IN thread data object
 *
 * @return apr status
 */
static apr_status_t worker_ssl_handshake(worker_t * worker) {
  apr_status_t status;
  char *error;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);
  
  if ((status = ssl_handshake(sconfig->ssl, &error, worker->pbody)) 
      != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "%s", error);
  }
  
  if (worker->flags & FLAGS_SSL_LEGACY) {
#if (OPENSSL_VERSION_NUMBER >= 0x009080cf)
#ifdef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    sconfig->ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION; 
#else 	 
    SSL_set_options(sconfig->ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif
#endif
  }

  return status;
}

/**
 * Handle p12 client certs
 *
 * @param worker IN worker object
 * @param infile IN p12 file name
 * @param pass IN optional password
 * 
 * @return APR_SUCCESS or APR_EINVAL if invalid cert
 */
static apr_status_t worker_ssl_ctx_p12(worker_t * worker, const char *infile, 
                                       const char *pass, int check) {
  BIO *in;
  PKCS12 *p12;
  EVP_PKEY *pkey = NULL;
  X509 *cert = NULL;
  STACK_OF(X509) *ca = NULL;
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (!(in = BIO_new_file(infile, "rb"))) {
    worker_log_error(worker, "Could not open p12 \"%s\"", infile);
    return APR_EINVAL;
  }
  p12 = d2i_PKCS12_bio (in, NULL);
  if (PKCS12_parse(p12, pass, &pkey, &cert, &ca) != 0) {
    worker_log(worker, LOG_ERR, "Could not load p12 \"%s\"", infile);
    return APR_EINVAL;
  }

  worker_log(worker, LOG_DEBUG, "p12 cert: %p; key: %p; ca: %p\n", cert, pkey, ca);

  if (pkey && SSL_CTX_use_PrivateKey(config->ssl_ctx, pkey) <= 0 && check) {
    worker_log(worker, LOG_ERR, "Could not load private key of \"%s\"",
	       infile);
    return APR_EINVAL;
  }

  if (cert && SSL_CTX_use_certificate(config->ssl_ctx, cert) <= 0 && check) {
    worker_log(worker, LOG_ERR, "Could not load certificate of \"%s\"",
	       infile);
    return APR_EINVAL;
  }

  return APR_SUCCESS;
}

/**
 * tls ext call back for debugging
 * @param ssl IN ssl instance
 * @param client_server IN
 * @param type IN
 * @param data IN 
 * @param len IN 
 * @param arg IN void pointer to worker
 */
static void ssl_tlsext_trace(SSL *s, int client_server, int type, unsigned char *data, int len, void *arg) {
  worker_t *worker = arg;
  char *extname;
  char *entry;
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  switch(type) {
    case TLSEXT_TYPE_server_name:
      extname = "server name";
      break;

    case TLSEXT_TYPE_max_fragment_length:
      extname = "max fragment length";
      break;

    case TLSEXT_TYPE_client_certificate_url:
      extname = "client certificate URL";
      break;

    case TLSEXT_TYPE_trusted_ca_keys:
      extname = "trusted CA keys";
      break;

    case TLSEXT_TYPE_truncated_hmac:
      extname = "truncated HMAC";
      break;

    case TLSEXT_TYPE_status_request:
      extname = "status request";
      break;

    case TLSEXT_TYPE_elliptic_curves:
      extname = "elliptic curves";
      break;

    case TLSEXT_TYPE_ec_point_formats:
      extname = "EC point formats";
      break;

    case TLSEXT_TYPE_session_ticket:
      extname = "server ticket";
      break;

    case TLSEXT_TYPE_renegotiate:
      extname = "renegotiate";
      break;

#ifdef TLSEXT_TYPE_opaque_prf_input
    case TLSEXT_TYPE_opaque_prf_input:
      extname = "opaque PRF input";
      break;
#endif

    default:
      extname = "unknown";
      break;

  }

  entry = apr_psprintf(config->msg_pool, "+TLS %s extension, %s, id=%d", 
                       client_server ? "server": "client",
                       extname, type);
  apr_table_addn(config->msgs, apr_psprintf(config->msg_pool, "TRUE"), entry);
  worker_log(worker, LOG_INFO, "%s", entry);

}

/**
 * Message call back for debugging
 * @param write_p IN write/read
 * @param version IN SSL version
 * @param content_type IN SSL message content type
 * @param buf IN SSL message
 * @param len IN SSL message length
 * @param ssl IN ssl instance
 * @param arg IN void pointer to worker
 */
static void ssl_message_trace(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl, void *arg)
{
  worker_t *worker = arg;
  char *entry;
  const char *str_write_p, *str_version, *str_content_type = "", *str_details1 = "", *str_details2= "";
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  str_write_p = write_p ? ">" : "<";

  switch (version) {
    case SSL2_VERSION:
      str_version = "SSL 2.0";
      break;
    case SSL3_VERSION:
      str_version = "SSL 3.0";
      break;
    case TLS1_VERSION:
      str_version = "TLS 1.0";
      break;
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL)
    case TLS1_1_VERSION:
      str_version = "TLS 1.1";
      break;
    case TLS1_2_VERSION:
      str_version = "TLS 1.2";
      break;
#endif
    case DTLS1_VERSION:
      str_version = "DTLS 1.0";
      break;
    case DTLS1_BAD_VER:
      str_version = "DTLS 1.0 (bad)";
      break;
    default:
      str_version = "???";
  }

  if (version == SSL2_VERSION) {
    str_details1 = "???";

    if (len > 0) {
      switch (((const unsigned char*)buf)[0]) {
        case 0:
          str_details1 = ", ERROR:";
          str_details2 = " ???";
          if (len >= 3) {
            unsigned err = (((const unsigned char*)buf)[1]<<8) + ((const unsigned char*)buf)[2];

            switch (err) {
              case 0x0001:
                str_details2 = " NO-CIPHER-ERROR";
                break;
              case 0x0002:
                str_details2 = " NO-CERTIFICATE-ERROR";
                break;
              case 0x0004:
                str_details2 = " BAD-CERTIFICATE-ERROR";
                break;
              case 0x0006:
                str_details2 = " UNSUPPORTED-CERTIFICATE-TYPE-ERROR";
                break;
            }
          }

          break;
        case 1:
          str_details1 = ", CLIENT-HELLO";
          break;
        case 2:
          str_details1 = ", CLIENT-MASTER-KEY";
          break;
        case 3:
          str_details1 = ", CLIENT-FINISHED";
          break;
        case 4:
          str_details1 = ", SERVER-HELLO";
          break;
        case 5:
          str_details1 = ", SERVER-VERIFY";
          break;
        case 6:
          str_details1 = ", SERVER-FINISHED";
          break;
        case 7:
          str_details1 = ", REQUEST-CERTIFICATE";
          break;
        case 8:
          str_details1 = ", CLIENT-CERTIFICATE";
          break;
      }
    }
  }

  if (version == SSL3_VERSION ||
      version == TLS1_VERSION ||
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL)
      version == TLS1_2_VERSION ||
      version == TLS1_1_VERSION ||
#endif
      version == DTLS1_VERSION ||
      version == DTLS1_BAD_VER) {
    switch (content_type) {
      case 20:
        str_content_type = "ChangeCipherSpec";
        break;
      case 21:
        str_content_type = "Alert";
        break;
      case 22:
        str_content_type = "Handshake";
        break;
    }

    if (content_type == 21) {
      str_details1 = ", ???";

      if (len == 2) {
        switch (((const unsigned char*)buf)[0])
        {
          case 1:
            str_details1 = ", warning";
            break;
          case 2:
            str_details1 = ", fatal";
            break;
        }

        str_details2 = " ???";
        switch (((const unsigned char*)buf)[1]) {
          case 0:
            str_details2 = " close_notify";
            break;
          case 10:
            str_details2 = " unexpected_message";
            break;
          case 20:
            str_details2 = " bad_record_mac";
            break;
          case 21:
            str_details2 = " decryption_failed";
            break;
          case 22:
            str_details2 = " record_overflow";
            break;
          case 30:
            str_details2 = " decompression_failure";
            break;
          case 40:
            str_details2 = " handshake_failure";
            break;
          case 42:
            str_details2 = " bad_certificate";
            break;
          case 43:
            str_details2 = " unsupported_certificate";
            break;
          case 44:
            str_details2 = " certificate_revoked";
            break;
          case 45:
            str_details2 = " certificate_expired";
            break;
          case 46:
            str_details2 = " certificate_unknown";
            break;
          case 47:
            str_details2 = " illegal_parameter";
            break;
          case 48:
            str_details2 = " unknown_ca";
            break;
          case 49:
            str_details2 = " access_denied";
            break;
          case 50:
            str_details2 = " decode_error";
            break;
          case 51:
            str_details2 = " decrypt_error";
            break;
          case 60:
            str_details2 = " export_restriction";
            break;
          case 70:
            str_details2 = " protocol_version";
            break;
          case 71:
            str_details2 = " insufficient_security";
            break;
          case 80:
            str_details2 = " internal_error";
            break;
          case 90:
            str_details2 = " user_canceled";
            break;
          case 100:
            str_details2 = " no_renegotiation";
            break;
          case 110:
            str_details2 = " unsupported_extension";
            break;
          case 111:
            str_details2 = " certificate_unobtainable";
            break;
          case 112:
            str_details2 = " unrecognized_name";
            break;
          case 113:
            str_details2 = " bad_certificate_status_response";
            break;
          case 114:
            str_details2 = " bad_certificate_hash_value";
            break;
          case 115:
            str_details2 = " unknown_psk_identity";
            break;
        }
      }
    }

    if (content_type == 22) {
      str_details1 = "???";

      if (len > 0) {
        switch (((const unsigned char*)buf)[0]) {
          case 0:
            str_details1 = ", HelloRequest";
            break;
          case 1:
            str_details1 = ", ClientHello";
            break;
          case 2:
            str_details1 = ", ServerHello";
            break;
          case 3:
            str_details1 = ", HelloVerifyRequest";
            break;
          case 11:
            str_details1 = ", Certificate";
            break;
          case 12:
            str_details1 = ", ServerKeyExchange";
            break;
          case 13:
            str_details1 = ", CertificateRequest";
            break;
          case 14:
            str_details1 = ", ServerHelloDone";
            break;
          case 15:
            str_details1 = ", CertificateVerify";
            break;
          case 16:
            str_details1 = ", ClientKeyExchange";
            break;
          case 20:
            str_details1 = ", Finished";
            break;
        }
      }
    }

#ifndef OPENSSL_NO_HEARTBEATS
    if (content_type == 24) /* Heartbeat */ {
      str_details1 = ", Heartbeat";

      if (len > 0) {
        switch (((const unsigned char*)buf)[0]) {
          case 1:
            str_details1 = ", HeartbeatRequest";
            break;
          case 2:
            str_details1 = ", HeartbeatResponse";
            break;
        }
      }
    }
#endif
  }

  entry = apr_psprintf(config->msg_pool, "%s%s: %s%s%s", str_write_p, 
      str_version, str_content_type, str_details1, str_details2);
  apr_table_addn(config->msgs, apr_psprintf(config->msg_pool, "TRUE"), entry);
  worker_log(worker, LOG_INFO, "%s", entry);
}

/**
 * Get server ctx with loaded cert and key file
 *
 * @param worker IN thread object data
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
static apr_status_t worker_ssl_ctx(worker_t * worker, const char *certfile, 
                            const char *keyfile, const char *ca, int check) {
  int len = 0;
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (config->flags & SSL_CONFIG_FLAGS_CERT_SET) {
    return APR_SUCCESS;
  }

  if (certfile && !keyfile && !ca) {
    ca = certfile;
    certfile = NULL;
  }

  if (config->set_ca && !ca) {
    ca = config->set_ca;
  }

  /* test if there are the same cert, key ca files or no certs at all */
  if (!(
      (((!config->certfile && !certfile) || 
      (config->certfile && certfile && strcmp(config->certfile, certfile) == 0)) &&
      ((!config->keyfile && !keyfile) ||
      (config->keyfile && keyfile && strcmp(config->keyfile, keyfile) == 0)) &&
      ((!config->cafile && !ca) ||
      (config->cafile && ca && strcmp(config->cafile, ca) == 0))))) {
    /* if there are not the same cert, key, ca files reinitialize ssl_ctx */
    if (config->ssl_ctx) {
      SSL_CTX_free(config->ssl_ctx);
      config->ssl_ctx = NULL;
    }
  }

  config->certfile = certfile;
  config->keyfile = keyfile;
  config->cafile = ca;

  worker_log(worker, LOG_DEBUG, "cert: %s; key: %s; ca: %s\n", 
             certfile?certfile:"(null)",
             keyfile?keyfile:"(null)",
             ca?ca:"(null)");
  if (!config->ssl_ctx) {
    if (!(config->ssl_ctx = SSL_CTX_new(config->meth))) {
      worker_log(worker, LOG_ERR, "Could not initialize SSL Context.");
      return APR_EINVAL;
    }
  }

  /* test if it is a p12 cert */
  if (certfile) {
    len = strlen(certfile);
    if (len > 4) {
      worker_log(worker, LOG_DEBUG, "certifcate suffix \"%s\"", &certfile[len-4]);
    }  
  }
  if (len > 4 && strcmp(&certfile[len - 4], ".p12") == 0) {
    apr_status_t status;
    worker_log(worker, LOG_DEBUG, "pkcs12 certifcate");
    if ((status = worker_ssl_ctx_p12(worker, certfile, keyfile, check))
	!= APR_SUCCESS) {
      return status;
    }
  }
  else {
    worker_log(worker, LOG_DEBUG, "pem formated cert and key");
    if (certfile && SSL_CTX_use_certificate_file(config->ssl_ctx, certfile, 
						 SSL_FILETYPE_PEM) <= 0 && 
	check) { 
      worker_log(worker, LOG_ERR, "Could not load certifacte \"%s\"",
		 certfile);
      return APR_EINVAL;
    }
    if (keyfile && SSL_CTX_use_PrivateKey_file(config->ssl_ctx, keyfile, 
					       SSL_FILETYPE_PEM) <= 0 && 
	check) {
      worker_log(worker, LOG_ERR, "Could not load private key \"%s\"",
		 keyfile);
      return APR_EINVAL;
    }
    if (ca && !SSL_CTX_load_verify_locations(config->ssl_ctx, ca,
					     NULL) && check) {
      worker_log(worker, LOG_ERR, "Could not load CA file \"%s\"", ca);
      return APR_EINVAL;
    }

    if (certfile && keyfile&& check && 
	!SSL_CTX_check_private_key(config->ssl_ctx)) {
      worker_log(worker, LOG_ERR, "Private key does not match the certificate public key");
      return APR_EINVAL;
    }
  }
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
  SSL_CTX_set_verify_depth(config->ssl_ctx,1);
#endif
  return APR_SUCCESS;
}

/**
 * Get client method 
 *
 * @param worker IN thread object data
 * @param sslstr IN SSL|SSL2|SSL3|TLS1|DTLS1
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
static int worker_set_client_method(worker_t * worker, const char *sslstr) {
  int is_ssl = 0;
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (strcasecmp(sslstr, "SSL") == 0) {
    is_ssl = 1;
    config->meth = SSLv23_client_method();
  }
#ifndef OPENSSL_NO_SSL2 
  else if (strcasecmp(sslstr, "SSL2") == 0) {
    is_ssl = 1;
    config->meth = SSLv2_client_method();
  }
#endif
  else if (strcasecmp(sslstr, "SSL3") == 0) {
    is_ssl = 1;
    config->meth = SSLv3_client_method();
  }
  else if (strcasecmp(sslstr, "TLS1") == 0) {
    is_ssl = 1;
    config->meth = TLSv1_client_method();
  }
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL)
  else if (strcasecmp(sslstr, "TLS1.1") == 0) {
    is_ssl = 1;
    config->meth = TLSv1_1_client_method();
  }
  else if (strcasecmp(sslstr, "TLS1.2") == 0) {
    is_ssl = 1;
    config->meth = TLSv1_2_client_method();
  }
#endif
  else if (strcasecmp(sslstr, "DTLS1") == 0) {
    is_ssl = 1;
    config->meth = DTLSv1_client_method();
  }
  return is_ssl;
}

/**
 * Get server method 
 *
 * @param worker IN thread object data
 * @param sslstr IN SSL|SSL2|SSL3|TLS1|DTLS1
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
static int worker_set_server_method(worker_t * worker, const char *sslstr) {
  int is_ssl = 0;
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (strcasecmp(sslstr, "SSL") == 0) {
    is_ssl = 1;
    config->meth = SSLv23_server_method();
  } 
#ifndef OPENSSL_NO_SSL2
  else if (strcasecmp(sslstr, "SSL2") == 0) {
    is_ssl = 1;
    config->meth = SSLv2_server_method();
  }
#endif
  else if (strcasecmp(sslstr, "SSL3") == 0) {
    is_ssl = 1;
    config->meth = SSLv3_server_method();
  }
  else if (strcasecmp(sslstr, "TLS1") == 0) {
    is_ssl = 1;
    config->meth = TLSv1_server_method();
  }
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL)
  else if (strcasecmp(sslstr, "TLS1.1") == 0) {
    is_ssl = 1;
    config->meth = TLSv1_1_server_method();
  }
  else if (strcasecmp(sslstr, "TLS1.2") == 0) {
    is_ssl = 1;
    config->meth = TLSv1_2_server_method();
  }
#endif
  else if (strcasecmp(sslstr, "DTLS1") == 0) {
    is_ssl = 1;
    config->meth = DTLSv1_server_method();
  }
  return is_ssl;
}

/**
 * create new ssl instance
 *
 * @param worker IN callee
 * @return apr status
 */
static apr_status_t ssl_new_instance(worker_t *worker) {
  ssl_wconf_t *config = ssl_get_worker_config(worker);
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (config->msg_worker) {
    worker_destroy(config->msg_worker);
  }
  worker_new(&config->msg_worker, NULL, worker->prefix, worker->global, worker->interpret); 
  config->msg_worker->config = worker->config;

  if ((sconfig->ssl = SSL_new(config->ssl_ctx)) == NULL) {
    worker_log(worker, LOG_ERR, "SSL_new failed.");
    return APR_ECONNREFUSED;
  }
  SSL_set_ssl_method(sconfig->ssl, config->meth);
  if (config->flags & SSL_CONFIG_FLAGS_TRACE) {
#ifndef OPENSSL_NO_TLSEXT
    SSL_set_tlsext_debug_callback(sconfig->ssl, ssl_tlsext_trace);
    SSL_set_tlsext_debug_arg(sconfig->ssl, config->msg_worker);
#endif
    SSL_set_msg_callback(sconfig->ssl, ssl_message_trace);
    SSL_set_msg_callback_arg(sconfig->ssl, config->msg_worker);
  }
  if (config->cipher_suite != NULL) {
    if (SSL_set_cipher_list(sconfig->ssl, config->cipher_suite) == 0) {
      return APR_EINVAL;
    }
  }
  return APR_SUCCESS;
}

/**
 * Do a ssl accept
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS
 */
static apr_status_t worker_ssl_accept(worker_t * worker) {
  apr_status_t status;
  char *error;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (worker->socket->is_ssl) {
    if (!sconfig->ssl) {
      BIO *bio;
      apr_os_sock_t fd;

      if ((status = ssl_new_instance(worker)) != APR_SUCCESS) {
        return status;
      }

      /**
       * openssl 1.0.1b want this ...
       * Have to understand this first, before I do add it
      SSL_set_session_id_context(sconfig->ssl, "foobar", strlen("foobar"));
       */

      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(sconfig->ssl, bio, bio);
    }
    else {
      return APR_SUCCESS;
    }
  }
  else {
    return APR_SUCCESS;
  }

  if ((status = ssl_accept(sconfig->ssl, &error, worker->pbody)) 
      != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "%s", error);
  }
  return status;
}

/**
 * Get os socket descriptor
 *
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return APR_ENOENT
 */
static apr_status_t ssl_transport_os_desc_get(void *data, int *desc) {
  return APR_ENOENT;
}

/**
 * Set timeout
 *
 * @param data IN void pointer to socket
 * @param t IN timeout 
 * @return APR_ENOENT
 */
static apr_status_t ssl_transport_set_timeout(void *data, apr_interval_time_t t) {
  ssl_transport_t *ssl_transport = data;

  ssl_transport->tmo = t;
  return transport_set_timeout(ssl_transport->tcp_transport, t);
}

/**
 * Get timeout
 *
 * @param data IN void pointer to socket
 * @param t OUT timeout 
 * @return APR_ENOENT
 */
static apr_status_t ssl_transport_get_timeout(void *data, apr_interval_time_t *t) {
  ssl_transport_t *ssl_transport = data;

  return transport_get_timeout(ssl_transport->tcp_transport, t);
}

/**
 * read from socket
 *
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t ssl_transport_read(void *data, char *buf, apr_size_t *size) {
  ssl_transport_t *ssl_transport = data;
  apr_status_t status;
  apr_time_t start = apr_time_now();
  apr_time_t cur;

tryagain:
  cur = apr_time_now();
  if (apr_time_as_msec(cur) - apr_time_as_msec(start) > ssl_transport->tmo) {
    return APR_TIMEUP;
  }
  
  apr_sleep(1);
  status = SSL_read(ssl_transport->ssl, buf, *size);
  if (status <= 0) {
    int scode = SSL_get_error(ssl_transport->ssl, status);

    if (scode == SSL_ERROR_ZERO_RETURN) {
      *size = 0;
      return APR_EOF;
    }
    else if (scode != SSL_ERROR_WANT_WRITE && scode != SSL_ERROR_WANT_READ) {
      *size = 0;
      return APR_ECONNABORTED;
    }
    else {
      goto tryagain;
    }
  }
  else {
    *size = status;
    return APR_SUCCESS;
  }

  return APR_ENOTIMPL;
}

/**
 * write to socket
 *
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t ssl_transport_write(void *data, const char *buf, apr_size_t size) {
  ssl_transport_t *ssl_transport = data;
  apr_size_t e_ssl;

tryagain:
  apr_sleep(1);
  e_ssl = SSL_write(ssl_transport->ssl, buf, size);
  if (e_ssl != size) {
    int scode = SSL_get_error(ssl_transport->ssl, e_ssl);
    if (scode == SSL_ERROR_WANT_WRITE) {
      goto tryagain;
    }
    return APR_ECONNABORTED;
  }

  return APR_SUCCESS;
}

/************************************************************************
 * Commands
 ***********************************************************************/

/**
 * SSL:SET_DEFAULT_CERT command
 * @param worker IN thread data object
 * @param data IN
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t block_SSL_SET_DEFAULT_CERT(worker_t * worker, 
                                               worker_t *parent,
                                               apr_pool_t *ptmp) {
  apr_status_t status;
  global_t *global = worker->global;
  ssl_gconf_t *gconf = ssl_get_global_config(global);

  if ((status = module_check_global(worker)) != APR_SUCCESS) {
    return status;
  }

  gconf->certfile = store_get_copy(worker->params, global->pool, "1");
  gconf->keyfile = store_get_copy(worker->params, global->pool, "2");
  gconf->cafile = store_get_copy(worker->params, global->pool, "3");

  return APR_SUCCESS;
}

/**
 * Connect block
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_CONNECT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *sslstr;
  int is_ssl;
  BIO *bio;
  apr_os_sock_t fd;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  sslstr = store_get(worker->params, "1");
  if (!sslstr) {
    worker_log_error(worker, "Missing type, must be one of SSL|SSL2|SSL3|TLS1");
    return APR_EGENERAL;
  }

  is_ssl = worker_set_client_method(worker, sslstr);
  if (!is_ssl) {
    worker_log(worker, LOG_ERR, "%s is not supported", sslstr);
    return APR_ENOTIMPL;
  }
  worker->socket->is_ssl = is_ssl;

  if (worker->socket->socket_state == SOCKET_CONNECTED) {
    if (worker->socket->is_ssl) {
      transport_t *transport;
      ssl_transport_t *ssl_transport;
      const char *cert;
      const char *key;
      const char *ca;
      apr_status_t status;

      cert = store_get(worker->params, "2");
      key = store_get(worker->params, "3");
      ca = store_get(worker->params, "4");
      if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) != APR_SUCCESS) {
	return status;
      }

      if ((status = ssl_new_instance(worker)) != APR_SUCCESS) {
        return status;
      }

      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(sconfig->ssl, bio, bio);
      if (sconfig->sess) {
	SSL_set_session(sconfig->ssl, sconfig->sess);
	SSL_SESSION_free(sconfig->sess);
	sconfig->sess = NULL;
      }
      SSL_set_connect_state(sconfig->ssl);

      if ((status = worker_ssl_handshake(worker)) != APR_SUCCESS) {
				return status;
      }

      ssl_transport = ssl_get_transport(worker, sconfig);
      transport = transport_new(ssl_transport, worker->pbody, 
				ssl_transport_os_desc_get, 
				ssl_transport_set_timeout, 
				ssl_transport_get_timeout, 
				ssl_transport_read, 
				ssl_transport_write);
      transport_register(worker->socket, transport);
    }
  }
  else {
    worker_log_error(worker, "Can not do a SSL connect, cause no TCP connection available");
    return APR_EGENERAL;
  }
  return APR_SUCCESS;
}

/**
 * Accept block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_ACCEPT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *sslstr;
  int is_ssl;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  sslstr = store_get(worker->params, "1");
  if (!sslstr) {
    worker_log_error(worker, "Missing type, must be one of SSL|SSL2|SSL3|TLS1");
    return APR_EGENERAL;
  }

  is_ssl = worker_set_server_method(worker, sslstr);
  if (!is_ssl) {
    worker_log(worker, LOG_ERR, "%s is not supported", sslstr);
    return APR_ENOTIMPL;
  }
  worker->socket->is_ssl = is_ssl;

  if (worker->socket->socket_state == SOCKET_CONNECTED) {
    if (worker->socket->is_ssl) {
      transport_t *transport;
      ssl_transport_t *ssl_transport;
      const char *cert;
      const char *key;
      const char *ca;
      apr_status_t status;
      ssl_gconf_t *gconf = ssl_get_global_config(worker->global);

      cert = store_get(worker->params, "2");
      key = store_get(worker->params, "3");
      ca = store_get(worker->params, "4");
      if (!cert) {
	cert = gconf->certfile;
      }
      if (!key) {
	key = gconf->keyfile;
      }
      if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) != APR_SUCCESS) {
	return status;
      }

      if ((status = worker_ssl_accept(worker)) != APR_SUCCESS) {
	return status;
      }
      ssl_transport = ssl_get_transport(worker, sconfig);
      transport = transport_new(ssl_transport, worker->pbody, 
				ssl_transport_os_desc_get, 
				ssl_transport_set_timeout, 
				ssl_transport_get_timeout, 
				ssl_transport_read, 
				ssl_transport_write);
      transport_register(worker->socket, transport);
    }
  }
  else {
    worker_log_error(worker, "Can not do a SSL connect, cause no TCP connection available");
    return APR_EGENERAL;
  }
  return APR_SUCCESS;
}

/**
 * Close block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_CLOSE(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  return command_CLOSE(NULL, worker, "SSL", ptmp);
}


/**
 * Get session block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_GET_SESSION(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *copy = store_get(worker->params, "1");
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (!copy) {
    worker_log_error(worker, "Missing varibale name to store session in");
    return APR_EGENERAL;
  }

  if (!worker->socket || !worker->socket->socket || !worker->socket->is_ssl) {
    worker_log_error(worker, "No established ssl socket");
    return APR_ENOSOCKET;
  }

  if (worker->socket->is_ssl) {
    if (sconfig->ssl) {
      apr_size_t b64_len;
      char *b64_str;
      apr_size_t enc_len;
      unsigned char *enc;
      unsigned char *tmp;
      SSL_SESSION *sess = SSL_get_session(sconfig->ssl);
      /* serialize to a variable an store it */
      enc_len = i2d_SSL_SESSION(sess, NULL);
      enc = apr_pcalloc(ptmp, enc_len);
      tmp = enc;
      enc_len = i2d_SSL_SESSION(sess, &tmp);
      b64_len = apr_base64_encode_len(enc_len);
      b64_str = apr_pcalloc(ptmp, b64_len);
      apr_base64_encode_binary(b64_str, enc, enc_len);
      worker_var_set(parent, copy, b64_str);
    }
  }

  return APR_SUCCESS;
}

/**
 * Set session block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_SET_SESSION(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *copy = store_get(worker->params, "1");
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (!copy) {
    worker_log_error(worker, "Missing session to set on SSL");
    return APR_EGENERAL;
  }

  if (!worker->socket) {
    worker_log_error(worker, "No established ssl socket");
    return APR_ENOSOCKET;
  }

  {
    apr_size_t enc_len;
    unsigned char *enc;
    const unsigned char *tmp;
    const char *b64_str = copy;
    if (b64_str) {
      enc_len = apr_base64_decode_len(b64_str);
      enc = apr_pcalloc(ptmp, enc_len);
      apr_base64_decode_binary(enc, b64_str);
      tmp = enc;
      sconfig->sess = d2i_SSL_SESSION(NULL, &tmp, enc_len);
    }
    else {
      worker_log_error(worker, "Variable \"%s\" does not exist", copy);
      return APR_ENOENT;
    }
  }

  return APR_SUCCESS;
}

/**
 * Set session block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_GET_SESSION_ID(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *copy = store_get(worker->params, "1");
  SSL_SESSION *sess;
  char *val;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (!copy) {
    worker_log_error(worker, "Missing varibale name to store session in");
    return APR_EGENERAL;
  }

  if (!worker->socket || !sconfig->ssl) {
    worker_log_error(worker, "Need an ssl connection");
    return APR_ENOSOCKET;
  }

  sess = SSL_get_session(sconfig->ssl);

  if (sess) {
    val = apr_pcalloc(ptmp, apr_base64_encode_len(sess->session_id_length));
    apr_base64_encode_binary(val, sess->session_id, sess->session_id_length);

    worker_var_set(parent, copy, val);
  }
  else {
    return APR_ENOENT;
  }

  return APR_SUCCESS;
}

/**
 * Set session block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_RENEG_CERT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  int rc;
  const char *copy = store_get(worker->params, "1");

  ssl_wconf_t *config = ssl_get_worker_config(worker);
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (config->cert) {
    X509_free(config->cert);
  }
  
  config->cert = NULL;

  if (!worker->socket->is_ssl || !sconfig->ssl) {
    worker_log(worker, LOG_ERR, 
	       "No ssl connection established can not verify peer");
    return APR_ENOSOCKET;
  }

  if (worker->flags & FLAGS_SERVER) {
    /* if we are server request the peer cert */
    if (copy && strcasecmp(copy, "verify") == 0) {
      if (worker->log_mode >= LOG_DEBUG) {
        SSL_set_verify(sconfig->ssl,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       debug_verify_callback);
      }
      else {
        SSL_set_verify(sconfig->ssl,
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       NULL);
      }
    }
    else {
      SSL_set_verify(sconfig->ssl,
                     SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                     skip_verify_callback);
    }
    SSL_set_session_id_context(sconfig->ssl, (void *)ssl_module, strlen(ssl_module));

    if (worker->flags & FLAGS_SSL_LEGACY) {
#if (OPENSSL_VERSION_NUMBER >= 0x009080cf)
#ifdef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
      sconfig->ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
#else
      SSL_set_options(sconfig->ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif
#endif
    }

    if((rc = SSL_renegotiate(sconfig->ssl) <= 0)) {
      worker_log(worker, LOG_ERR, "SSL renegotiation a error: %d", rc);
      return APR_EACCES;
    }
    worker_ssl_handshake(worker);
    sconfig->ssl->state=SSL_ST_ACCEPT;
    worker_ssl_handshake(worker);

    config->cert = SSL_get_peer_certificate(sconfig->ssl);
    if (copy && strcasecmp(copy, "verify") == 0) {
      if (!config->cert) {
	worker_log(worker, LOG_ERR, "No peer certificate");
	return APR_EACCES;
      }
    }
  }
  else {
    config->cert = SSL_get_peer_certificate(sconfig->ssl);
    if (!config->cert) {
      worker_log(worker, LOG_ERR, "No peer certificate");
      return APR_EACCES;
    }

    if (copy && strcasecmp(copy, "verify") == 0) {
      if((rc = SSL_get_verify_result(sconfig->ssl)) != X509_V_OK) {
	worker_log(worker, LOG_ERR, "SSL peer verify failed: %s(%d)",
	X509_verify_cert_error_string(rc), rc);
	return APR_EACCES;
      }
    }
  }

  return APR_SUCCESS;
}

/**
 * SSL_CERT_VAL command
 
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_GET_CERT_VALUE(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  char *val = NULL;
  const char *cmd = store_get(worker->params, "1");
  const char *var = store_get(worker->params, "2");

  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (!cmd) {
    worker_log_error(worker, "SSL variable name is missing");
    return APR_EGENERAL;
  }

  if (!var) {
    worker_log_error(worker, "variable name to store result is missing");
    return APR_EGENERAL;
  }

  if (!config || !config->cert) {
    worker_log_error(worker, "no peer cert");
    return APR_EINVAL;
  }
  
  val = ssl_var_lookup_ssl_cert(ptmp, config->cert, cmd);

  if (!val) {
    worker_log_error(worker, "SSL value for \"%s\" not found", cmd);
    return APR_ENOENT;
  }

  worker_var_set(parent, var, val);

  return APR_SUCCESS;
}

/**
 * SSL_SECURE_RENEG_SUPPORTED command
 *
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SSL_SET_ENGINE(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
#ifndef OPENSSL_NO_ENGINE
  const char *copy = store_get(worker->params, "1");
  BIO *bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);

  if (!setup_engine(bio_err, copy, worker->log_mode == LOG_DEBUG ? 1 : 0)) {
    worker_log(worker, LOG_ERR, "Could not initialize engine \"%s\".", copy);
    return APR_EINVAL;
  }
#endif
  return APR_ENOTIMPL;
}

/**
 * SSL_CIPHER_SUITE command
 *
 * See http://www.openssl.org/docs/apps/ciphers.html
 *
 * @param worker IN thread data object
 * @param data IN
 *
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t block_SSL_CIPHER_SUITE(worker_t * worker, worker_t *parent,
                                           apr_pool_t *ptmp) {
  ssl_wconf_t *config = ssl_get_worker_config(worker);
  const char *val = store_get(worker->params, "1");
  char *copy = apr_pstrdup(worker->pbody, val);
  config->cipher_suite = copy;
  return APR_SUCCESS;
}

/**
 * SSL_LEGACY command
 *
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SSL_SET_LEGACY(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *copy = store_get(worker->params, "1");

  if (strcasecmp(copy,  "on") == 0) {
    worker->flags |= FLAGS_SSL_LEGACY;
  }
  else {
    worker->flags &= ~FLAGS_SSL_LEGACY;
  }
  return APR_SUCCESS;
}

/**
 * SSL_LOAD_CERT command
 *
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_LOAD_CERT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *val = store_get(worker->params, "1");
  char *copy = apr_pstrdup(worker->pbody, val);
  BIO *mem;

  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (config->cert) {
    X509_free(config->cert);
  }
  
  mem = BIO_new_mem_buf(copy, strlen(copy));
  config->cert = PEM_read_bio_X509(mem,NULL,NULL,NULL);

  if (!config->cert) {
    worker_log_error(worker, "Not a valid cert (PEM)");
    return APR_EINVAL;
  }
  return APR_SUCCESS;
}

/**
 * SSL_LOAD_KEY command
 *
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_LOAD_KEY(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *val = store_get(worker->params, "1");
  char *copy = apr_pstrdup(worker->pbody, val);
  BIO *mem;

  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (config->pkey) {
    EVP_PKEY_free(config->pkey);
  }
  
  mem = BIO_new_mem_buf(copy, strlen(copy));
  config->pkey = PEM_read_bio_PrivateKey(mem,NULL,NULL,NULL);

  if (!config->pkey) {
    worker_log_error(worker, "Not a valid cert (PEM)");
    return APR_EINVAL;
  }
  return APR_SUCCESS;
}

/**
 * SSL_SET_CERT command
 *
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_SET_CERT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (!config->ssl_ctx) {
    worker_log_error(worker, "Can not set cert, ssl not enabled in %s",
	             (worker->flags & FLAGS_SERVER) ? "SERVER" : "CLIENT");
    return APR_EINVAL;
  }

  /* check if we have parameters */
  if (store_get_size(worker->params)) {
    const char *cert;
    const char *key;
    const char *ca;
    cert = store_get(worker->params, "1");
    key = store_get(worker->params, "2");
    ca = store_get(worker->params, "3");
    worker_ssl_ctx(worker, cert, key, ca, 1);
    config->flags |= SSL_CONFIG_FLAGS_CERT_SET;
    return  APR_SUCCESS;
  }

  /* else set cert */
  if (!config || !config->cert) {
    worker_log_error(worker, "No cert to use, get a cert with _SSL:LOAD_CERT");
    return APR_EINVAL;
  }

  if (SSL_CTX_use_certificate(config->ssl_ctx, config->cert) <=0) {
    worker_log_error(worker, "Can not use this cert");
    return APR_EINVAL;
  }
  return APR_SUCCESS;
}

/**
 * SSL_SET_CA command
 *
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_SET_CA(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  /* check if we have parameters */
  if (store_get_size(worker->params)) {
    config->set_ca = store_get(worker->params, "1");
    return  APR_SUCCESS;
  }

  return APR_SUCCESS;
}

/**
 * SSL_SECURE_RENEG_SUPPORTED command
 *
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SSL_SECURE_RENEG_SUPPORTED(worker_t * worker, 
                                                     worker_t *parent, apr_pool_t *ptmp) {
#if (define USE_SSL && OPENSSL_VERSION_NUMBER >= 0x009080ff)
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);
  if (SSL_get_secure_renegotiation_support(sconfig->ssl)) {
    return APR_SUCCESS;
  }
  else {
    return APR_EINVAL;
  }
#else
  return APR_ENOTIMPL;
#endif
}

/**
 * SSL_TRACE_START command
 *
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SSL_TRACE(worker_t * worker, worker_t *parent, 
                                    apr_pool_t *ptmp) {
  apr_pool_t *pool;
  ssl_wconf_t *config = ssl_get_worker_config(worker);
  config->flags |= SSL_CONFIG_FLAGS_TRACE;
  apr_pool_create(&pool, NULL);
  config->msg_pool = pool;
  config->msgs = apr_table_make(pool, 5);
  return APR_SUCCESS;
}

/**
 * clone worker
 *
 * @param worker IN
 * @param clone IN 
 * @return APR_SUCCESS
 */
static apr_status_t ssl_worker_clone(worker_t *worker, worker_t *clone) {
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  worker_get_socket(clone, "Default", "0");
  clone->socket->is_ssl = worker->socket->is_ssl;

  if (config->meth) {
    ssl_wconf_t *clone_config = ssl_get_worker_config(clone);
    /* copy workers content to clone */
    memcpy(clone_config, config, sizeof(*clone_config)); 
    clone_config->ssl_ctx = NULL;
    return worker_ssl_ctx(clone, config->certfile, config->keyfile, config->cafile, 0);
  }
  return APR_SUCCESS;
}

/**
 * parse line and extract the SSL relevant stuff
 *
 * @param worker IN
 * @param line IN original line
 * @param new_line OUT manipulated
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t ssl_client_port_args(worker_t *worker, char *portinfo, 
                                         char **new_portinfo, char *rest) {
  apr_status_t status;
  char *port;
  char *last;
  char *copy = apr_pstrdup(worker->pbody, portinfo);
  char *sslstr = apr_strtok(copy, ":", &port);
  char *cert = NULL;
  char *key = NULL;
  char *ca = NULL;
  ssl_wconf_t *config = ssl_get_worker_config(worker);

  if (!worker->socket) {
    worker_log_error(worker, "No socket available");
    return APR_ENOSOCKET;
  }

  if (worker->socket->socket_state == SOCKET_CONNECTED) {
    return APR_SUCCESS;
  }

  worker->socket->is_ssl = worker_set_client_method(worker, sslstr);
  
  if (!worker->socket->is_ssl) {
    /* nothing to do give the port info back */
    *new_portinfo = portinfo;
  }
  else {
    *new_portinfo = port;

    /* lets see if we have cert infos */
    if (rest && rest[0]) {
      cert = apr_strtok(rest, " ", &last);
      key = apr_strtok(NULL, " ", &last);
      ca = apr_strtok(NULL, " ", &last);
    }
    if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) 
	!= APR_SUCCESS) {
      return status;
    }
    SSL_CTX_set_options(config->ssl_ctx, SSL_OP_ALL);
    SSL_CTX_set_options(config->ssl_ctx, SSL_OP_SINGLE_DH_USE);
#if (OPENSSL_VERSION_NUMBER >= 0x0090806f)
    SSL_CTX_set_options(config->ssl_ctx, SSL_OP_NO_TICKET);
#endif
  }
  return APR_SUCCESS;
}

/**
 * parse line and extract the SSL relevant stuff
 *
 * @param worker IN
 * @param line IN original line
 * @param new_line OUT manipulated
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t ssl_server_port_args(worker_t *worker, char *portinfo, 
                                         char **new_portinfo, char *rest) {
  apr_status_t status;
  char *port;
  char *copy = apr_pstrdup(worker->pbody, portinfo);
  char *sslstr = apr_strtok(copy, ":", &port);


  worker->socket->is_ssl = worker_set_server_method(worker, sslstr);

  if (!worker->socket->is_ssl) {
    /* if not ssl we do have nothing to do give back portinfo untouched */
    *new_portinfo = portinfo;
  }
  else { 
    ssl_gconf_t *gconf = ssl_get_global_config(worker->global);
    *new_portinfo = port;
    if ((status = worker_ssl_ctx(worker, gconf->certfile, gconf->keyfile, NULL, 0)) 
        != APR_SUCCESS) {
      return status;
    }
  }
  return APR_SUCCESS;
}

/**
 * do ssl connect
 *
 * @param worker IN
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t ssl_hook_connect(worker_t *worker) {
  apr_status_t status;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (worker->socket->is_ssl) {
    transport_t *transport;
    ssl_transport_t *ssl_transport;
    BIO *bio;
    apr_os_sock_t fd;

    if ((status = ssl_new_instance(worker)) != APR_SUCCESS) {
      return status;
    }

    ssl_rand_seed();
    apr_os_sock_get(&fd, worker->socket->socket);
    bio = BIO_new_socket(fd, BIO_NOCLOSE);
    SSL_set_bio(sconfig->ssl, bio, bio);
    if (sconfig->sess) {
      SSL_set_session(sconfig->ssl, sconfig->sess);
      SSL_SESSION_free(sconfig->sess);
      sconfig->sess = NULL;
    }
    SSL_set_connect_state(sconfig->ssl);
    if ((status = worker_ssl_handshake(worker)) != APR_SUCCESS) {
      return status;
    }
    ssl_transport = ssl_get_transport(worker, sconfig);
    transport = transport_new(ssl_transport, worker->pbody, 
			      ssl_transport_os_desc_get, 
			      ssl_transport_set_timeout, 
			      ssl_transport_get_timeout, 
			      ssl_transport_read, 
			      ssl_transport_write);
    transport_register(worker->socket, transport);
  }

  return APR_SUCCESS;
}

/**
 * do ssl accept handshake
 *
 * @param worker IN
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t ssl_hook_accept(worker_t *worker, char *data) {
  apr_status_t status;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  if (worker->socket->is_ssl) {
    char *last;
    transport_t *transport;
    ssl_transport_t *ssl_transport;
    const char *cert = NULL;
    const char *key = NULL;
    const char *ca = NULL;
    ssl_gconf_t *gconf = ssl_get_global_config(worker->global);

    if (data && data[0]) {
      cert = apr_strtok(data, " ", &last);
      if (cert) {
	key = apr_strtok(NULL, " ", &last);
      }
      if (key) {
	ca = apr_strtok(NULL, " ", &last);
      }
    }
    if (!cert) {
      cert = gconf->certfile;
    }
    if (!key) {
      key = gconf->keyfile;
    }
    if (!ca) {
      ca = gconf->cafile;
    }
    if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) != APR_SUCCESS) {
      return status;
    }

    if ((status = worker_ssl_accept(worker)) != APR_SUCCESS) {
      return status;
    }
    ssl_transport = ssl_get_transport(worker, sconfig);
    transport = transport_new(ssl_transport, worker->pbody, 
			      ssl_transport_os_desc_get, 
			      ssl_transport_set_timeout, 
			      ssl_transport_get_timeout, 
			      ssl_transport_read, 
			      ssl_transport_write);
    transport_register(worker->socket, transport);
  }

  return APR_SUCCESS;
}

/**
 * do ssl accept handshake
 *
 * @param worker IN
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t ssl_hook_close(worker_t *worker, char *info, 
                                   char **new_info) {
  int i;
  ssl_sconf_t *sconfig = ssl_get_socket_config(worker);

  *new_info = info;
  if (!info || !info[0]) {
    if (sconfig->ssl) {
      for (i = 0; i < 4; i++) {
	if (SSL_shutdown(sconfig->ssl) != 0) {
	  break;
	}
      }
      SSL_free(sconfig->ssl);
      sconfig->ssl = NULL;
    }
  }
  else if (strcmp(info, "SSL") == 0) {
    /* do not shutdown SSL because it will also shutdown TCP 
     * do just remove ssl methods by setting is_ssl to 0
     */
    worker->socket->is_ssl = 0;
    *new_info = NULL;
    /* work is done break hook chain here! */
    return APR_EINTR;
  }
  return APR_SUCCESS;
}

/**
 * expect/grep/match SSL handshake
 *
 * @param worker IN
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t ssl_hook_read_pre_headers(worker_t *worker) {
  ssl_wconf_t *config = ssl_get_worker_config(worker);
  if (config->msgs) {
    int i;
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(config->msgs)->elts;
    for (i = 0; i < apr_table_elts(config->msgs)->nelts; i++) {
      worker_match(worker, worker->match.dot, e[i].val, strlen(e[i].val));
      worker_match(worker, worker->match.headers, e[i].val, strlen(e[i].val));
      worker_match(worker, worker->grep.dot, e[i].val, strlen(e[i].val));
      worker_match(worker, worker->grep.headers, e[i].val, strlen(e[i].val));
      worker_expect(worker, worker->expect.dot, e[i].val, strlen(e[i].val));
      worker_expect(worker, worker->expect.headers, e[i].val, strlen(e[i].val));
    }
    apr_table_clear(config->msgs);
    apr_pool_destroy(config->msg_pool);
    apr_pool_create(&config->msg_pool, NULL);
    config->msgs = apr_table_make(config->msg_pool, 5);
  }
  return APR_SUCCESS;
}

/************************************************************************
 * Module 
 ***********************************************************************/
apr_status_t ssl_module_init(global_t *global) {
  apr_status_t status;

  /* setup ssl library */
#ifndef OPENSSL_NO_ENGINE
  ENGINE_load_builtin_engines();
#endif
#ifdef RSAREF
  R_malloc_init();
#else
  CRYPTO_malloc_init();
#endif
  SSL_load_error_strings();
  SSL_library_init();
  ssl_util_thread_setup(global->pool);

  ssl_get_global_config(global);

  if ((status = module_command_new(global, "SSL", "SET_DEFAULT_CERT", "[<cert>] [<key>] [<ca>]",
	                           "set default cert files <cert> <key> <ca> ",
	                           block_SSL_SET_DEFAULT_CERT)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "SSL", "_CONNECT",
	                           "SSL|SSL2|SSL3|DTLS1|TLS1"
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL)
                                   "|TLS1.1|TLS1.2"
#endif
                                   " [<cert-file> <key-file>]",
	                           "Needs a connected socket to establish a ssl "
				   "connection on it.",
	                           block_SSL_CONNECT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_ACCEPT",
	                           "SSL|SSL2|SSL3|DTLS|TLS1"
#if (OPENSSL_VERSION_NUMBER >= 0x1000100fL)
                                   "|TLS1.1|TLS1.2"
#endif
                                   " [<cert-file> <key-file>]",
	                           "Needs a connected socket to accept a ssl "
				   "connection on it.",
	                           block_SSL_ACCEPT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_CLOSE", "",
	                           "Close the ssl connect, but not the "
				   "underlying socket.",
	                           block_SSL_CLOSE)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_GET_SESSION", "<var>",
	                           "Stores the SSL session in <var>.",
	                           block_SSL_GET_SESSION)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_SET_SESSION", "<session>",
	                           "Set a base64 encoded <session> in "
				   "the current SSL.",
	                           block_SSL_SET_SESSION)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_GET_SESSION_ID", "<var>",
	                           "Get a SSL session id and store it in <var>",
	                           block_SSL_GET_SESSION_ID)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_RENEG_CERT", "[verify]",
	                           "Performs an SSL renegotiation and optional a verification. "
				   "Stores the cert for later use with commands like"
				   "_SSL_GET_CERT_VALUE or _SSL:SET_CERT",
	                           block_SSL_RENEG_CERT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_LOAD_CERT", "<pem-cert>",
				   "Read the given pem formated <pem-cert>. Stores it for later use "
				   "with commands like _SSL:GET_CERT_VALUE or _SSL:SET_CERT",
	                           block_SSL_LOAD_CERT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_SET_CERT", "[<cert> <key> [<ca>]]",
	                           "set cert either from file <cert> <key> <ca> "
				   "or got with _SSL:RENEG_CERT or _SSL:LOAD_CERT/_SSL:LOAD_KEY",
	                           block_SSL_SET_CERT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_SET_CA", "<ca>",
	                           "set <ca> cert",
	                           block_SSL_SET_CA)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_LOAD_KEY", "<pem-key>",
				   "Read the given pem formated <pem-key>. Stores it for later use "
				   "with commands like _SSL:SET_KEY",
	                           block_SSL_LOAD_KEY)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "SSL", "_GET_CERT_VALUE", "<cert entry> <variable>",
	                           "Get <cert entry> and store it into <variable>\n"
  				   "Get cert with _SSL:RENEG_CERT or _SSL:LOAD_CERT\n"
				   "<cert entry> are\n" 
				   "  M_VERSION\n" 
				   "  M_SERIAL\n" 
				   "  V_START\n" 
				   "  V_END\n" 
				   "  V_REMAIN\n" 
				   "  S_DN\n" 
				   "  S_DN_<var>\n" 
				   "  I_DN\n" 
				   "  I_DN_<var>\n" 
				   "  A_SIG\n" 
				   "  A_KEY\n" 
				   "  CERT",
	                           block_SSL_GET_CERT_VALUE)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_SET_ENGINE", "<engine>",
				   "Set an openssl crypto <engine> to run tests with crypto devices",
	                           block_SSL_SET_ENGINE)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_SET_LEGACY", "on | off",
				   "Turn on|off SSL legacy behavour for renegotiation for openssl libraries 0.9.8l and above",
	                           block_SSL_SET_LEGACY)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_SECURE_RENEG_SUPPORTED", "",
				   "Test if remote peer do support secure renegotiation",
	                           block_SSL_SECURE_RENEG_SUPPORTED)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_TRACE", "",
				   "Start SSL debug session",
	                           block_SSL_TRACE)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "SSL", "_SET_CIPHER_SUITE", "<ciphers>",
				   "Set an opnessl cipher suite to be used",
	                           block_SSL_CIPHER_SUITE)) != APR_SUCCESS) {
    return status;
  }

  htt_hook_worker_clone(ssl_worker_clone, NULL, NULL, 0);
  htt_hook_client_port_args(ssl_client_port_args, NULL, NULL, 0);
  htt_hook_server_port_args(ssl_server_port_args, NULL, NULL, 0);
  htt_hook_connect(ssl_hook_connect, NULL, NULL, 0);
  htt_hook_accept(ssl_hook_accept, NULL, NULL, 0);
  htt_hook_close(ssl_hook_close, NULL, NULL, 0);
  htt_hook_read_pre_headers(ssl_hook_read_pre_headers, NULL, NULL, 0);
  return APR_SUCCESS;
}


