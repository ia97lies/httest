/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
#include "module.h"

/* on windows the inclusion of windows.h/wincrypt.h causes
 * X509_NAME and a few more to be defined; found no other
 * way than to undef manually before inclusion of engine.h;
 * somehow the same undef in ossl_typ.h is not enough...
 */
#ifdef OPENSSL_SYS_WIN32
#undef X509_NAME
#endif

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * ssl_module = "ssl_module";

typedef struct ssl_config_s {
  X509 *cert;
  EVP_PKEY *pkey;
  SSL_CTX *ssl_ctx;
  SSL_METHOD *meth;
  BIO *bio_out;
  BIO *bio_err;
  char *ssl_info;
} ssl_config_t;

/* TODO use this for transport hook */
typedef struct ssl_transport_s {
  int is_ssl;
  SSL *ssl;
  SSL_SESSION *sess;
  /* need this for timeout settings */
  transport_t *tcp_transport;
} ssl_transport_t;

/************************************************************************
 * Local 
 ***********************************************************************/

/**
 * Get ssl config from worker
 *
 * @param worker IN worker
 * @return ssl config
 */
static ssl_config_t *ssl_get_worker_config(worker_t *worker) {
  ssl_config_t *config = module_get_config(worker->config, ssl_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, apr_pstrdup(worker->pbody, ssl_module), config);
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
apr_status_t worker_ssl_handshake(worker_t * worker) {
  apr_status_t status;
  char *error;
  
  if ((status = ssl_handshake(worker->socket->ssl, &error, worker->pbody)) 
      != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "%s", error);
  }
  
  if (worker->flags & FLAGS_SSL_LEGACY) {
#if (OPENSSL_VERSION_NUMBER >= 0x009080cf)
#ifdef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    worker->socket->ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION; 
#else 	 
    SSL_set_options(worker->socket->ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif
#endif
  }

  return status;
}

/**
 * Get server ctx with loaded cert and key file
 *
 * @param self IN thread object data
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
apr_status_t worker_ssl_ctx(worker_t * self, const char *certfile, 
                            const char *keyfile, const char *ca, int check) {
  ssl_config_t *config = ssl_get_worker_config(self);
  worker_log(self, LOG_DEBUG, "cert: %s; key: %s; ca: %s\n", 
             certfile?certfile:"(null)",
             keyfile?keyfile:"(null)",
             ca?ca:"(null)");
  if (!config->ssl_ctx) {
    if (!(config->ssl_ctx = SSL_CTX_new(self->meth))) {
      worker_log(self, LOG_ERR, "Could not initialize SSL Context.");
      return APR_EINVAL;
    }
  }
  if (config->ssl_ctx) {
    if (certfile && SSL_CTX_use_certificate_file(config->ssl_ctx, certfile, 
	                                         SSL_FILETYPE_PEM) <= 0 && 
	check) { 
      worker_log(self, LOG_ERR, "Could not load RSA server certifacte \"%s\"",
	         certfile);
      return APR_EINVAL;
    }
    if (keyfile && SSL_CTX_use_PrivateKey_file(config->ssl_ctx, keyfile, 
	                                       SSL_FILETYPE_PEM) <= 0 && 
	check) {
      worker_log(self, LOG_ERR, "Could not load RSA server private key \"%s\"",
	         keyfile);
      return APR_EINVAL;
    }
    if (ca && !SSL_CTX_load_verify_locations(config->ssl_ctx, ca,
					     NULL) && check) {
      worker_log(self, LOG_ERR, "Could not load CA file \"%s\"", ca);
      return APR_EINVAL;
    }

    if (certfile && keyfile&& check && 
	!SSL_CTX_check_private_key(config->ssl_ctx)) {
      worker_log(self, LOG_ERR, "Private key does not match the certificate public key");
      return APR_EINVAL;
    }
#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(config->ssl_ctx,1);
#endif
 }
  return APR_SUCCESS;
}

/**
 * Get client method 
 *
 * @param self IN thread object data
 * @param sslstr IN SSL|SSL2|SSL3|TLS1
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
int worker_set_client_method(worker_t * worker, const char *sslstr) {
  int is_ssl = 0;
  if (strcasecmp(sslstr, "SSL") == 0) {
    is_ssl = 1;
    worker->meth = SSLv23_client_method();
  }
  else if (strcasecmp(sslstr, "SSL2") == 0) {
    is_ssl = 1;
    worker->meth = SSLv2_client_method();
  }
  else if (strcasecmp(sslstr, "SSL3") == 0) {
    is_ssl = 1;
    worker->meth = SSLv3_client_method();
  }
  else if (strcasecmp(sslstr, "TLS1") == 0) {
    is_ssl = 1;
    worker->meth = TLSv1_client_method();
  }
  return is_ssl;
}

/**
 * Get server method 
 *
 * @param self IN thread object data
 * @param sslstr IN SSL|SSL2|SSL3|TLS1
 *
 * @return APR_SUCCESS or APR_ECONNABORTED
 */
int worker_set_server_method(worker_t * worker, const char *sslstr) {
  int is_ssl = 0;
  if (strcasecmp(sslstr, "SSL") == 0) {
    is_ssl = 1;
    worker->meth = SSLv23_server_method();
  }
  else if (strcasecmp(sslstr, "SSL2") == 0) {
    is_ssl = 1;
    worker->meth = SSLv2_server_method();
  }
  else if (strcasecmp(sslstr, "SSL3") == 0) {
    is_ssl = 1;
    worker->meth = SSLv3_server_method();
  }
  else if (strcasecmp(sslstr, "TLS1") == 0) {
    is_ssl = 1;
    worker->meth = TLSv1_server_method();
  }
  return is_ssl;
}

/**
 * Do a ssl accept
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS
 */
apr_status_t worker_ssl_accept(worker_t * worker) {
  apr_status_t status;
  char *error;
  ssl_config_t *config = ssl_get_worker_config(worker);

  if (worker->socket->is_ssl) {
    if (!worker->socket->ssl) {
      BIO *bio;
      apr_os_sock_t fd;

      if ((worker->socket->ssl = SSL_new(config->ssl_ctx)) == NULL) {
	worker_log(worker, LOG_ERR, "SSL_new failed.");
	status = APR_ECONNREFUSED;
      }
      SSL_set_ssl_method(worker->socket->ssl, worker->meth);
      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(worker->socket->ssl, bio, bio);
    }
    else {
      return APR_SUCCESS;
    }
  }
  else {
    return APR_SUCCESS;
  }

  if ((status = ssl_accept(worker->socket->ssl, &error, worker->pbody)) 
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
apr_status_t ssl_transport_os_desc_get(void *data, int *desc) {
  return APR_ENOENT;
}

/**
 * Get os socket descriptor
 *
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return APR_ENOENT
 */
apr_status_t ssl_transport_set_timeout(void *data, apr_interval_time_t t) {
  return APR_ENOENT;
}

/**
 * read from socket
 *
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
apr_status_t ssl_transport_read(void *data, char *buf, apr_size_t *size) {
  SSL *ssl = data;
  apr_status_t status;

tryagain:
  apr_sleep(1);
  status = SSL_read(ssl, buf, *size);
  if (status <= 0) {
    int scode = SSL_get_error(ssl, status);

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
apr_status_t ssl_transport_write(void *data, char *buf, apr_size_t size) {
  SSL *ssl = data;
  apr_size_t e_ssl;

tryagain:
  apr_sleep(1);
  e_ssl = SSL_write(ssl, buf, size);
  if (e_ssl != size) {
    int scode = SSL_get_error(ssl, e_ssl);
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
 * Connect block
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_CONNECT(worker_t * worker, worker_t *parent) {
  const char *sslstr;
  int is_ssl;
  BIO *bio;
  apr_os_sock_t fd;
  ssl_config_t *config = ssl_get_worker_config(worker);

  sslstr = apr_table_get(worker->params, "1");
  if (!sslstr) {
    worker_log_error(worker, "Missing type, must be one of SSL|SSL2|SSL3|TLS1");
    return APR_EGENERAL;
  }

  is_ssl = worker_set_client_method(worker, sslstr);
  if (!is_ssl) {
    worker_log(worker, LOG_ERR, "%s is not supported", sslstr);
    return APR_EGENERAL;
  }
  worker->socket->is_ssl = is_ssl;

  if (worker->socket->socket_state == SOCKET_CONNECTED) {
    if (worker->socket->is_ssl) {
      transport_t *transport;
      const char *cert;
      const char *key;
      const char *ca;
      apr_status_t status;

      cert = apr_table_get(worker->params, "2");
      key = apr_table_get(worker->params, "3");
      ca = apr_table_get(worker->params, "4");
      if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) != APR_SUCCESS) {
	return status;
      }

      if ((worker->socket->ssl = SSL_new(config->ssl_ctx)) == NULL) {
				worker_log(worker, LOG_ERR, "SSL_new failed.");
				return APR_ECONNREFUSED;
      }
      SSL_set_ssl_method(worker->socket->ssl, worker->meth);
      ssl_rand_seed();
      apr_os_sock_get(&fd, worker->socket->socket);
      bio = BIO_new_socket(fd, BIO_NOCLOSE);
      SSL_set_bio(worker->socket->ssl, bio, bio);
      if (worker->socket->sess) {
				SSL_set_session(worker->socket->ssl, worker->socket->sess);
				SSL_SESSION_free(worker->socket->sess);
				worker->socket->sess = NULL;
      }
      SSL_set_connect_state(worker->socket->ssl);

      if ((status = worker_ssl_handshake(worker)) != APR_SUCCESS) {
				return status;
      }

      transport = transport_new(worker->socket->ssl, worker->pbody, 
				ssl_transport_os_desc_get, 
				ssl_transport_set_timeout, 
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
static apr_status_t block_SSL_ACCEPT(worker_t * worker, worker_t *parent) {
  const char *sslstr;
  int is_ssl;
  ssl_config_t *config = ssl_get_worker_config(worker);

  sslstr = apr_table_get(worker->params, "1");
  if (!sslstr) {
    worker_log_error(worker, "Missing type, must be one of SSL|SSL2|SSL3|TLS1");
    return APR_EGENERAL;
  }

  is_ssl = worker_set_server_method(worker, sslstr);
  if (!is_ssl) {
    worker_log(worker, LOG_ERR, "%s is not supported", sslstr);
    return APR_EGENERAL;
  }
  worker->socket->is_ssl = is_ssl;

  if (worker->socket->socket_state == SOCKET_CONNECTED) {
    if (worker->socket->is_ssl) {
      transport_t *transport;
      const char *cert;
      const char *key;
      const char *ca;
      apr_status_t status;

      cert = apr_table_get(worker->params, "2");
      key = apr_table_get(worker->params, "3");
      ca = apr_table_get(worker->params, "4");
      if (!cert) {
	cert = RSA_SERVER_CERT;
      }
      if (!key) {
	key = RSA_SERVER_KEY;
      }
      if ((status = worker_ssl_ctx(worker, cert, key, ca, 1)) != APR_SUCCESS) {
	return status;
      }

      if ((status = worker_ssl_accept(worker)) != APR_SUCCESS) {
	return status;
      }
      transport = transport_new(worker->socket->ssl, worker->pbody, 
				ssl_transport_os_desc_get, 
				ssl_transport_set_timeout, 
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
static apr_status_t block_SSL_CLOSE(worker_t * worker, worker_t *parent) {
  return command_CLOSE(NULL, worker, "SSL");
}


/**
 * Get session block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_GET_SESSION(worker_t * worker, worker_t *parent) {
  const char *copy = apr_table_get(worker->params, "1");

  if (!copy) {
    worker_log_error(worker, "Missing varibale name to store session in");
    return APR_EGENERAL;
  }

  if (!worker->socket || !worker->socket->socket || !worker->socket->is_ssl) {
    worker_log_error(worker, "No established ssl socket");
    return APR_ENOSOCKET;
  }

  if (worker->socket->is_ssl) {
    if (worker->socket->ssl) {
      apr_size_t b64_len;
      char *b64_str;
      apr_size_t enc_len;
      unsigned char *enc;
      unsigned char *tmp;
      SSL_SESSION *sess = SSL_get_session(worker->socket->ssl);
      /* serialize to a variable an store it */
      enc_len = i2d_SSL_SESSION(sess, NULL);
      enc = apr_pcalloc(worker->pbody, enc_len);
      tmp = enc;
      enc_len = i2d_SSL_SESSION(sess, &tmp);
      b64_len = apr_base64_encode_len(enc_len);
      b64_str = apr_pcalloc(worker->pbody, b64_len);
      apr_base64_encode_binary(b64_str, enc, enc_len);
      varset(worker, copy, b64_str);
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
static apr_status_t block_SSL_SET_SESSION(worker_t * worker, worker_t *parent) {
  const char *copy = apr_table_get(worker->params, "1");

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
      enc = apr_pcalloc(worker->pbody, enc_len);
      apr_base64_decode_binary(enc, b64_str);
      tmp = enc;
      worker->socket->sess = d2i_SSL_SESSION(NULL, &tmp, enc_len);
    }
    else {
      worker_log_error(worker, "Variable \"%s\" do not exist", copy);
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
static apr_status_t block_SSL_GET_SESSION_ID(worker_t * worker, worker_t *parent) {
  const char *copy = apr_table_get(worker->params, "1");
  SSL_SESSION *sess;
  char *val;

  if (!copy) {
    worker_log_error(worker, "Missing varibale name to store session in");
    return APR_EGENERAL;
  }

  if (!worker->socket || !worker->socket->ssl) {
    worker_log_error(worker, "Need an ssl connection");
    return APR_ENOSOCKET;
  }

  sess = SSL_get_session(worker->socket->ssl);

  if (sess) {
    val = apr_pcalloc(worker->pbody, apr_base64_encode_len(sess->session_id_length));
    apr_base64_encode_binary(val, sess->session_id, sess->session_id_length);

    varset(worker, copy, val);
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
static apr_status_t block_SSL_RENEG_CERT(worker_t * worker, worker_t *parent) {
  int rc;
  const char *copy = apr_table_get(worker->params, "1");

  ssl_config_t *config = ssl_get_worker_config(worker);

  if (config->cert) {
    X509_free(config->cert);
  }
  
  config->cert = NULL;

  if (!worker->socket->is_ssl || !worker->socket->ssl) {
    worker_log(worker, LOG_ERR, 
	       "No ssl connection established can not verify peer");
    return APR_ENOSOCKET;
  }

  if (worker->flags & FLAGS_SERVER) {
    if (strcasecmp(copy, "verify") == 0) {
      /* if we are server request the peer cert */
      if (worker->log_mode >= LOG_DEBUG) {
	SSL_set_verify(worker->socket->ssl,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		       debug_verify_callback);
      }
      else {
	SSL_set_verify(worker->socket->ssl,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
		       NULL);
      }
    }

    if (worker->flags & FLAGS_SSL_LEGACY) {
#if (OPENSSL_VERSION_NUMBER >= 0x009080cf)
#ifdef SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
      worker->socket->ssl->s3->flags |= SSL3_FLAGS_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
#else
      SSL_set_options(worker->socket->ssl, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
#endif
#endif
    }

    if((rc = SSL_renegotiate(worker->socket->ssl) <= 0)) {
      worker_log(worker, LOG_ERR, "SSL renegotiation a error: %d", rc);
      return APR_EACCES;
    }
    worker_ssl_handshake(worker);
    worker->socket->ssl->state=SSL_ST_ACCEPT;
    worker_ssl_handshake(worker);

    if (strcasecmp(copy, "verify") == 0) {
      config->cert = SSL_get_peer_certificate(worker->socket->ssl);
      if (!config->cert) {
	worker_log(worker, LOG_ERR, "No peer certificate");
	return APR_EACCES;
      }
    }
  }
  else {
    if (strcasecmp(copy, "verify") == 0) {
      config->cert = SSL_get_peer_certificate(worker->socket->ssl);
      if (!config->cert) {
	worker_log(worker, LOG_ERR, "No peer certificate");
	return APR_EACCES;
      }

      if((rc = SSL_get_verify_result(worker->socket->ssl)) != X509_V_OK) {
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
 
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_GET_CERT_VALUE(worker_t * worker, worker_t *parent) {
  char *val = NULL;
  const char *cmd = apr_table_get(worker->params, "1");
  const char *var = apr_table_get(worker->params, "2");

  ssl_config_t *config = ssl_get_worker_config(worker);

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
  
  val = ssl_var_lookup_ssl_cert(worker->pbody, config->cert, cmd);

  if (!val) {
    worker_log_error(worker, "SSL value for \"%s\" not found", cmd);
    return APR_ENOENT;
  }

  varset(worker, var, val);

  return APR_SUCCESS;
}

/**
 * SSL_SECURE_RENEG_SUPPORTED command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SSL_SET_ENGINE(worker_t * worker, worker_t *parent) {
#ifndef OPENSSL_NO_ENGINE
  const char *copy = apr_table_get(worker->params, "1");
  BIO *bio_err = BIO_new_fp(stderr,BIO_NOCLOSE);

  if (!setup_engine(bio_err, copy, worker->log_mode == LOG_DEBUG ? 1 : 0)) {
    worker_log(worker, LOG_ERR, "Could not initialize engine \"%s\".", copy);
    return APR_EINVAL;
  }
#endif
  return APR_ENOTIMPL;
}

/**
 * SSL_LEGACY command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SSL_SET_LEGACY(worker_t * worker, worker_t *parent) {
  const char *copy = apr_table_get(worker->params, "1");

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
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_LOAD_CERT(worker_t * worker, worker_t *parent) {
  const char *val = apr_table_get(worker->params, "1");
  char *copy = apr_pstrdup(worker->pbody, val);
  BIO *mem;

  ssl_config_t *config = ssl_get_worker_config(worker);

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
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_LOAD_KEY(worker_t * worker, worker_t *parent) {
  const char *val = apr_table_get(worker->params, "1");
  char *copy = apr_pstrdup(worker->pbody, val);
  BIO *mem;

  ssl_config_t *config = ssl_get_worker_config(worker);

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
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN ssl variable and a variable name 
 *
 * @return APR_SUCCESS
 */
static apr_status_t block_SSL_SET_CERT(worker_t * worker, worker_t *parent) {
  ssl_config_t *config = ssl_get_worker_config(worker);

  if (!config->ssl_ctx) {
    worker_log_error(worker, "You are not in a ssl context");
    return APR_EINVAL;
  }

  /* check if we have parameters */
  if (apr_table_elts(worker->params)->nelts) {
    const char *cert;
    const char *key;
    const char *ca;
    cert = apr_table_get(worker->params, "1");
    key = apr_table_get(worker->params, "2");
    ca = apr_table_get(worker->params, "3");
    worker_ssl_ctx(worker, cert, key, ca, 1);
    return  APR_SUCCESS;
  }

  /* else set cert */
  if (!config || !config->cert || !config->pkey) {
    worker_log_error(worker, "No cert and key to use, get a cert and key with _SSL:LOAD_KEY of _SSL:LOAD_CERT");
    return APR_EINVAL;
  }

  if (SSL_CTX_use_certificate(config->ssl_ctx, config->cert) <=0) {
    worker_log_error(worker, "Can not use this cert");
    return APR_EINVAL;
  }
  return APR_SUCCESS;
}

/**
 * SSL_SECURE_RENEG_SUPPORTED command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SSL_SECURE_RENEG_SUPPORTED(worker_t * worker, 
                                                     worker_t *parent) {
#if (define USE_SSL && OPENSSL_VERSION_NUMBER >= 0x009080ff)
  if (SSL_get_secure_renegotiation_support(worker->socket->ssl)) {
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
 * clone worker
 *
 * @param worker IN
 * @param clone IN 
 * @return APR_SUCCESS
 */
static apr_status_t ssl_clone_worker(worker_t *worker, worker_t *clone) {
  ssl_config_t *config = ssl_get_worker_config(worker);
  ssl_config_t *clone_config = ssl_get_worker_config(clone);

  /* TODO: copy all config entries, cause they will be used concurrent */
  memcpy(clone_config, config, sizeof(*clone_config)); 

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
  ssl_config_t *config = ssl_get_worker_config(worker);

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
    *new_portinfo = port;
    if ((status = worker_ssl_ctx(worker, RSA_SERVER_CERT, RSA_SERVER_KEY, NULL, 0)) 
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
  ssl_config_t *config = ssl_get_worker_config(worker);

  if (worker->socket->is_ssl) {
    transport_t *transport;
    BIO *bio;
    apr_os_sock_t fd;

    if ((worker->socket->ssl = SSL_new(config->ssl_ctx)) == NULL) {
      worker_log(worker, LOG_ERR, "SSL_new failed.");
      return APR_EGENERAL;
    }
    SSL_set_ssl_method(worker->socket->ssl, worker->meth);
    ssl_rand_seed();
    apr_os_sock_get(&fd, worker->socket->socket);
    bio = BIO_new_socket(fd, BIO_NOCLOSE);
    SSL_set_bio(worker->socket->ssl, bio, bio);
    if (worker->socket->sess) {
      SSL_set_session(worker->socket->ssl, worker->socket->sess);
      SSL_SESSION_free(worker->socket->sess);
      worker->socket->sess = NULL;
    }
    SSL_set_connect_state(worker->socket->ssl);
    if ((status = worker_ssl_handshake(worker)) != APR_SUCCESS) {
      return status;
    }
    transport = transport_new(worker->socket->ssl, worker->pbody, 
			      ssl_transport_os_desc_get, 
			      ssl_transport_set_timeout, 
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
static apr_status_t ssl_hook_accept(worker_t *worker) {
  apr_status_t status;
  ssl_config_t *config = ssl_get_worker_config(worker);

  if (worker->socket->is_ssl) {
    transport_t *transport;
    if ((status = worker_ssl_accept(worker)) != APR_SUCCESS) {
      return status;
    }
    transport = transport_new(worker->socket->ssl, worker->pbody, 
			      ssl_transport_os_desc_get, 
			      ssl_transport_set_timeout, 
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
  *new_info = info;
  if (!info || !info[0]) {
    if (worker->socket->ssl) {
      for (i = 0; i < 4; i++) {
	if (SSL_shutdown(worker->socket->ssl) != 0) {
	  break;
	}
      }
      SSL_free(worker->socket->ssl);
      worker->socket->ssl = NULL;
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

  if ((status = module_command_new(global, "SSL", "_CONNECT",
	                           "SSL|SSL2|SSL3|TLS1 [<cert-file> <key-file>]",
	                           "Needs a connected socket to establish a ssl "
				   "connection on it.",
	                           block_SSL_CONNECT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_ACCEPT",
	                           "SSL|SSL2|SSL3|TLS1 [<cert-file> <key-file>]",
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
				   "  CERT"
				   "Performs an SSL renegotiation.",
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

  htt_hook_clone_worker(ssl_clone_worker, NULL, NULL, 0);
  htt_hook_client_port_args(ssl_client_port_args, NULL, NULL, 0);
  htt_hook_server_port_args(ssl_server_port_args, NULL, NULL, 0);
  htt_hook_connect(ssl_hook_connect, NULL, NULL, 0);
  htt_hook_accept(ssl_hook_accept, NULL, NULL, 0);
  htt_hook_close(ssl_hook_close, NULL, NULL, 0);
  return APR_SUCCESS;
}


