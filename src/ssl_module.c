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

/************************************************************************
 * Definitions 
 ***********************************************************************/
void * ssl_module;

typedef struct ssl_config_s {
  X509 *cert;
  EVP_PKEY *pkey;
} ssl_config_t;

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

      if ((worker->socket->ssl = SSL_new(worker->ssl_ctx)) == NULL) {
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

  ssl_config_t *config = module_get_config(worker->config, ssl_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, ssl_module, config);
  }

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

  ssl_config_t *config = module_get_config(worker->config, ssl_module);

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

  ssl_config_t *config = module_get_config(worker->config, ssl_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, ssl_module, config);
  }

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

  ssl_config_t *config = module_get_config(worker->config, ssl_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, ssl_module, config);
  }

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
  ssl_config_t *config = module_get_config(worker->config, ssl_module);

  if (!worker->ssl_ctx) {
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

  if (SSL_CTX_use_certificate(worker->ssl_ctx, config->cert) <=0) {
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
    SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_ALL);
    SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_SINGLE_DH_USE);
#if (OPENSSL_VERSION_NUMBER >= 0x0090806f)
    SSL_CTX_set_options(worker->ssl_ctx, SSL_OP_NO_TICKET);
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


  worker->is_ssl = worker_set_server_method(worker, sslstr);

  if (!worker->is_ssl) {
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

/************************************************************************
 * Module 
 ***********************************************************************/
apr_status_t ssl_module_init(global_t *global) {
  apr_status_t status;
  ssl_module = apr_pcalloc(global->pool, sizeof(*ssl_module));
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

  htt_hook_client_port_args(ssl_client_port_args, NULL, NULL, 0);
  htt_hook_server_port_args(ssl_server_port_args, NULL, NULL, 0);
  return APR_SUCCESS;
}


