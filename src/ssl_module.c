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

/************************************************************************
 * Globals 
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
static apr_status_t block_SSL_RENEG(worker_t * worker, worker_t *parent) {
  int rc;
  const char *copy = apr_table_get(worker->params, "1");

  if (worker->foreign_cert) {
    X509_free(worker->foreign_cert);
  }
  
  worker->foreign_cert = NULL;

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
      worker->foreign_cert = SSL_get_peer_certificate(worker->socket->ssl);
      if (!worker->foreign_cert) {
	worker_log(worker, LOG_ERR, "No peer certificate");
	return APR_EACCES;
      }
    }
  }
  else {
    if (strcasecmp(copy, "verify") == 0) {
      worker->foreign_cert = SSL_get_peer_certificate(worker->socket->ssl);
      if (!worker->foreign_cert) {
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
/************************************************************************
 * Implementation
 ***********************************************************************/
apr_status_t ssl_module_init(global_t *global) {
  apr_status_t status;
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
  if ((status = module_command_new(global, "SSL", "_RENEG", "[verify]",
	                           "Performs an SSL renegotiation.",
	                           block_SSL_RENEG)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

