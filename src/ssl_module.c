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
 * Get session block 
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_SET_SESSION(worker_t * worker, worker_t *parent) {
  const char *copy = apr_table_get(worker->params, "1");

  if (!copy) {
    worker_log_error(worker, "Missing varibale name to store session in");
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
  if ((status = module_command_new(global, "SSL", "_SET_SESSION", "<var>",
	                           "Get a SSL session from <var> and set it in "
				   "the current SSL.",
	                           block_SSL_SET_SESSION)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

