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
 * SSL_CONNECT block
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
 * SSL_ACCEPT block
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
 * SSL_CLOSE block
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_SSL_CLOSE(worker_t * worker, worker_t *parent) {
  return APR_SUCCESS;
}

/************************************************************************
 * Implementation
 ***********************************************************************/
apr_status_t ssl_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "SSL", "_CONNECT", "TYPE CERT KEY CA", "",
	                           "SSL|SSL2|SSL3|TLS1 [<cert-file> <key-file>]",
	                           "Needs a connected socket to establish a ssl "
				   "connection on it.",
	                           block_SSL_CONNECT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_ACCEPT", "TYPE, CERT KEY CA", "",
	                           "SSL|SSL2|SSL3|TLS1 [<cert-file> <key-file>]",
	                           "Needs a connected socket to accept a ssl "
				   "connection on it.",
	                           block_SSL_ACCEPT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "SSL", "_CLOSE", "", "", "",
	                           "Close the ssl connect, but not the "
				   "underlying socket.",
	                           block_SSL_ACCEPT)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
}

