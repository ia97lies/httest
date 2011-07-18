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
 * Implementation of the HTTP Test Tool tcp module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * tcp_module = "tcp_module";

typedef struct tcp_config_s {
  int port;
} tcp_config_t;

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * Get os socket descriptor
 *
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
apr_status_t tcp_transport_os_desc_get(void *data, int *desc) {
  apr_socket_t *socket = data;
  return apr_os_sock_get(desc, socket);
}

/**
 * Set timeout
 *
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
apr_status_t tcp_transport_set_timeout(void *data, apr_interval_time_t t) {
  apr_socket_t *socket = data;
  return apr_socket_timeout_set(socket, t);
}

/**
 * read from socket
 *
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
apr_status_t tcp_transport_read(void *data, char *buf, apr_size_t *size) {
  apr_socket_t *socket = data;
  return apr_socket_recv(socket, buf, size);
}

/**
 * write to socket
 *
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
apr_status_t tcp_transport_write(void *data, char *buf, apr_size_t size) {
  apr_socket_t *socket = data;
  apr_status_t status = APR_SUCCESS;
  apr_size_t total = size;
  apr_size_t count = 0;
  apr_size_t len;

  while (total != count) {
    len = total - count;
    if ((status = apr_socket_send(socket, &buf[count], &len)) 
	!= APR_SUCCESS) {
      return status;
    }
    count += len;
  }

  return APR_SUCCESS;
}

/**
 * Get ssl config from worker
 *
 * @param worker IN worker
 * @return ssl config
 */
static tcp_config_t *tcp_get_worker_config(worker_t *worker) {
  tcp_config_t *config = module_get_config(worker->config, tcp_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    /* we could not set it here, we have to before register, but want this only
     * alloc one time per worker
     */
    module_set_config(worker->config, apr_pstrdup(worker->pbody, tcp_module), config);
  }
  return config;
}

/************************************************************************
 * Commands
 ***********************************************************************/
/**
 * do ssl connect
 *
 * @param worker IN
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t tcp_hook_connect(worker_t *worker) {
  transport_t *transport;
  apr_status_t status;

  tcp_config_t *config = tcp_get_worker_config(worker);

  transport = transport_new(worker->socket->socket, worker->pbody, 
			    tcp_transport_os_desc_get, 
			    tcp_transport_set_timeout,
			    tcp_transport_read, 
			    tcp_transport_write);

  transport_register(worker->socket, transport);

  worker_log(worker, LOG_DEBUG, "tcp connect socket: %p transport: %p", worker->socket, transport);

  return APR_SUCCESS;
}

/**
 * do ssl accept handshake
 *
 * @param worker IN
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t tcp_hook_accept(worker_t *worker, char *data) {
  transport_t *transport;
  apr_status_t status;
  tcp_config_t *config = tcp_get_worker_config(worker);

  transport = transport_new(worker->socket->socket, worker->pbody, 
			    tcp_transport_os_desc_get, 
			    tcp_transport_set_timeout,
			    tcp_transport_read, 
			    tcp_transport_write);
  transport_register(worker->socket, transport);

  worker_log(worker, LOG_DEBUG, "tcp accept socket: %p transport: %p", worker->socket, transport);

  return APR_SUCCESS;
}

/************************************************************************
 * Module 
 ***********************************************************************/
apr_status_t tcp_module_init(global_t *global) {
  apr_status_t status;

  htt_hook_connect(tcp_hook_connect, NULL, NULL, 0);
  htt_hook_accept(tcp_hook_accept, NULL, NULL, 0);
  return APR_SUCCESS;
}


