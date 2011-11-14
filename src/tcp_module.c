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

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * Get os socket descriptor
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

/************************************************************************
 * Commands
 ***********************************************************************/
/**
 * do ssl connect
 * @param worker IN
 * @return APR_SUCCESS or apr error
 */
static apr_status_t tcp_hook_connect(worker_t *worker) {
  transport_t *transport;

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
 * @param worker IN
 * @return APR_SUCCESS or apr error
 */
static apr_status_t tcp_hook_accept(worker_t *worker, char *data) {
  transport_t *transport;

  transport = transport_new(worker->socket->socket, worker->pbody, 
			    tcp_transport_os_desc_get, 
			    tcp_transport_set_timeout,
			    tcp_transport_read, 
			    tcp_transport_write);
  transport_register(worker->socket, transport);

  worker_log(worker, LOG_DEBUG, "tcp accept socket: %p transport: %p", worker->socket, transport);

  return APR_SUCCESS;
}

/**
 * Setup a connection to host
 * @param self IN command object
 * @param worker IN thread data object
 * @param data IN aditional data
 * @return an apr status
 */
static apr_status_t block_TCP_CONNECT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  apr_sockaddr_t *remote_addr;
  char *portname;
  char *hostname;
  char *tag;
  int port;
  int family = APR_INET;

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  hostname = store_get_copy(worker->params, ptmp, "1");
  portname = store_get_copy(worker->params, ptmp, "2");

  /* use hostname and portname for unique id of sockets, portname may also have 
   * additional tags and infos which are possible resolved in the following
   * hook
   */
  worker_log(worker, LOG_DEBUG, "get socket \"%s:%s\"", hostname, portname);
  worker_get_socket(worker, hostname, portname);

  if (!hostname) {
    worker_log(worker, LOG_ERR, "no host name specified");
    return APR_EGENERAL;
  }
  
  if (!portname) {
    worker_log(worker, LOG_ERR, "no portname name specified");
    return APR_EGENERAL;
  }

  /* remove tag from port */
  portname = apr_strtok(portname, ":", &tag);
  if (!portname) {
    worker_log(worker, LOG_ERR, "no port specified");
    return APR_EGENERAL;
  }
  port = apr_atoi64(portname);

  if (worker->socket->socket_state == SOCKET_CLOSED) {
#if APR_HAVE_IPV6
    /* hostname/address must be surrounded in square brackets */
    if((hostname[0] == '[') && (hostname[strlen(hostname)-1] == ']')) {
      family = APR_INET6;
      hostname++;
      hostname[strlen(hostname)-1] = '\0';
    }
#endif
    if ((status = apr_socket_create(&worker->socket->socket, family,
				    SOCK_STREAM, APR_PROTO_TCP,
                                    worker->pbody)) != APR_SUCCESS) {
      worker->socket->socket = NULL;
      return status;
    }
    if ((status =
         apr_socket_opt_set(worker->socket->socket, APR_TCP_NODELAY,
                            1)) != APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) != APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_sockaddr_info_get(&remote_addr, hostname, AF_UNSPEC, port,
                               APR_IPV4_ADDR_OK, worker->pbody))
        != APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_connect(worker->socket->socket, remote_addr)) 
				!= APR_SUCCESS) {
      return status;
    }

    if ((status =
         apr_socket_opt_set(worker->socket->socket, APR_SO_KEEPALIVE,
                            1)) != APR_SUCCESS) {
      return status;
    }

    worker->socket->socket_state = SOCKET_CONNECTED;
    if ((status = tcp_hook_connect(worker)) != APR_SUCCESS) {
      return status;
    }
  }

  /* reset the matcher tables */
  apr_table_clear(worker->match.dot);
  apr_table_clear(worker->match.headers);
  apr_table_clear(worker->match.body);
  apr_table_clear(worker->match.error);
  apr_table_clear(worker->expect.dot);
  apr_table_clear(worker->expect.headers);
  apr_table_clear(worker->expect.body);
  apr_table_clear(worker->expect.error);

  return APR_SUCCESS;
}

/************************************************************************
 * Module 
 ***********************************************************************/
apr_status_t tcp_module_init(global_t *global) {
  apr_status_t status;

  if ((status = module_command_new(global, "TCP", "_CONNECT",
				   "<host> <port>[:<tag>]",
                                   "Open connection to defined <host> <port>.\n"
                                   "If connection exist no connect will be performed\n"
                                   "<host>: host name or IPv4/IPv6 address (IPv6 address must be surrounded\n"
                                   "        in square brackets)\n"
                                   "<tag>: Additional tag info do support multiple connection to one target.",
	                           block_TCP_CONNECT)) != APR_SUCCESS) {
    return status;
  }

  /* TCP ACCEPT */
  /* TCP CLOSE */
  htt_hook_connect(tcp_hook_connect, NULL, NULL, 0);
  htt_hook_accept(tcp_hook_accept, NULL, NULL, 0);
  return APR_SUCCESS;
}


