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
 * Implementation of the HTTP Test Tool tcp module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"
#include "tcp_module.h"

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
static apr_status_t tcp_transport_os_desc_get(void *data, int *desc) {
  apr_socket_t *socket = data;
  if (!socket) {
    return APR_ENOSOCKET;
  }
  return apr_os_sock_get(desc, socket);
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t tcp_transport_set_timeout(void *data, apr_interval_time_t t) {
  apr_socket_t *socket = data;
  if (!socket) {
    return APR_ENOSOCKET;
  }
  return apr_socket_timeout_set(socket, t);
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t tcp_transport_get_timeout(void *data, apr_interval_time_t *t) {
  apr_socket_t *socket = data;
  if (!socket) {
    return APR_ENOSOCKET;
  }
  return apr_socket_timeout_get(socket, t);
}

/**
 * read from socket
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t tcp_transport_read(void *data, char *buf, apr_size_t *size) {
  apr_socket_t *socket = data;
  if (!socket) {
    return APR_ENOSOCKET;
  }
  return apr_socket_recv(socket, buf, size);
}

/**
 * write to socket
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t tcp_transport_write(void *data, const char *buf, apr_size_t size) {
  apr_socket_t *socket = data;
  apr_status_t status = APR_SUCCESS;
  apr_size_t total = size;
  apr_size_t count = 0;
  apr_size_t len;

  if (!socket) {
    return APR_ENOSOCKET;
  }
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
 * Hooks
************************************************************************/
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
			    tcp_transport_get_timeout,
			    tcp_transport_read, 
			    tcp_transport_write);

  transport_register(worker->socket, transport);

  worker_log(worker, LOG_DEBUG, "tcp connect socket: %"APR_UINT64_T_HEX_FMT" "
             "transport: %"APR_UINT64_T_HEX_FMT, worker->socket, transport);

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
			    tcp_transport_get_timeout,
			    tcp_transport_read, 
			    tcp_transport_write);
  transport_register(worker->socket, transport);

  worker_log(worker, LOG_DEBUG, "tcp accept socket: %"APR_UINT64_T_HEX_FMT" "
             "transport: %"APR_UINT64_T_HEX_FMT, worker->socket, transport);

  return APR_SUCCESS;
}

/************************************************************************
 * Optional Functions 
************************************************************************/
/**
 * Listen to a tcp socket
 * @param worker IN callee
 * @param address IN address to bind to
 * @param backlog IN backlog size
 * @return apr status
 */
apr_status_t tcp_listen(worker_t *worker,  int backlog) {
  apr_status_t status;
  apr_sockaddr_t *local_addr;
  
  if (worker->listener) {
    worker_log(worker, LOG_ERR, "Server allready up");
    return APR_EGENERAL;
  }

  if ((status = apr_sockaddr_info_get(&local_addr, worker->listener_addr, APR_UNSPEC,
                                      worker->listener_port, APR_IPV6_ADDR_OK, worker->pbody))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_socket_create(&worker->listener, local_addr->family, SOCK_STREAM,
                                  APR_PROTO_TCP, worker->pbody)) != APR_SUCCESS) {
    worker->listener = NULL;
    return status;
  }

  status = apr_socket_opt_set(worker->listener, APR_SO_REUSEADDR, 1);
  if (status != APR_SUCCESS && status != APR_ENOTIMPL) {
    return status;
  }
  
  worker_log(worker, LOG_DEBUG, "--- bind");
  if ((status = apr_socket_bind(worker->listener, local_addr)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not bind");
    return status;
  }

  worker_log(worker, LOG_DEBUG, "--- listen");
  if ((status = apr_socket_listen(worker->listener, backlog)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not listen");
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Listen to a tcp socket
 * @param worker IN callee
 * @param hostname IN host to connect
 * @param portname IN port and optional tags
 * @return apr status
 */
apr_status_t tcp_connect(worker_t *worker, char *hostname, char *portname) {
  apr_status_t status = APR_SUCCESS;
  apr_sockaddr_t *remote_addr;
  char *tag;
  int port;

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

#if APR_HAVE_IPV6
  /* hostname/address must be surrounded in square brackets */
  if((hostname[0] == '[') && (hostname[strlen(hostname)-1] == ']')) {
    hostname++;
    hostname[strlen(hostname)-1] = '\0';
  }
#endif
  if ((status = apr_sockaddr_info_get(&remote_addr, hostname, AF_UNSPEC, port,
                                      APR_IPV6_ADDR_OK, worker->pbody))
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_socket_create(&worker->socket->socket, remote_addr->family,
                                  SOCK_STREAM, APR_PROTO_TCP,
                                  worker->pbody)) != APR_SUCCESS) {
    worker->socket->socket = NULL;
    return status;
  }

  if ((status = apr_socket_opt_set(worker->socket->socket, APR_TCP_NODELAY, 1)) 
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) 
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_socket_connect(worker->socket->socket, remote_addr)) 
      != APR_SUCCESS) {
    return status;
  }

  if ((status = apr_socket_opt_set(worker->socket->socket, APR_SO_KEEPALIVE, 1)) 
      != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * Accept a tcp socket
 * @param worker IN callee
 * @return apr status
 */
apr_status_t tcp_accept(worker_t *worker) {
  apr_status_t status = APR_SUCCESS;

  worker_log(worker, LOG_DEBUG, "--- accept");
  if (!worker->listener) {
    worker_log(worker, LOG_ERR, "Server down");
    return APR_EGENERAL;
  }

  if ((status =
       apr_socket_accept(&worker->socket->socket, worker->listener,
                         worker->pbody)) != APR_SUCCESS) {
    worker->socket->socket = NULL;
    return status;
  }
  if ((status = apr_socket_opt_set(worker->socket->socket, APR_TCP_NODELAY, 1)) 
      != APR_SUCCESS) {
    return status;
  }
  if ((status =
         apr_socket_timeout_set(worker->socket->socket, worker->socktmo)) 
      != APR_SUCCESS) {
    return status;
  }
  
  return status;
}

/**
 * Accept a tcp socket
 * @param worker IN callee
 * @return apr status
 */
apr_status_t tcp_close(worker_t *worker) {
  apr_status_t status;

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    return APR_SUCCESS;
  }

  status = apr_socket_close(worker->socket->socket);
  worker->socket->socket = NULL;
  return status;
}

/************************************************************************
 * Commands
 ***********************************************************************/

/**
 * Setup a connection to host
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return an apr status
 */
static apr_status_t block_TCP_LISTEN(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  int backlog_size;
  char *scope_id;

  apr_status_t status = APR_SUCCESS;
  char *address = store_get_copy(worker->params, ptmp, "1");
  char *backlog = store_get_copy(worker->params, ptmp, "2");

  if (!address) {
    worker_log(worker, LOG_ERR, "no address specified");
    status = APR_EINVAL;
  }

  backlog_size = backlog ? apr_atoi64(backlog) : LISTENBACKLOG_DEFAULT;

  if ((status = apr_parse_addr_port(&worker->listener_addr, &scope_id, 
	                            &worker->listener_port, address, 
				    worker->pbody)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Can not parse '%s'", address);
    return status;
  }

  return tcp_listen(worker, backlog_size);
}

/**
 * Setup a connection to host
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return an apr status
 */
static apr_status_t block_TCP_CONNECT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  char *portname;
  char *hostname;

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  hostname = store_get_copy(worker->params, ptmp, "1");
  portname = store_get_copy(worker->params, ptmp, "2");

  worker_log(worker, LOG_DEBUG, "get socket \"%s:%s\"", hostname, portname);
  worker_get_socket(worker, hostname, portname);

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    status = tcp_connect(worker, hostname, portname);

    if ((status = tcp_hook_connect(worker)) != APR_SUCCESS) {
      return status;
    }

    worker->socket->socket_state = SOCKET_CONNECTED;
  }

  worker_test_reset(worker);

  return status;
}

/**
 * Accept connection from remote host 
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return an apr status
 */
static apr_status_t block_TCP_ACCEPT(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_test_unused(worker)) != APR_SUCCESS) {
    return status;
  }

  worker_get_socket(worker, "Default", "0");

  if (worker->socket->socket_state == SOCKET_CLOSED) {
    if ((status = tcp_accept(worker)) != APR_SUCCESS) {
      return status;
    }

    if ((status = tcp_hook_accept(worker, NULL)) != APR_SUCCESS) {
      return status;
    }
    worker->socket->socket_state = SOCKET_CONNECTED;
  }

  worker_test_reset(worker);

  return APR_SUCCESS;
}

/**
 * Accept connection from remote host 
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return an apr status
 */
static apr_status_t block_TCP_CLOSE(worker_t * worker, worker_t *parent, apr_pool_t *ptmp) {
  return tcp_close(worker);
}

/************************************************************************
 * Module 
 ***********************************************************************/
apr_status_t tcp_module_init(global_t *global) {
  apr_status_t status;

  if ((status = module_command_new(global, "TCP", "_LISTEN",
				   "<host>:<port>",
                                   "Listen for TCP connection.",
	                           block_TCP_LISTEN)) != APR_SUCCESS) {
    return status;
  }

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

  if ((status = module_command_new(global, "TCP", "_ACCEPT",
				   "",
                                   "Accept a TCP connection.",
	                           block_TCP_ACCEPT)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "TCP", "_CLOSE",
				   "",
                                   "Close a TCP connection.",
	                           block_TCP_CLOSE)) != APR_SUCCESS) {
    return status;
  }

  htt_hook_connect(tcp_hook_connect, NULL, NULL, 0);
  htt_hook_accept(tcp_hook_accept, NULL, NULL, 0);
  return APR_SUCCESS;
}


