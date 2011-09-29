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
 * Implementation of the HTTP Test Tool socks module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"
#include <netinet/in.h>

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef union ip_s {
  uint32_t addr;
  uint8_t  digit[4];
} ip_u;

typedef union port_s {
  uint16_t port;
  uint8_t  digit[2];
} port_u;

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * check if string is an IPv4 address
 * @param addr IN addr to check
 * @return 1 if it is IPv4 else 0
 */ 
static int socks_is_ipv4(const char *addr) {
  return apr_isdigit(addr[0]);
}

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Do socks proxy handshake.
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temp pool
 * @return apr status
 */
static apr_status_t block_SOCKS_CONNECT(worker_t *worker, worker_t *parent, 
                                        apr_pool_t *ptmp) {
  port_u port;
  unsigned char buf[10];
  apr_status_t status;
  char *hostname = store_get_copy(worker->params, ptmp, "1");
  const char *portname = store_get(worker->params, "2");
  transport_t *transport;
  apr_size_t len;
 
  if (!worker->socket) {
    worker_log_error(worker, "Can not send initial SOCKS bytes");
    return APR_ENOSOCKET;
  }

  transport = worker->socket->transport;

  buf[0] = 5; buf[1] = 1; buf[2] = 0;
  if ((status = transport_write(transport, (char *)buf, 3)) != APR_SUCCESS) {
    worker_log_error(worker, "Can not send initial SOCKS bytes");
    return status;
  }
  
  len = 2;
  if ((status = transport_read(transport, (char *)buf, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Can not read initial SOCKS bytes");
    return status;
  }    

  if (len != 2 || buf[0] != 5 || buf[1] != 0) {
    worker_log_error(worker, "Wrong protocol bytes received");
    return APR_EINVAL;
  }

  buf[0] = 5; buf[1] = 1; buf[2] = 0; 

  if (socks_is_ipv4(hostname)) {
    ip_u ip;
    char *last;
    char *digit = apr_strtok(hostname, ".", &last);
    int i = 0;
    ip.addr = 0;
    while (digit) {
      ip.digit[i] = atoi(digit);
      digit = apr_strtok(NULL, ".", &last);
      i++;
    }
    
    /* ATYPE IPv4 */
    buf[3] = 1;
    for (i = 0; i < 4; i++) {
      buf[4 + i] = ip.digit[i];
    }
    if ((status = transport_write(transport, (char *)buf, 8)) != APR_SUCCESS) {
      worker_log_error(worker, "Can not send IP to SOCKS proxy");
      return status;
    }
  }
  else {
    /* ATYPE Domain name */
    buf[3] = 3;
    buf[4] = strlen(hostname);
    if ((status = transport_write(transport, (char *)buf, 5)) != APR_SUCCESS) {
      worker_log_error(worker, "Can not send hostname to SOCKS proxy");
      return status;
    }
    if ((status = transport_write(transport, hostname, buf[4])) != APR_SUCCESS) {
      worker_log_error(worker, "Can not send hostname to SOCKS proxy");
      return status;
    }
  }

  port.port = atoi(portname);
  port.port = htons(port.port);

  if ((status = transport_write(transport, (char *)port.digit, 2)) != APR_SUCCESS) {
    worker_log_error(worker, "Can not send port to SOCKS proxy");
    return status;
  }

  len = 10;
  if ((status = transport_read(transport, (char *)buf, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Can not read final SOCKS bytes");
    return status;
  }    
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t socks_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "SOCKS", "_CONNECT",
	                           "<remote-host> <remote-port>",
	                           "Do run socks protocol over a established TCP connection",
	                           block_SOCKS_CONNECT)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}


