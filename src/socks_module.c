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
  return 1;
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
  apr_status_t status;
  const char *hostname = store_get(worker->params, "1");
  const char *portname = store_get(worker->params, "2");
  apr_port_t port = apr_atoi64(portname);

  if (socks_is_ipv4(hostname)) {
  }
  else {
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


