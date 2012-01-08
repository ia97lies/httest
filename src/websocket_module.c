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
 * Implementation of the HTTP Test Tool Websocket Extention 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * ws_module = "ws_module";

/************************************************************************
 * Private 
 ***********************************************************************/

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Recevie websocket frames
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temp pool
 * @return apr status
 */
static apr_status_t block_WS_RECV(worker_t *worker, worker_t *parent, 
                                  apr_pool_t *ptmp) {
  if (!worker->sockreader) {
    worker_log_error(worker, "Websockets need a open HTTP stream, use _SOCKET");
  }

  return APR_SUCCESS;
}

/**
 * Send websocket frames
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temp pool
 * @return apr status
 */
static apr_status_t block_WS_SEND(worker_t *worker, worker_t *parent, 
                                  apr_pool_t *ptmp) {
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t websocket_module_init(global_t *global) {
  apr_status_t status;

  if ((status = module_command_new(global, "WS", "_RECV", "",
				   "Receive websocket frames",
	                           block_WS_RECV)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "WS", "_SEND", "",
				   "Send websocket frames",
	                           block_WS_SEND)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

