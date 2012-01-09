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
  apr_status_t status;
  apr_size_t len;
  int fin;
  int masked;
  uint8_t op;
  uint8_t pl_len;
  uint16_t mask = 0x0;
  apr_size_t payload_len;
  char *payload;

  if (!worker->sockreader) {
    worker_log_error(worker, "Websockets need a open HTTP stream, use _SOCKET");
  }

  len = 1;
  if ((status = sockreader_read_block(worker->sockreader, (char *)&op, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not read first frame byte");
  }
  fin = op & 0x01;

  len = 1;
  if ((status = sockreader_read_block(worker->sockreader, (char *)&pl_len, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not read first frame byte");
  }
  masked = pl_len & 0x01;
  pl_len = pl_len >> 1;

  if (pl_len == 126) {
    uint16_t length;
    len = 2;
    if ((status = sockreader_read_block(worker->sockreader, (char *)&length, &len)) != APR_SUCCESS) {
      worker_log_error(worker, "Could not read 16 bit payload length");
    }
    payload_len = ntoh16(length);
  }
  else if (pl_len == 127) {
    uint32_t length;
    len = 4;
    if ((status = sockreader_read_block(worker->sockreader, (char *)&length, &len)) != APR_SUCCESS) {
      worker_log_error(worker, "Could not read 32 bit payload length");
    }
    payload_len = ntoh32(length);

  }
  else {
    payload_len = pl_len;
  }
  
  if (masked) {
    len = 2;
    if ((status = sockreader_read_block(worker->sockreader, (char *)&mask, &len)) != APR_SUCCESS) {
      worker_log_error(worker, "Could not read mask");
    }
  }

  len = payload_len;
  payload = apr_pcalloc(worker->pbody, len + 1);
  if ((status = sockreader_read_block(worker->sockreader, payload, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not read payload");
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

