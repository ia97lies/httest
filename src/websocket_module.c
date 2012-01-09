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
  int masked;
  uint8_t op;
  uint8_t pl_len;
  uint16_t mask = 0x0;
  apr_size_t payload_len;
  char *type;
  char *payload;

  if (!worker->sockreader) {
    worker_log_error(worker, "Websockets need a open HTTP stream, use _SOCKET");
  }

  len = 1;
  if ((status = sockreader_read_block(worker->sockreader, (char *)&op, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not read first frame byte");
  }
  worker_log(worker, LOG_DEBUG, "Got opcode 0x%X", op);
  type = NULL;
  if (op & 0x01) {
    type = apr_pstrcat(ptmp, "FIN", type?",":NULL, type, NULL);
  }
  if (op & 0x10) {
    type = apr_pstrcat(ptmp, "CONTINUE", type?",":NULL, type, NULL);
  }
  if (op & 0x20) {
    type = apr_pstrcat(ptmp, "TEXT", type?",":NULL, type, NULL);
  }
  if (op & 0x40) {
    type = apr_pstrcat(ptmp, "BINARY", type?",":NULL, type, NULL);
  }
  if (op & 0x80) {
    type = apr_pstrcat(ptmp, "CLOSE", type?",":NULL, type, NULL);
  }
  worker_log(worker, LOG_INFO, "Opcode: %s", type);

  len = 1;
  if ((status = sockreader_read_block(worker->sockreader, (char *)&pl_len, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not read first frame byte");
  }
  worker_log(worker, LOG_DEBUG, "Got first len byte %x", pl_len);
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
    uint64_t length;
    len = 8;
    if ((status = sockreader_read_block(worker->sockreader, (char *)&length, &len)) != APR_SUCCESS) {
      worker_log_error(worker, "Could not read 32 bit payload length");
    }
    payload_len = ntoh64(length);

  }
  else {
    payload_len = pl_len;
  }
  
  if (masked) {
    worker_log(worker, LOG_INFO, "Masked: %s", masked?"TRUE":"FALSE");
    len = 2;
    if ((status = sockreader_read_block(worker->sockreader, (char *)&mask, &len)) != APR_SUCCESS) {
      worker_log_error(worker, "Could not read mask");
    }
  }

  len = payload_len;
  worker_log(worker, LOG_INFO, "Payload-Length: %ld", len);
  payload = apr_pcalloc(worker->pbody, len + 1);
  if ((status = sockreader_read_block(worker->sockreader, payload, &len)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not read payload");
  }

  /* TODO: If masked unmask */
  worker_log_buf(worker, LOG_INFO, payload, "<", len);

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
  apr_status_t status;
  char *last;
  char *e;
  char *op_param = store_get_copy(worker->params, ptmp, "1");
  const char *payload_len = store_get(worker->params, "2");
  const char *payload = store_get(worker->params, "3");
  const char *mask = store_get(worker->params, "4");
  uint8_t op = 0;
  uint8_t pl_len_8 = 0;
  uint16_t pl_len_16 = 0;
  uint64_t pl_len_64 = 0;
  apr_size_t len;

  if (!worker->socket || !worker->socket->transport) {
    worker_log_error(worker, "No established socket for websocket protocol");
    return APR_ENOSOCKET;
  }

  worker_log(worker, LOG_DEBUG, "payload: \"%s\"", payload);

  e = apr_strtok(op_param, ",", &last);
  while (e) {
    if (strcmp(e, "FIN") == 0) {
      op |= 0x01;
    }
    else if (strcmp(e, "CONTINUE") == 0) {
      op |= 0x10;
    }
    else if (strcmp(e, "TEXT") == 0) {
      op |= 0x20;
    }
    else if (strcmp(e, "BINARY") == 0) {
      op |= 0x40;
    }
    else if (strcmp(e, "CLOSE") == 0) {
      op |= 0x80;
    }
    e = apr_strtok(NULL, ",", &last);
  }
  worker_log(worker, LOG_DEBUG, "Send opcod 0x%X", op);
  
  if (strcmp(payload_len, "AUTO") == 0) {
    if (payload) {
      len = strlen(payload);
    }
  }
  else {
    len = apr_atoi64(payload_len);
  }

  worker_log(worker, LOG_DEBUG, "Payload length: %ld", len);

  if (len < 126) {
    pl_len_8 = len;
  }
  else if (len < 65536) {
    uint16_t tmp;
    pl_len_8 = 126;
    tmp = len;
    pl_len_16 = hton16(tmp);
  }
  else {
    uint16_t tmp;
    pl_len_8 = 127;
    tmp = len;
    pl_len_64 = hton64(tmp);
  }

  pl_len_8 = pl_len_8 << 1;
  if (mask) {
    pl_len_8 |= 0x01;
  }

  if ((status = transport_write(worker->socket->transport, (const char *)&op, 1)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not send Opcode");
    return status;
  }

  if ((status = transport_write(worker->socket->transport, (const char *)&pl_len_8, 1)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not send first len byte");
    return status;
  }

  if (pl_len_16) {
    if ((status = transport_write(worker->socket->transport, (const char *)&pl_len_16, 2)) != APR_SUCCESS) {
      worker_log_error(worker, "Could not send 16 bit len bytes");
      return status;
    }
  }

  if (pl_len_64) {
    if ((status = transport_write(worker->socket->transport, (const char *)&pl_len_64, 8)) != APR_SUCCESS) {
      worker_log_error(worker, "Could not send 64 bit len bytes");
      return status;
    }
  }

  if (mask) {
    /* TODO */
  }

  if ((status = transport_write(worker->socket->transport, payload, len)) != APR_SUCCESS) {
    worker_log_error(worker, "Could not send payload");
    return status;
  }
  worker_log_buf(worker, LOG_INFO, payload, ">", len);


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

