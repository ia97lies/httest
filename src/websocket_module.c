/**
 * Copyright 2011 Christian Liesch
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
 * Implementation of the HTTP Test Tool Websocket Extention 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
#define WS_8_TYPE_CONTINUE 0x0
#define WS_8_TYPE_TEXT 0x1
#define WS_8_TYPE_BINARY 0x2
#define WS_8_TYPE_CLOSE 0x8
#define WS_8_TYPE_PING 0x9
#define WS_8_TYPE_PONG 0xA

const char * ws_module = "ws_module";

typedef struct ws_socket_config_s {
  int version;
} ws_socket_config_t;

/************************************************************************
 * Private 
 ***********************************************************************/

/**
 * GET ssl socket config from socket
 * @param worker IN worker
 * @return socket config
 */
static ws_socket_config_t *ws_get_socket_config(worker_t *worker) {
   ws_socket_config_t *config;
   if (!worker || !worker->socket) {
    return NULL;
  }

  config = module_get_config(worker->socket->config, ws_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->socket->config, 
                      apr_pstrdup(worker->pbody, ws_module), config);
  }
  return config;
}

/**
 * Do hex to bin transformation with this hook, this is called
 * after late variable replacement.
 *
 * @param worker IN worker context
 * @param payload IN payload as a string of space separated hex digits
 * @param binary OUT binary data buffer
 * @param binary_len OUT binary data buffer length
 */
static apr_status_t ws_hex_to_binary(worker_t *worker, char *payload, char **binary, size_t *binary_len) {
  apr_status_t status;
  char *buf;
  apr_size_t i;
  apr_size_t len;

  apr_collapse_spaces(payload, payload);
  /* callculate buf len */
  len = strlen(payload);
  if (len && len%2 != 1) {
    len /= 2;
  }
  else {
    worker_log(worker, LOG_ERR, "Binary data must have an equal number of digits");
    return APR_EINVAL;
  }

  buf = apr_pcalloc(worker->pbody, len);

  for (i = 0; i < len; i++) {
    char hex[3];
    hex[0] = payload[i * 2];
    hex[1] = payload[i * 2 + 1];
    hex[2] = 0;
    buf[i] = (char )apr_strtoi64(hex, NULL, 16);
  }
  *binary = buf;
  *binary_len = len;

  return APR_SUCCESS;
}

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
static apr_status_t block_WS_VERSION(worker_t *worker, worker_t *parent, 
                                     apr_pool_t *ptmp) {
  ws_socket_config_t *sconf = ws_get_socket_config(worker);
  sconf->version = 13;
  return APR_SUCCESS;
}

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
  uint32_t mask = 0x0;
  uint64_t payload_len = 0;
  char *type;
  char *payload;

  const char *type_param = store_get(worker->params, "1");
  const char *len_param = store_get(worker->params, "2");

  if (!worker->socket->sockreader) {
    worker_log(worker, LOG_ERR, 
               "Websockets need a open HTTP stream, use _SOCKET");
    return APR_ENOSOCKET;
  }

  len = 1;
  if ((status = sockreader_read_block(worker->socket->sockreader, 
                                      (char *)&op, &len)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not read first frame byte");
	goto exit;
  }
  worker_log(worker, LOG_DEBUG, "Got opcode 0x%X", op);
  type = NULL;
  if ((op >> 7) & 1) {
    type = apr_pstrcat(ptmp, "FIN", type?",":NULL, type, NULL);
  }
  
  switch (op &0xf) {
  case WS_8_TYPE_CONTINUE:
    type = apr_pstrcat(ptmp, "CONTINUE", type?",":NULL, type, NULL);
    break;
  case WS_8_TYPE_TEXT:
    type = apr_pstrcat(ptmp, "TEXT", type?",":NULL, type, NULL);
    break;
  case WS_8_TYPE_BINARY:
    type = apr_pstrcat(ptmp, "BINARY", type?",":NULL, type, NULL);
    break;
  case WS_8_TYPE_CLOSE:
    type = apr_pstrcat(ptmp, "CLOSE", type?",":NULL, type, NULL);
    break;
  case WS_8_TYPE_PING:
    type = apr_pstrcat(ptmp, "PING", type?",":NULL, type, NULL);
    break;
  case WS_8_TYPE_PONG:
    type = apr_pstrcat(ptmp, "PONG", type?",":NULL, type, NULL);
    break;
  }

  len = 1;
  if ((status = sockreader_read_block(worker->socket->sockreader, 
                                      (char *)&pl_len, &len)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not read first frame byte");
	goto exit;
  }
  worker_log(worker, LOG_DEBUG, "Got first len byte %x", pl_len);
  masked = (pl_len & 0x80);
  if (masked) {
    type = apr_pstrcat(ptmp, "MASKED", type?",":NULL, type, NULL);
  }
  worker_log(worker, LOG_DEBUG, "Opcode: %s", type);
  if (type_param) {
    worker_var_set(worker, type_param, type?type:"<NONE>");
  }
  pl_len = pl_len & 0x7f;

#if APR_IS_BIGENDIAN
  worker_log(worker, LOG_DEBUG, "bigendian", type);
#else
  worker_log(worker, LOG_DEBUG, "littlendian", type);
#endif
  if (pl_len == 126) {
    uint16_t length;
    worker_log(worker, LOG_DEBUG, "payload uint16 read 2 length bytes", type);
    len = 2;
    if ((status = sockreader_read_block(worker->socket->sockreader, 
                                        (char *)&length, &len)) 
        != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not read 16 bit payload length");
	  goto exit;
    }
#if APR_IS_BIGENDIAN
	payload_len = length;
#else
    payload_len = swap16(length);
#endif
  }
  else if (pl_len == 127) {
    uint64_t length;
    worker_log(worker, LOG_DEBUG, "payload uint64 read 4 length bytes", type);
    len = 8;
    if ((status = sockreader_read_block(worker->socket->sockreader, 
                                        (char *)&length, &len)) 
        != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not read 32 bit payload length");
	  goto exit;
    }
#if APR_IS_BIGENDIAN
	payload_len = length;
#else
    payload_len = swap64(length);
#endif
  }
  else {
    worker_log(worker, LOG_DEBUG, "payload uint8", type);
    payload_len = pl_len;
  }
  
  if (masked) {
    len = 4;
    if ((status = sockreader_read_block(worker->socket->sockreader, 
                                        (char *)&mask, &len)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not read mask");
	  goto exit;
    }
  }

  if (len_param) {
    worker_var_set(worker, len_param, apr_itoa(ptmp, payload_len));
  }
  worker_log(worker, LOG_DEBUG, "Payload-Length: %ld", payload_len);
  payload = apr_pcalloc(worker->pbody, payload_len + 1);
  len = payload_len;
  status = sockreader_read_block(worker->socket->sockreader, payload, &len);
  worker_log(worker, LOG_DEBUG, "Got: %ld bytes; Status: %d", payload_len, status);
  if (status != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not read payload");
	goto exit;
  }

  if (masked) {
    int i, j;
    for (i = 0; i < payload_len; i++) {
      j = i % 4;
      payload[i] ^= ((uint8_t *)&mask)[j];
    }
  }

exit:
  {
	apr_status_t hndl_buf_status;
	hndl_buf_status = worker_handle_buf(worker, ptmp, payload, payload_len);
	if (hndl_buf_status != APR_SUCCESS) {
	  worker_log(worker, LOG_ERR, "inspect payload failed");
	  return status;
	}
	status = worker_assert(worker, status);
	return status;
  }
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
  char *payload = store_get_copy(worker->params, ptmp, "3");
  const char *mask_str = store_get(worker->params, "4");
  uint8_t op = 0;
  uint8_t pl_len_8 = 0;
  uint16_t pl_len_16 = 0;
  uint64_t pl_len_64 = 0;
  uint64_t len;
  int is_binary = 0;

  if (!worker->socket || !worker->socket->transport) {
    worker_log(worker, LOG_ERR, "No established socket for websocket protocol");
    return APR_ENOSOCKET;
  }

  worker_log(worker, LOG_DEBUG, "payload: \"%s\"", payload);

  e = apr_strtok(op_param, ",", &last);
  while (e) {
    if (strcmp(e, "FIN") == 0) {
      op |= 1 << 7;
    }
    else if (strcmp(e, "CONTINUE") == 0) {
      op |= WS_8_TYPE_CONTINUE;
    }
    else if (strcmp(e, "TEXT") == 0) {
      op |= WS_8_TYPE_TEXT;
    }
    else if (strcmp(e, "BINARY") == 0) {
      op |= WS_8_TYPE_BINARY;
      is_binary = 1;
    }
    else if (strcmp(e, "CLOSE") == 0) {
      op |= WS_8_TYPE_CLOSE;
    }
    else if (strcmp(e, "PING") == 0) {
      op |= WS_8_TYPE_PING;
    }
    else if (strcmp(e, "PONG") == 0) {
      op |= WS_8_TYPE_PONG;
    }
    e = apr_strtok(NULL, ",", &last);
  }
  worker_log(worker, LOG_DEBUG, "Send opcod 0x%X", op);
  
  if (strcmp(payload_len, "AUTO") == 0) {
    if (payload) {
      if (is_binary) {
        char *result;
        if ((status = ws_hex_to_binary(worker, payload, &result, &len)) != APR_SUCCESS) {
            return status;
        }
        payload = result;
      }
      else {
        len = strlen(payload);
      }
    }
    else {
      len = 0;
    }
  }
  else {
    len = apr_atoi64(payload_len);
  }

  worker_log(worker, LOG_DEBUG, "Payload length: %ld", len);

  if (len < 126) {
    pl_len_8 = len;
  }
  else if (len <= 0xFFFF) {
    uint16_t tmp;
    pl_len_8 = 126;
    tmp = len;
#if APR_IS_BIGENDIAN
    pl_len_16 = tmp;
#else
    pl_len_16 = swap16(tmp);
#endif
  }
  else {
    uint64_t tmp;
    pl_len_8 = 127;
    tmp = len;
#if APR_IS_BIGENDIAN
    pl_len_64 = tmp;
#else
    pl_len_64 = swap64(tmp);
#endif
  }

  pl_len_8 = pl_len_8;
  worker_log(worker, LOG_DEBUG, "pl_len: %0x", pl_len_8);
  if (mask_str) {
    pl_len_8 |= 0x80;
  }
  worker_log(worker, LOG_DEBUG, "pl_len_8: %0x, pl_len_16: %ld, pl_len_64: %ld",
             pl_len_8, pl_len_16, pl_len_64);

  if ((status = transport_write(worker->socket->transport, 
                                (const char *)&op, 1)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not send Opcode");
    return status;
  }

  if ((status = transport_write(worker->socket->transport, 
                                (const char *)&pl_len_8, 1)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not send first len byte");
    return status;
  }

  if (pl_len_16) {
    if ((status = transport_write(worker->socket->transport, 
                                  (const char *)&pl_len_16, 2)) 
        != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not send 16 bit len bytes");
      return status;
    }
  }

  if (pl_len_64) {
    if ((status = transport_write(worker->socket->transport, 
                                  (const char *)&pl_len_64, 8)) 
        != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not send 64 bit len bytes");
      return status;
    }
  }

  if (mask_str) {
    uint32_t mask = apr_strtoi64(mask_str, NULL, 0);
    int i, j;
    for (i = 0; i < len; i++) {
      j = i % 4;
      payload[i] ^= ((uint8_t *)&mask)[j];
    }
    if ((status = transport_write(worker->socket->transport,
                                  (const char *)&mask, 4)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not send mask bytes");
      return status;
    }
  }

  if ((status = transport_write(worker->socket->transport, payload, len)) 
      != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Could not send payload");
    return status;
  }
  logger_log_buf(worker->logger, LOG_INFO, '>', payload, len);


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

  if ((status = module_command_new(global, "WS", "_SEND", "<type> <length> <data> <mask>",
				   "Send websocket frames\n" 
				   "  <type>: can be one or more of the following keywords\n"
			           "          FIN, CONTINUE, CLOSE, TEXT, BINARY, PING, PONG\n"
				   "          there are combinations which will not work, see also RFC\n"
				   "          of websockets to get a clue what is possible and what not.\n"
				   "  <length>: Length of data or AUTO to do this automaticaly\n"
				   "  <data>: Data to be send if spaces the data must be quoted\n"
				   "  <mask>: Optional 64 Byte number to mask data",
	                           block_WS_SEND)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "WS", "_VERSION", "",
				   "Set version, for the moment only version 13 is implemented",
	                           block_WS_VERSION)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

