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
 * Implementation of the HTTP Test Tool binary module 
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
 * SEND binary data
 *
 * @param worker IN
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_BINARY_SEND(worker_t * worker, worker_t *parent) {
  apr_status_t status = APR_SUCCESS;
  const char *data;
  char *copy;
  apr_size_t i;
  apr_table_entry_t *e;

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }
    
  e = (apr_table_entry_t *) apr_table_elts(worker->params)->elts;
  for (i = 1; i < apr_table_elts(worker->params)->nelts; i++) {
    int unresolved; 

    data = e[i].val;
    copy = apr_pstrdup(worker->pbody, data);
    copy = worker_replace_vars(worker, copy, &unresolved);

    apr_table_addn(worker->cache, 
		   apr_pstrdup(worker->pcache, "BINARY"), copy);
  }

error:
  return status;
}

/**
 * RECV binary data and makes a hex dump
 *
 * @param worker IN 
 * @param parent IN
 *
 * @return APR_SUCCESS or an APR error
 */
static apr_status_t block_BINARY_RECV(worker_t * worker, worker_t *parent) {
  char *copy;
  apr_pool_t *pool;
  apr_status_t status;
  apr_size_t recv_len;
  apr_size_t peeklen;
  sockreader_t *sockreader;
  char *buf;
  const char *val;
  int j;

  int poll = 0;

  val = apr_table_get(worker->params, "1");
  /* must be a number */
  recv_len = apr_atoi64(val);

  apr_pool_create(&pool, NULL);

  if (worker->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&sockreader, worker->socket->socket,
#ifdef USE_SSL
				 worker->socket->is_ssl ? worker->socket->ssl : NULL,
#endif
				 worker->socket->peek, peeklen, pool)) != APR_SUCCESS) {
      goto out_err;
    }
  }
  else {
    sockreader = worker->sockreader;
  }

  if ((status = content_length_reader(sockreader, &buf, &recv_len, "")) != APR_SUCCESS) {
    if (poll && APR_STATUS_IS_INCOMPLETE(status)) {
      status = APR_SUCCESS;
    }
    else {
      goto out_err;
    }
  }

  worker->flags |= FLAGS_PRINT_HEX;
  if ((status = worker_handle_buf(worker, pool, buf, recv_len)) 
      != APR_SUCCESS) {
    goto out_err;
  }

out_err:
  status = worker_check_expect(worker, status);
  apr_pool_destroy(pool);

  return status;
}

/**
 * Do hex to bin transformation with this hook, this is called
 * after late variable replacement.
 *
 * @param worker IN worker context
 * @param line IN line informations
 */
static void binary_flush_resolved_line(worker_t *worker, line_t *line) {
  apr_size_t len;
  char *buf;
  apr_size_t i;

  /* lets see if we do have work */
  if (strcmp(line->info, "BINARY") != 0) {
    return;
  }

  apr_collapse_spaces(line->buf, line->buf);
  /* callculate buf len */
  len = strlen(line->buf);
  if (len && len%2 != 1) {
    len /= 2;
  }
  else {
    worker_log_error(worker, "Binary data must have an equal number of digits");
    return;
  }

  buf = apr_pcalloc(worker->pcache, len);

  for (i = 0; i < len; i++) {
    char hex[3];
    hex[0] = line->buf[i * 2];
    hex[1] = line->buf[i * 2 + 1];
    hex[2] = 0;
    buf[i] = (char )apr_strtoi64(hex, NULL, 16);
  }
  line->buf = buf;
  line->len = len;

  line->info = apr_psprintf(worker->pcache, "NOCRLF:%d", len);
}

/************************************************************************
 * Implementation
 ***********************************************************************/
apr_status_t binary_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "BINARY", "_SEND", "<hex-digits>*",
	                           "send hex digits as binary data",
	                           block_BINARY_SEND)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "BINARY", "_RECV", "<number-of-bytes>",
	                           "prints received data as hex digit",
	                           block_BINARY_RECV)) != APR_SUCCESS) {
    return status;
  }
  htt_hook_flush_resolved_line(binary_flush_resolved_line, NULL, NULL, 0);
  return APR_SUCCESS;
}

