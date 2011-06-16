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
static apr_status_t command_SEND(worker_t * worker, worker_t *parent) {
  char *copy;
  char *buf;
  apr_size_t len;
  apr_size_t i;

  if (!worker->socket || !worker->socket->socket) {
    return APR_ENOSOCKET;
  }
    
  copy = apr_pstrdup(worker->pbody, data); 
  copy = worker_replace_vars(worker, copy);
  worker_log(worker, LOG_CMD, "%s%s", self->name, copy); 
  apr_collapse_spaces(copy, copy);

  /* callculate buf len */
  len = strlen(copy);
  if (len && len%2 != 1) {
    len /= 2;
  }
  else {
    worker_log_error(worker, "Binary data must have an equal number of digits");
    return APR_EINVAL;
  }

  buf = apr_pcalloc(worker->pcache, len);

  for (i = 0; i < len; i++) {
    char hex[3];
    hex[0] = copy[i * 2];
    hex[1] = copy[i * 2 + 1];
    hex[2] = 0;
    buf[i] = (char )apr_strtoi64(hex, NULL, 16);
  }

  apr_table_addn(worker->cache, 
		 apr_psprintf(worker->pcache, "NOCRLF:%d", len), buf);

  return APR_SUCCESS;

  return APR_SUCCESS;
}

/************************************************************************
 * Implementation
 ***********************************************************************/
apr_status_t binary_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "BINARY", "SEND", 
	                           command_SEND)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
}

