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
 * Implementation of the HTTP Test Tool charset module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"
#include <apr_xlate.h>

/************************************************************************
 * Definitions 
 ***********************************************************************/

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/

/************************************************************************
 * Commands 
 ***********************************************************************/
static apr_status_t block_CHARSET_CONVERT(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  apr_xlate_t *convset;
  const char *from = store_get(worker->params, "1");
  const char *to = store_get(worker->params, "2");
  const char *string = store_get(worker->params, "3");
  const char *result = store_get(worker->params, "4");
  char *outbuf;
  apr_size_t inbytes;
  apr_size_t outbytes;

  if ((status = apr_xlate_open(&convset, to, from, ptmp)) != APR_SUCCESS) {
	worker_log_error(worker, "Can not open convert for conversion from %s to %s", from, to);
	return status;
  }

  inbytes = strlen(string);
  outbytes = inbytes;
  outbuf = apr_pcalloc(ptmp, outbytes);
  if ((status = apr_xlate_conv_buffer(convset, string, &inbytes, outbuf, &outbytes))
     != APR_SUCCESS) {
	worker_log_error(worker, "Can not convert from %s to %s", from, to);
	return status;
  }

  worker_var_set(parent, result, outbuf);

  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t charset_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "CHARSET", "_CONVERT",
	                           "<from-charset> <to-charset> <string>",
	                           "Convert a string from on to another charset",
	                           block_CHARSET_CONVERT)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
}

