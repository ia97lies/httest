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
#include <apr_buckets.h>

/************************************************************************
 * Definitions 
 ***********************************************************************/
#define CHARSET_BUF_MAX 8192
typedef struct charset_buf_s {
  const char *const_data;
  char *data;
  apr_size_t len;
  apr_size_t rest;
  apr_size_t i;
} charset_buf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/
static apr_status_t charset_xlate(worker_t *worker, apr_xlate_t *convset, 
                                  const char *string, char **result, apr_size_t* resultLen,
                                  apr_pool_t *ptmp) {
  apr_status_t status;
  apr_bucket_alloc_t *alloc = apr_bucket_alloc_create(ptmp);
  apr_bucket_brigade *bb = apr_brigade_create(ptmp, alloc);
  charset_buf_t *inbuf = apr_pcalloc(ptmp, sizeof(*inbuf));
  charset_buf_t *outbuf = apr_pcalloc(ptmp, sizeof(*outbuf));

  inbuf->const_data = string;
  inbuf->len = strlen(string);
  inbuf->rest = inbuf->len;

  outbuf->data = apr_pcalloc(ptmp, CHARSET_BUF_MAX);

  do {
    outbuf->len = CHARSET_BUF_MAX;
    outbuf->rest = outbuf->len;

    status = apr_xlate_conv_buffer(convset, 
                                   &inbuf->const_data[inbuf->i], &inbuf->rest, 
                                   outbuf->data, &outbuf->rest);
    inbuf->i = inbuf->len -inbuf->rest;
    inbuf->len = inbuf->rest;
    
    apr_brigade_write(bb, NULL, NULL, outbuf->data, outbuf->len - outbuf->rest);
  } while (status == APR_SUCCESS && inbuf->len);
  apr_brigade_putc(bb, NULL, NULL, '\0');

  if (status != APR_SUCCESS) {
    return status;
  }

  status = apr_brigade_pflatten(bb, result, resultLen, ptmp);
  if (status != APR_SUCCESS) {
	worker_log(worker, LOG_ERR, "Can't flatten converted buffer");
    return status;
  }
  return APR_SUCCESS;
}

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
	worker_log(worker, LOG_ERR, "Can not open convert for conversion from %s to %s", from, to);
	return status;
  }

  inbytes = strlen(string);
  outbytes = inbytes;
  outbuf = apr_pcalloc(ptmp, outbytes);
  if ((status = charset_xlate(worker, convset, string, &outbuf, &outbytes, ptmp))
     != APR_SUCCESS) {
	worker_log(worker, LOG_ERR, "Can not convert from %s to %s", from, to);
	return status;
  }

  worker_var_set_and_zero_terminate(parent, result, outbuf, outbytes);

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

