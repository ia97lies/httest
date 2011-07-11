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
 * Implementation of the HTTP Test Tool transport.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_lib.h>
#include <apr_errno.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_portable.h>
#include <apr_hash.h>
#include <apr_base64.h>
#include <apr_hooks.h>


#include "defines.h"
#include "transport.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
struct transport_s {
  void *data;
  transport_read_f read;
  transport_write_f write;
};

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Implementation
 ***********************************************************************/
/**
 * create transport object
 * @param data IN custom data
 * @param read IN read method
 * @param write IN write method
 * @return transport object
 */ 
transport_t *transport_new(void *data, 
                           apr_pool_t *pool, 
                           transport_read_f read, 
			   transport_write_f write) {
  transport_t *hook = apr_pcalloc(pool, sizeof(*hook));

  hook->data = data;
  hook->read = read;
  hook->write = write;

  return hook;
}

/** 
 * call registered transport method
 * @param transport IN hook
 * @param buf IN buffer which contains read bytes
 * @param size INOUT size of buffer
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_read(transport_t *hook, char *buf, apr_size_t *size) {
  if (hook && hook->read) {
    return hook->read(hook->data, buf, size);
  }
  else {
    return APR_ENOSOCKET;
  }
}

/** 
 * call registered transport method
 * @param transport IN hook
 * @param buf IN buffer which contains read bytes
 * @param size INOUT size of buffer
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_write(transport_t *hook, char *buf, apr_size_t *size) {
  if (hook && hook->write) {
    return hook->write(hook->data, buf, size);
  }
  else {
    return APR_ENOSOCKET;
  }
}

