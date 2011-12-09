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
  transport_os_desc_get_f os_desc_get;
  transport_set_timeout_f set_timeout;
  transport_get_timeout_f get_timeout;
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
                           transport_os_desc_get_f os_desc_get, 
                           transport_set_timeout_f set_timeout, 
                           transport_get_timeout_f get_timeout, 
                           transport_read_f read, 
			   transport_write_f write) {
  transport_t *hook = apr_pcalloc(pool, sizeof(*hook));

  hook->data = data;
  hook->os_desc_get = os_desc_get;
  hook->set_timeout = set_timeout;
  hook->get_timeout = get_timeout;
  hook->read = read;
  hook->write = write;

  return hook;
}

/**
 * set new user data
 * @param hook IN transport hook
 * @param data IN new user data
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_set_data(transport_t *hook, void *data) {
  if (hook) {
    hook->data = data;
    return APR_SUCCESS;
  }
  else {
    return APR_EGENERAL;
  }

}

/**
 * Get socket descriptor of the transport protocol
 * @param transport IN hook
 * @param desc OUT os descriptor of this transport
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_os_desc_get(transport_t *hook, int *desc) {
  if (hook && hook->os_desc_get) {
    return hook->os_desc_get(hook->data, desc);
  }
  else {
    *desc = -1;
    return APR_EGENERAL;
  }

}

/** 
 * set timeout for this transport 
 * @param transport IN hook
 * @param t INOUT timeout in ns
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_set_timeout(transport_t *hook, apr_interval_time_t t) {
  if (hook && hook->set_timeout) {
    return hook->set_timeout(hook->data, t);
  }
  else {
    return APR_EGENERAL;
  }
}

/** 
 * get timeout for this transport 
 * @param transport IN hook
 * @param t OUT timeout in ns
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_get_timeout(transport_t *hook, apr_interval_time_t *t) {
  if (hook && hook->get_timeout) {
    return hook->get_timeout(hook->data, t);
  }
  else {
    return APR_EGENERAL;
  }
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
    *size = 0;
    return APR_EGENERAL;
  }
}

/** 
 * call registered transport method
 * @param transport IN hook
 * @param buf IN buffer which contains read bytes
 * @param size IN size of buffer
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_write(transport_t *hook, const char *buf, apr_size_t size) {
  if (hook && hook->write) {
    return hook->write(hook->data, buf, size);
  }
  else {
    return APR_EGENERAL;
  }
}

