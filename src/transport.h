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
 * Interface definition of the HTTP Test Tool transport.
 */

#ifndef HTTEST_TRANSPORT_H
#define HTTEST_TRANSPORT_H

typedef struct transport_s transport_t;

/**
 * socket/file descriptor method
 * @param data IN custom data
 * @param desc OUT filedescriptor
 * @return APR_SUCCESS or any apr status
 */
typedef apr_status_t (*transport_os_desc_get_f)(void *data, int *desc);

/**
 * set timeout method
 * @param data IN custom data
 * @param t IN timeout
 * @return APR_SUCCESS or any apr status
 */
typedef apr_status_t (*transport_set_timeout_f)(void *data, apr_interval_time_t t);

/**
 * set timeout method
 * @param data IN custom data
 * @param t OUT timeout
 * @return APR_SUCCESS or any apr status
 */
typedef apr_status_t (*transport_get_timeout_f)(void *data, apr_interval_time_t *t);

/**
 * read method
 * @param data IN custom data
 * @param buf IN buffer which contains read bytes
 * @param size INOUT size of buffer and on return actually read bytes
 * @return APR_SUCCESS or any apr status
 */
typedef apr_status_t (*transport_read_f)(void *data, char *buf, 
                                         apr_size_t *size);

/**
 * write method
 * @param data IN custom data
 * @param buf IN buffer which contains read bytes
 * @param size IN size of buffer and on return actually read bytes
 * @return APR_SUCCESS or any apr status
 */
typedef apr_status_t (*transport_write_f)(void *data, const char *buf, 
                                          apr_size_t size);

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
			   transport_write_f write);

/**
 * set new user data
 * @param hook IN transport hook
 * @param data IN new user data
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_set_data(transport_t *hook, void *data);

/**
 * get user data
 * @param hook IN transport hook
 * @return user data
 */
void *transport_get_data(transport_t *hook);

/**
 * Get socket descriptor of the transport protocol
 * @param hook IN transport hook
 * @param desc OUT os descriptor of this transport
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_os_desc_get(transport_t *hook, int *desc);

/**
 * Set transport timeout 
 * @param hook IN transport hook
 * @param t IN timeout
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_set_timeout(transport_t *hook, apr_interval_time_t t);

/**
 * Set transport timeout 
 * @param hook IN transport hook
 * @param t OUT timeout
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_get_timeout(transport_t *hook, apr_interval_time_t *t);

/** 
 * call registered transport method
 * @param hook IN transport hook
 * @param buf IN buffer which contains read bytes
 * @param size INOUT size of buffer
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_read(transport_t *hook, char *buf, apr_size_t *size);

/** 
 * call registered transport method
 * @param hook IN transport hook
 * @param buf IN buffer which contains read bytes
 * @param size IN size of buffer
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_write(transport_t *hook, const char *buf, apr_size_t size);

#endif
