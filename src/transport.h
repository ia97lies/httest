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
 * Interface definition of the HTTP Test Tool transport.
 */

#ifndef HTTEST_TRANSPORT_H
#define HTTEST_TRANSPORT_H

typedef struct transport_s transport_t;

/**
 * read method
 * @param data IN custom data
 * @param buf OUT buffer which contains read bytes
 * @param size INOUT size of buffer and on return actually read bytes
 * @return APR_SUCCESS or any apr status
 */
typedef apr_status_t (*transport_read_f)(transport_t *hook, char *buf, 
                                         apr_size_t *size);

/**
 * write method
 * @param data IN custom data
 * @param buf OUT buffer which contains read bytes
 * @param size INOUT size of buffer and on return actually read bytes
 * @return APR_SUCCESS or any apr status
 */
typedef apr_status_t (*transport_write_f)(transport_t *hook, char *buf, 
                                          apr_size_t *size);

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
			   transport_write_f write);

/** 
 * call registered transport method
 * @param transport IN hook
 * @param buf IN buffer which contains read bytes
 * @param size INOUT size of buffer
 * @return APR_SUCCESS, APR_NOSOCK if no transport hook or any apr status
 */
apr_status_t transport_read(transport_t *hook, char *buf, apr_size_t *size);
apr_status_t transport_write(transport_t *hook, char *buf, apr_size_t *size);

#endif
