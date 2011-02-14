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
 * Interface of the HTTP Test Tool socket.
 */

#ifndef HTTEST_SOCKET_H
#define HTTEST_SOCKET_H

#define SOCKREADER_OPTIONS_NONE 0
#define SOCKREADER_OPTIONS_IGNORE_BODY 1

typedef struct sockreader_s sockreader_t;

apr_status_t sockreader_new(sockreader_t ** sockreader, apr_socket_t * socket,
#ifdef USE_SSL
                            SSL * ssl,
#endif
                            char *rest, apr_size_t len, apr_pool_t * p);
apr_status_t sockreader_peek(sockreader_t *self
#ifdef USE_SSL
                             , SSL * ssl
#endif
                             ); 
apr_status_t sockreader_push_back(sockreader_t * self, const char *buf, 
                                  apr_size_t len); 
apr_status_t sockreader_push_line(sockreader_t * self, const char *line);
apr_status_t sockreader_read_line(sockreader_t * self, char **line); 
apr_status_t sockreader_read_block(sockreader_t * self, char *block,
                                   apr_size_t *length); 
apr_status_t content_length_reader(sockreader_t * sockreader,
                                   char **buf, apr_size_t *ct, 
				   const char *val); 
apr_status_t transfer_enc_reader(sockreader_t * sockreader,
                                 char **buf, apr_size_t *len, const char *val); 
apr_status_t eof_reader(sockreader_t * sockreader, char **buf,
                        apr_size_t *len, const char *val);
apr_status_t encapsulated_reader(sockreader_t * sockreader, char **buf,
                                 apr_size_t *len, const char *enc_info,
				 const char *preview); 
apr_socket_t * sockreader_get_socket(sockreader_t *self);
void sockreader_set_options(sockreader_t *self, int options); 

#endif
