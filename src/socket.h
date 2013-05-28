/**
 * Copyright 2006 Christian Liesch
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
 * Interface of the HTTP Test Tool socket.
 */

#ifndef HTTEST_SOCKET_H
#define HTTEST_SOCKET_H

#include "transport.h"

#define SOCKREADER_OPTIONS_NONE 0
#define SOCKREADER_OPTIONS_IGNORE_BODY 1

typedef struct sockreader_s sockreader_t;

apr_status_t sockreader_new(sockreader_t ** sockreader, transport_t * transport,
                            char *rest, apr_size_t len);
void sockreader_destroy(sockreader_t **sockreader);
void sockreader_set_transport(sockreader_t *sockreader, 
                              transport_t *transport); 
apr_socket_t * sockreader_get_socket(sockreader_t *self);
void sockreader_set_options(sockreader_t *self, int options); 
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

#endif
