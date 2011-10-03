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
 * Interface of the HTTP Test Tool util.
 */

#ifndef HTTEST_UTIL_H
#define HTTEST_UTIL_H

#include "store.h"

typedef const char *replace_vars_f(void *udata, const char *name);

char *my_unescape(char *string, char **last); 
apr_table_t *my_table_deep_copy(apr_pool_t *p, apr_table_t *orig); 
apr_table_t *my_table_swallow_copy(apr_pool_t *p, apr_table_t *orig); 
char *my_status_str(apr_pool_t * p, apr_status_t rc); 
char *my_replace_vars(apr_pool_t * p, char *line, void *udata, 
                      replace_vars_f replace);
void copyright(const char *progname); 
const char *filename(apr_pool_t *pool, const char *path); 
char x2c(const char *what); 
void my_get_args(char *line, store_t *params, apr_pool_t *pool); 

#endif
