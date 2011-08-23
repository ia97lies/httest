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
 * Interface of the HTTP Test Tool eval.
 */

#ifndef HTTEST_EVAL_H
#define HTTEST_EVAL_H

#include <apr_pools.h>

typedef struct math_eval_s math_eval_t;

math_eval_t *math_eval_make(apr_pool_t * pool); 
apr_status_t math_evaluate(math_eval_t * hook, const char *line, long *val); 

#endif
