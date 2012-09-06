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
 * Interface of the HTTP Test Tool expr.
 */

#ifndef HTT_EVAL_H
#define HTT_EVAL_H

#include <apr_pools.h>

typedef struct htt_expr_s htt_expr_t;

/**
 * Create new instance of evaluator
 * @param pool IN pool
 * @return expr instance
 */
htt_expr_t *htt_expr_new(apr_pool_t * pool); 

/**
 * Evaluate math expression 
 * @param hook IN expr instance
 * @param line IN line to parse
 * @param val OUT result
 * @return APR_SUCCESS or APR_EINVAL
 */
apr_status_t htt_expr(htt_expr_t * expr, const char *line, long *val); 

/**
 * Free expr internals 
 * @param hook IN expr instance
 */
void htt_expr_free(htt_expr_t * expr); 

#endif