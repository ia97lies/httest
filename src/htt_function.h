/**
 * Copyright 2012 Christian Liesch
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
 * Interface of the HTTP Test Tool function type.
 */

#ifndef HTT_FUNCTION_H
#define HTT_FUNCTION_H

#include <apr_pools.h>
#include "htt_executable.h"
#include "htt_context.h"

typedef struct htt_function_s htt_function_t;

/**
 * Create a function variable
 * @param pool IN parent pool for inheritance
 * @param value IN function to hold in this function variable
 * @return function instance 
 */
htt_function_t *htt_function_new(apr_pool_t *pool, htt_executable_t *executable,
                                 htt_context_t *context);

/**
 * Update function 
 * @param function IN
 * @param value IN new function, replace the old, no memory loss 
 */
void htt_function_update(htt_function_t *function, htt_executable_t *executable,
                         htt_context_t *context); 

/**
 * Get executable 
 * @param function IN
 * @return executable
 */
htt_executable_t *htt_function_get_executable(htt_function_t *function);

/**
 * Get context
 * @param function IN
 * @return context
 */
htt_context_t *htt_function_get_context(htt_function_t *function);

/**
 * Execute a function with its context
 * @param function IN
 * @param ptmp IN temporary pool
 * @param params IN input parameters
 * @param retvars IN return parameters
 * @return apr status
 */
apr_status_t htt_function_call(htt_function_t *function, apr_pool_t *ptmp, 
                               htt_map_t *params, htt_stack_t *retvars); 

/**
 * Test if a pointer is a function type
 * @param void IN possible string pointer
 * @return 1 if it is a string type
 */
int htt_isa_function(void *type);

/**
 * Function destructor
 * @param function IN
 */
void htt_function_free(void *function);

#endif
