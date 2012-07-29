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
 * Interface of the HTTP Test Tool store.
 */

#ifndef HTT_FUNCTION_H
#define HTT_FUNCTION_H

#include <apr_pools.h>
#include <htt_executable.h>
#include <htt_context.h>

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
 * @return value
 */
const char *htt_function_update(htt_function_t *function, 
                                htt_executable_t *executable,
                                htt_context_t *context); 

/**
 * Get executable 
 * @param function IN
 * @return executable
 */
const char *htt_function_get_executable(htt_function_t *function);

/**
 * Get context
 * @param function IN
 * @return context
 */
const char *htt_function_get_context(htt_function_t *function);

#endif
