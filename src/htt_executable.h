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

#ifndef HTT_EXECUTABLE_H
#define HTT_EXECUTABLE_H

#include <apr_hash.h>
#include "htt_context.h"

typedef struct htt_executable_s htt_executable_t;

typedef apr_status_t(*htt_function_f)(htt_executable_t *executable, 
                                      htt_context_t *context, 
                                      apr_pool_t *ptmp, htt_store_t *params, 
                                      htt_store_t *retvars, char *line);

/**
 * Create a new executable
 * @param pool IN
 * @param name IN name of function
 * @param function IN function
 * @param cleanup IN cleanup after function has done work
 * @param raw IN the raw args line
 * @param file IN filename
 * @param line IN line number
 * @return executable
 */
htt_executable_t *htt_executable_new(apr_pool_t *pool, const char *name,
                                     const char *signature, 
                                     htt_function_f function, char *raw, 
                                     const char *file, int line);

/**
 * Get file name of this executable
 * @param executable IN
 * @return file name
 */
const char *htt_executable_get_file(htt_executable_t *executable);

/**
 * Get line of this executable
 * @param executable IN
 * @return line 
 */
int htt_executable_get_line(htt_executable_t *executable); 

/**
 * Get raw line no resolve
 * @param executable IN executable
 * @return raw string
 */
const char *htt_executable_get_raw(htt_executable_t *executable);

/**
 * Get configuration of executable
 * @param executable IN
 * @return config hash
 */
apr_hash_t *htt_executable_get_config(htt_executable_t *executable); 

/**
 * Add a executable to an executable (body)
 * @param executable IN
 * @param addition IN executable to incorporate
 */
void htt_executable_add(htt_executable_t *executable, 
                        htt_executable_t *addition);

/**
 * Get function from executable
 * @param executable IN
 * @return function
 */
htt_function_f htt_executable_get_function(htt_executable_t *executable);

/**
 * Execute an executable
 * @param executable IN 
 * @param context IN executable context
 * @return apr status
 */
apr_status_t htt_execute(htt_executable_t *executable, htt_context_t *context); 


#endif
