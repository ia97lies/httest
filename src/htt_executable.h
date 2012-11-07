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
 * Interface of the HTTP Test Tool executable.
 */

#ifndef HTT_EXECUTABLE_H
#define HTT_EXECUTABLE_H

#include <apr_hash.h>
#include <apr_hooks.h>
#include "htt_map.h"
#include "htt_stack.h"
#include "htt_context.h"

typedef struct htt_executable_s htt_executable_t;

#define HTT_STATUS_BREAK -1

typedef apr_status_t(*htt_function_f)(htt_executable_t *executable, 
                                      htt_context_t *context, 
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvals, char *line);

/**
 * Create a new executable
 * @param pool IN
 * @param parent IN parent executable need for on the fly command lookup
 * @param name IN name of function
 * @param function IN function
 * @param cleanup IN cleanup after function has done work
 * @param raw IN the raw args line
 * @param file IN filename
 * @param line IN line number
 * @return executable
 */
htt_executable_t *htt_executable_new(apr_pool_t *pool, htt_executable_t *parent,
                                     const char *name, const char *signature, 
                                     htt_function_f function, char *raw, 
                                     const char *file, int line);

/**
 * Dump entries for debug purpose
 * @param executable IN 
 */
void htt_executable_dump(htt_executable_t *executable); 

/**
 * Set stack of parameters
 * @param executable IN
 * @param params IN
 */
void htt_executable_set_params(htt_executable_t *executable, 
                               htt_stack_t *params); 

/**
 * Set parent 
 * @param executable IN
 * @param parent IN parent executable
 */
void htt_executable_set_parent(htt_executable_t *executable, 
                               htt_executable_t *parent); 

/**
 * Set stack of return variable
 * @param executable IN
 * @param params IN
 */
void htt_executable_set_retvars(htt_executable_t *executable, 
                                htt_stack_t *retvars); 

/**
 * Get stack of parameter variables
 * @param executable IN
 * @return stack of parameters 
 */
htt_stack_t *htt_executable_get_params(htt_executable_t *executable); 

/**
 * Get stack of return variables
 * @param executable IN
 * @return stack of return variables 
 */
htt_stack_t *htt_executable_get_retvars(htt_executable_t *executable); 


/**
 * Set raw
 * @param executable IN
 * @param raw IN
 */
void htt_executable_set_raw(htt_executable_t *executable, char *raw);

/**
 * Get parent of this executable
 * @param executable IN
 * @return parent
 */
htt_executable_t *htt_executable_get_parent(htt_executable_t *executable);

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
 * Get name 
 * @param exeuctabl IN executable
 * @return name 
 */
const char *htt_executable_get_name(htt_executable_t *executable);

/**
 * Get signatur
 * @param exeuctabl IN executable
 * @return signature
 */
const char *htt_executable_get_signature(htt_executable_t *executable); 

/**
 * Get body 
 * @param exeuctabl IN executable
 * @return table of executables
 */
apr_table_t *htt_executable_get_body(htt_executable_t *executable);

/**
 * Set a named configuration
 * @param context IN context
 * @param name IN name for stored data
 * @param data IN data to store
 */
void htt_executable_set_config(htt_executable_t *executable, const char *name, 
                               void *data);

/**
 * Get named configuraion
 * @param context IN context
 * @param name IN name for data
 * @return data
 */
void  *htt_executable_get_config(htt_executable_t *executable, 
                                 const char *name);

/**
 * Set a command
 * @param context IN context
 * @param name IN name for stored data
 * @param data IN data to store
 */
void htt_executable_set_command(htt_executable_t *executable, const char *name, 
                                void *data);

/**
 * Get command
 * @param context IN context
 * @param name IN name for data
 * @return data
 */
void  *htt_executable_get_command(htt_executable_t *executable, 
                                  const char *name);

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

/**
 * Execute a single command
 * @param executable IN static context
 * @param context IN dynamic context
 * @param name IN command name
 * @param args IN arguments line
 * @param retvals INOUT stack of return variables
 * @param pool IN
 * @return apr status
 */
apr_status_t htt_execute_command(htt_executable_t *executable, 
                                 htt_context_t *context, const char *name, 
                                 const char *args, htt_stack_t **retvals, 
                                 apr_pool_t *pool); 

# define HTT_DECLARE(type)    type
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, begin,
                          (htt_executable_t *executable, 
                           htt_context_t *context));
APR_DECLARE_EXTERNAL_HOOK(htt, HTT, apr_status_t, final,
                          (htt_executable_t *executable, 
                           htt_context_t *context, apr_status_t status));
#endif
