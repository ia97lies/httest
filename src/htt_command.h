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
 * Interface of the HTTP Test Tool string.
 */

#ifndef HTT_COMMAND_H
#define HTT_COMMAND_H

#include <apr_pools.h>
#include "htt_executable.h"
#include "htt_context.h"

typedef struct htt_command_s htt_command_t;

typedef apr_status_t(*htt_compile_f)(htt_command_t *command, char *params);

/**
 * Create a command
 * @param pool IN parent pool for inheritance
 * @param name IN command name
 * @param signature IN command signature
 * @param short_desc IN short description
 * @param desc IN description
 * @param compile IN compile function, most often htt_line_compile
 * @param function IN commands runtime function
 * @return command
 */
htt_command_t *htt_command_new(apr_pool_t *pool,  const char *name, 
                               const char *signature, const char *short_desc, 
                               const char *desc, htt_compile_f compile, 
                               htt_function_f function); 
/**
 * Set an own configuration pointer
 * @param command IN 
 * @param name IN name of configuration should be uniq
 * @param data IN data pointer
 */
void htt_command_set_config(htt_command_t *command, const char *name, 
                            void *data); 

/**
 * Get an own configuration pointer
 * @param command IN 
 * @param name IN name of configuration should be uniq
 * @return data pointer
 */
void *htt_command_get_config(htt_command_t *command, const char *name); 

/**
 * Get name
 * @param command IN 
 * @return name
 */
const char *htt_command_get_name(htt_command_t *command); 

/**
 * Get signature
 * @param command IN 
 * @return signature
 */
const char *htt_command_get_signature(htt_command_t *command); 

/**
 * Get short description
 * @param command IN 
 * @return short description
 */
const char *htt_command_get_short_desc(htt_command_t *command); 

/**
 * Get description
 * @param command IN 
 * @return full description
 */
const char *htt_command_get_desc(htt_command_t *command); 

/**
 * Get function
 * @param command IN
 * @return function
 */
htt_function_f htt_command_get_function(htt_command_t *command); 

/**
 * Get defined parameters (signature)
 * @param command IN
 * @return stack of parameters
 */
htt_stack_t *htt_command_get_params(htt_command_t *command); 

/**
 * Get defined return variables (signature)
 * @param command IN
 * @return stack of return variables
 */
htt_stack_t *htt_command_get_retvars(htt_command_t *command); 

/**
 * Compiles given command
 * @param command IN
 * @param args IN args
 * @return apr status
 */
apr_status_t htt_command_compile(htt_command_t *command, char *args);

#endif
