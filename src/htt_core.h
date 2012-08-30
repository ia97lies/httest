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
 * Interface of the htt log.
 */

#ifndef HTT_CORE_H
#define HTT_CORE_H

#include <apr_file_io.h>
#include "htt_context.h"
#include "htt_executable.h"
#include "htt_command.h"

typedef struct htt_s htt_t;
typedef struct htt_command_s htt_command_t; 

/**
 * Instanted a new interpreter
 * @param pool IN
 * @return new interpreter instance
 */
htt_t *htt_new(apr_pool_t *pool);

/**
 * Set log file handles
 * @param htt IN instance
 * @param std IN standard out
 * @param err IN error out
 * @param mode IN log mode
 */
void htt_set_log(htt_t *htt, apr_file_t *std, apr_file_t *err, int mode);

/**
 * Set values to pass to interpreter
 * @param htt IN instance
 * @param key IN key
 * @param val IN value
 */
void htt_add_value(htt_t *htt, const char *key, const char *val);

/**
 * Store current file name
 * @param htt IN instance
 * @param name IN filename
 */
void htt_set_cur_file_name(htt_t *htt, const char *name);

/**
 * Store current file name
 * @param htt IN instance
 * @param name IN filename
 */
const char *htt_get_cur_file_name(htt_t *htt);

/**
 * Compiles a simple command 
 * @param command IN command instance
 * @param args IN commands arguments
 * @param APR_SUCCESS on successfull compilation
 */
apr_status_t htt_cmd_line_compile(htt_command_t *command, char *args);

/**
 * Compiles a command with a body (if, loop, ...)
 * @param command IN command instance
 * @param args IN commands arguments
 * @param APR_SUCCESS on successfull compilation
 */
apr_status_t htt_cmd_body_compile(htt_command_t *command, char *args);

/**
 * Add command
 * @param htt IN instance
 * @param name IN command name
 * @param type IN none | body
 * @param function IN function called by interpreter
 */
void htt_add_command(htt_t *htt, const char *name, const char *signature, 
                     const char *short_desc, const char *desc,
                     htt_compile_f compile, htt_function_f function);

/**
 * Get registered command
 * TODO: Refactor, command should be in its own file, but difficult
 * @param executable IN 
 * @param cmd IN command name
 * @return found command or NULL
 */
htt_command_t *htt_get_command(htt_executable_t *executable, const char *cmd); 

/**
 * Get function of command
 * @param command IN command
 * @return function
 */
htt_function_f htt_get_command_function(htt_command_t *command); 

/**
 * Get signature of command
 * @param command IN command
 * @return signature
 */
const char *htt_get_command_signature(htt_command_t *command); 

/**
 * Interpret reading from given apr_file_t 
 * @param htt IN instance
 * @param fp IN apr file pointer
 * @return apr status
 */
apr_status_t htt_compile_fp(htt_t *htt, apr_file_t *fp);

/**
 * Interpret reading from a buffer
 * @param htt IN instance
 * @param buf IN buffer to read from
 * @param len IN buffer length
 * @return apr status
 */
apr_status_t htt_compile_buf(htt_t *htt, const char *buf, apr_size_t len);

/**
 * Run a compiled script
 * @param htt IN
 * @return apr status
 */
apr_status_t htt_run(htt_t *htt);

/**
 * verbose exit func
 */
void htt_exit();

/**
 * silent exit func
 */
void htt_no_output_exit();

/**
 * Throw error exception, terminate 
 */
void htt_throw_error();

/**
 * Throw skip exception, terminate
 */
void htt_throw_skip();

/**
 * Throw ok exception, terminate
 */
void htt_throw_ok(); 

 #endif
