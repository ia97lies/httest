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
 * Implementation of the HTTP Test Tool exception module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_strings.h>
#include "htt_modules.h"
#include "htt_defines.h"
#include "htt_core.h"
#include "htt_string.h"
#include "htt_util.h"
#include "htt_expr.h"
#include "htt_function.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
/**
 * Compile finally statement
 * @param command IN command data
 * @param args IN 
 * @return apr status
 */
static apr_status_t _cmd_finally_compile(htt_command_t *command, char *args); 

/** 
 * finally block
 * @param executable IN static context
 * @param context IN dynamic context
 * @param ptmp IN temporary pool
 * @param params IN unused
 * @param retvars IN return closure
 * @param line IN raw line
 * @return apr status
 */
static apr_status_t _cmd_finally_function(htt_executable_t *executable, 
                                          htt_context_t *context, 
                                          apr_pool_t *ptmp, htt_map_t *params, 
                                          htt_stack_t *retvars, char *line); 

/**
 * Call finally block if any
 * @param executable IN static context
 * @param context IN dynamic context
 */
static apr_status_t _hook_call_final(htt_executable_t *executable, 
                                     htt_context_t *context,
                                     apr_status_t status); 
/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t exception_module_init(htt_t *htt) {
  htt_hook_final(_hook_call_final, NULL, NULL, 0);
  return APR_SUCCESS;
}

apr_status_t exception_module_register(htt_t *htt) {
  htt_add_command(htt, "finally", NULL, "", 
                  "run finally in a block even on error", 
                  _cmd_finally_compile, _cmd_finally_function);
  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/

static apr_status_t _hook_call_final(htt_executable_t *executable, 
                                     htt_context_t *context, 
                                     apr_status_t status) {
  htt_executable_t *finally;
  finally = htt_executable_get_config(executable, "__finally");
  if (finally) {
    htt_execute(finally, context);
  }
  return APR_SUCCESS;
}

static apr_status_t _cmd_finally_compile(htt_command_t *command, char *args) {
  apr_status_t status;
  htt_t *htt = htt_command_get_config(command, "htt");
  htt_executable_t *parent = htt_get_executable(htt);

  status = htt_cmd_body_compile(command, args);
  if (status == APR_SUCCESS) {
    htt_executable_t *finally = htt_get_executable(htt);
    htt_executable_set_config(parent, "__finally", finally);
  }
  return status;
}

static apr_status_t _cmd_finally_function(htt_executable_t *executable, 
                                          htt_context_t *context, 
                                          apr_pool_t *ptmp, htt_map_t *params, 
                                          htt_stack_t *retvars, char *line) {
  htt_executable_t *finally_executable;
  htt_context_t *finally_context;
  htt_function_t *finally_closure;

  finally_executable = htt_executable_new(htt_context_get_pool(context), 
                                          executable, "_finally_closure", NULL,
                                          htt_null_closure, NULL, 
                                          htt_executable_get_file(executable), 
                                          htt_executable_get_line(executable));
  finally_context= htt_context_new(context, htt_context_get_log(context));
  finally_closure = htt_function_new(htt_context_get_pool(finally_context), 
                                    finally_executable, finally_context);
  /* this must return a closure */
  htt_stack_push(retvars, finally_closure);
  return APR_SUCCESS;
}

