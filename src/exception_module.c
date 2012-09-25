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
 * thread closure
 * @param executable IN static context
 * @param context IN dynamic context
 * @param ptmp IN temporyry pool
 * @param params IN unused
 * @param retvars IN push 0 on stack
 * @param line IN unused
 * @return 0 mean the body is run as thread do not run it outside again
 */
static apr_status_t _finally_closure(htt_executable_t *executable, 
                                     htt_context_t *context, apr_pool_t *ptmp, 
                                     htt_map_t *params, htt_stack_t *retvars, 
                                     char *line);

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t exception_module_init(htt_t *htt) {
  htt_add_command(htt, "finally", NULL, "", 
                  "run finally in a block even on error", 
                  _cmd_finally_compile, _cmd_finally_function);
  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/

static apr_status_t _cmd_finally_compile(htt_command_t *command, char *args) {
  /* htt_t *htt = htt_command_get_config(command, "htt");
   */
  /* TODO: register finally to current executable and call it at end or
   *       termination. Need a secure point where all exits will pass
   *       through!
   */
  return htt_cmd_body_compile(command, args);
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
                                          _finally_closure, NULL, 
                                          htt_executable_get_file(executable), 
                                          htt_executable_get_line(executable));
  finally_context= htt_context_new(context, htt_context_get_log(context));
  finally_closure = htt_function_new(htt_context_get_pool(finally_context), 
                                    finally_executable, finally_context);
  /* this must return a closure */
  htt_stack_push(retvars, finally_closure);
  return APR_SUCCESS;
}

static apr_status_t _finally_closure(htt_executable_t *executable, 
                                     htt_context_t *context, apr_pool_t *ptmp, 
                                     htt_map_t *params, htt_stack_t *retvars, 
                                     char *line) {
  htt_string_t *retval = htt_string_new(ptmp, apr_pstrdup(ptmp, "0"));
  htt_stack_push(retvars, retval);
  return APR_SUCCESS;
}

