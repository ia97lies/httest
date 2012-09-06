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
 * Implementation of the HTTP Test Tool core module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_strings.h>
#include "htt_modules.h"
#include "htt_core.h"
#include "htt_string.h"
#include "htt_util.h"
#include "htt_expr.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct _request_config_s {
  apr_pool_t *pool;
  const char *var;
} _request_config_t;

/**
 * Simple echo command 
 * @param executable IN executable
 * @param context IN running context
 * @param ptmp IN pool
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @return apr status
 */
static apr_status_t _cmd_echo_function(htt_executable_t *executable, 
                                       htt_context_t *context,
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line);

/**
 * Set command 
 * @param executable IN executable
 * @param context IN running context
 * @param ptmp IN pool
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @return apr status
 */
static apr_status_t _cmd_set_function(htt_executable_t *executable, 
                                      htt_context_t *context,
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line); 
/**
 * Local command 
 * @param executable IN executable
 * @param context IN running context
 * @param ptmp IN pool
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @return apr status
 */
static apr_status_t _cmd_local_function(htt_executable_t *executable, 
                                        htt_context_t *context, 
                                        apr_pool_t *ptmp, htt_map_t *params, 
                                        htt_stack_t *retvars, char *line); 

/**
 * Eval math expressions
 * @param executable IN executable
 * @param context IN running context
 * @param ptmp IN pool
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @return apr status
 */
static apr_status_t _cmd_expr_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line); 

/**
 * Exit
 * @param executable IN executable
 * @param context IN running context
 * @param ptmp IN pool
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @return apr status
 */
static apr_status_t _cmd_exit_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line); 

/**
 * Assert
 * @param executable IN executable
 * @param context IN running context
 * @param ptmp IN pool
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @return apr status
 */
static apr_status_t _cmd_assert_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * Core req functionality
 * @param executable IN executable
 * @param context IN running context
 * @param line IN unsplitted but resolved line
 * return apr status
 */
static apr_status_t _hook_request(htt_executable_t *executable, 
                                  htt_context_t *context, char *line);

/**
 * Core wait functionality
 * @param executable IN executable
 * @param context IN running context
 * @param line IN unsplitted but resolved line
 * return apr status
 */
static apr_status_t _hook_wait(htt_executable_t *executable, 
                               htt_context_t *context, char *line);

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t core_module_init(htt_t *htt) {
  htt_add_command(htt, "echo", NULL, "<string>", "echo a string", 
                  htt_cmd_line_compile, _cmd_echo_function);
  htt_add_command(htt, "set", NULL, "<name>=<value>", "set variable <name> to <value>", 
                  htt_cmd_line_compile, _cmd_set_function);
  htt_add_command(htt, "local", NULL, "<variable>+", "define variable local", 
                  htt_cmd_line_compile, _cmd_local_function);
  htt_add_command(htt, "expr", "expression : result", "<expression> <variable>", 
                  "Evaluate <expression> and store it in <variable>",
                  htt_cmd_line_compile, _cmd_expr_function);
  htt_add_command(htt, "exit", NULL, "", 
                  "terminate script either with success, failed or skipped",
                  htt_cmd_line_compile, _cmd_exit_function);
  htt_add_command(htt, "assert", NULL, "0|1 use $expr(\"<expression>\")", 
                  "assert throw exception if 0",
                  htt_cmd_line_compile, _cmd_assert_function);
  htt_hook_request(_hook_request, NULL, NULL, 0);
  htt_hook_request(_hook_wait, NULL, NULL, 0);
  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/
static apr_status_t _cmd_echo_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  htt_log(htt_context_get_log(context), HTT_LOG_NONE, "%s", line);
  return APR_SUCCESS;
}

static apr_status_t _cmd_set_function(htt_executable_t *executable, 
                                      htt_context_t *context, 
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line) {
  char *key;
  char *val;
  char *rest;
  htt_context_t *cur = context;
  htt_string_t *string;
 
  key = apr_strtok(line, "=", &val);
  while (*val == ' ') ++val;
  val = htt_util_unescape(val, &rest);
  apr_collapse_spaces(key, key);
  string = htt_string_new(htt_context_get_pool(cur), val);
  htt_context_set_var(context, key, string);
  return APR_SUCCESS;
}

static apr_status_t _cmd_local_function(htt_executable_t *executable, 
                                        htt_context_t *context, 
                                        apr_pool_t *ptmp, htt_map_t *params, 
                                        htt_stack_t *retvars, char *line) {
  char *var;
  char *rest;
  htt_map_t *vars;

  vars = htt_context_get_vars(context);
  var = apr_strtok(line, " ", &rest);
  while (var) {
    htt_string_t *string = htt_string_new(htt_context_get_pool(context), NULL);
    htt_map_set(vars, var, string);
    var = apr_strtok(NULL, " ", &rest);
  }
  return APR_SUCCESS;
}

static apr_status_t _cmd_expr_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  long result;
  htt_string_t *string;
  htt_string_t *expression;
  apr_status_t status;
  htt_expr_t *expr = htt_expr_new(ptmp);
  expression = htt_map_get(params, "expression");
  if ((status = htt_expr(expr, htt_string_get(expression), &result)) 
      == APR_SUCCESS) {
    string = htt_string_new(ptmp, apr_psprintf(ptmp, "%ld", result));
    htt_stack_push(retvars, string);
  }
  htt_expr_free(expr);
  return status;
} 

static apr_status_t _cmd_exit_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  apr_collapse_spaces(line, line);
  if (strcmp(line, "fail") == 0) {
    htt_throw_error();
  }
  else if (strcmp(line, "ok") == 0) {
    htt_throw_ok();
  }
  else if (strcmp(line, "skip") == 0) {
    htt_throw_skip();
  }
  else {
    htt_throw_error();
  }
  return APR_SUCCESS;
} 

static apr_status_t _cmd_assert_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  apr_collapse_spaces(line, line);
  if (strcmp(line, "1") != 0) {
    return APR_EINVAL;
  }
  return APR_SUCCESS;
} 

static _request_config_t *_create_request_config(htt_context_t *context) {
  _request_config_t *varconf;
  varconf = apr_pcalloc(htt_context_get_pool(context), sizeof(*varconf));
  htt_context_set_config(context, "core_module_request", varconf); 
  return varconf;
}

static void _destroy_request_config(htt_context_t *context) {
  htt_context_set_config(context, "core_module_request", NULL); 
}

static _request_config_t *_get_request_config(htt_context_t *context) {
  return htt_context_get_config(context, "core_module_request"); 
}

static apr_status_t _hook_request(htt_executable_t *executable, 
                                  htt_context_t *context, char *line) {
  if (strncmp(line, "var://", 6) == 0) {
    _request_config_t *config = _create_request_config(context);
    char *var = &line[6];
    apr_collapse_spaces(var, var);
    apr_pool_create(&config->pool, htt_context_get_pool(context));
    config->var = apr_pstrdup(config->pool, var);
  }
  return APR_SUCCESS;
}

static apr_status_t _hook_wait(htt_executable_t *executable, 
                               htt_context_t *context, char *line) {
  _request_config_t *config;
  config = _get_request_config(context);
  if (config) {
    htt_string_t *value = htt_context_get_var(context, config->var);
    htt_core_expect(context, ".", htt_string_get(value), -1);
    apr_pool_destroy(config->pool);
    _destroy_request_config(context); 
  }
  return APR_SUCCESS;
}
