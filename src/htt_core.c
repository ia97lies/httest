/**
 * Copyright 2006 Christian Liesch
 *
 * fooLicensed under the Apache License, Version 2.0 (the "License");
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
 * Implementation of the HTTP Test Tool.
 */

/* affects include files on Solaris */
#define BSD_COMP

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include "defines.h"

#include <apr.h>
#include <apr_signal.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_file_io.h>
#include <apr_time.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_support.h>
#include <apr_hash.h>
#include <apr_base64.h>
#include <apr_env.h>
#include <apr_hooks.h>

#include <pcre.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "htt_bufreader.h"
#include "htt_util.h"
#include "htt_core.h"
#include "htt_log.h"
#include "htt_map.h"
#include "htt_stack.h"
#include "htt_executable.h"
#include "htt_context.h"
#include "htt_object.h"
#include "htt_function.h"
#include "htt_string.h"
#include "htt_eval.h"
#include "htt_command.h"

/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Structurs
 ***********************************************************************/
struct htt_s {
  apr_pool_t *pool;
  htt_map_t *defines;
  htt_log_t *log;
  const char *cur_file;
  int cur_line;
  htt_stack_t *stack;
  htt_executable_t *executable;
  apr_hash_t *config;
};

typedef struct _loop_config_s {
  int i;
} _loop_config_t;

/**
 * Get return vals with given signature
 * @param context IN 
 * @param retvars IN stack of return variables
 * @param retvals INOUT fill return values in this stack
 * @param pool IN
 */
static void _get_retvals(htt_context_t *context, htt_stack_t *retvars,
                         htt_stack_t *retvals, apr_pool_t *pool); 
/**
 * Interpret reading from given bufreader 
 * @param htt IN instance
 * @param fp IN apr file pointer
 * @return apr status
 */
static apr_status_t _compile(htt_t *htt, htt_bufreader_t *bufreader); 

/**
 * Compile function for include. Just open file and and interpret.
 * @param command IN command
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_include_compile(htt_command_t *command, char *args); 

/**
 * Get last body from stack
 * @param command IN command
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_end_compile(htt_command_t *command, char *args); 

/**
 * Define a new function and register it
 * @param command IN command
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_func_def_compile(htt_command_t *command, char *args);

/**
 * Add defined function 
 * @param command IN command
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_function_compile(htt_command_t *command, char *args); 
/**
 * Simple echo command 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_echo_function(htt_executable_t *executable, 
                                       htt_context_t *context,
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line);

/**
 * Set command 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_set_function(htt_executable_t *executable, 
                                      htt_context_t *context,
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line); 
/**
 * Local command 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_local_function(htt_executable_t *executable, 
                                        htt_context_t *context, 
                                        apr_pool_t *ptmp, htt_map_t *params, 
                                        htt_stack_t *retvars, char *line); 

/**
 * Loop command
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_loop_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line);

/**
 * Function command
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_function_function(htt_executable_t *executable, 
                                           htt_context_t *context, 
                                           apr_pool_t *ptmp, htt_map_t *params, 
                                           htt_stack_t *retvars, char *line); 

/**
 * Eval math expressions
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_eval_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line); 

/************************************************************************
 * Globals 
 ***********************************************************************/
int htt_error = 0;

/************************************************************************
 * Public 
 ***********************************************************************/
apr_status_t htt_cmd_line_compile(htt_command_t *command, char *args) {
  htt_executable_t *executable;
  htt_t *htt = htt_command_get_config(command, "htt");

  executable = htt_executable_new(htt->pool, htt->executable, 
                                  htt_command_get_name(command), 
                                  htt_command_get_signature(command), 
                                  htt_command_get_function(command), args, 
                                  htt->cur_file, htt->cur_line);
  htt_executable_set_params(executable, htt_command_get_params(command));
  htt_executable_set_retvars(executable, htt_command_get_retvars(command));
  htt_executable_add(htt->executable, executable);
  return APR_SUCCESS;
}

apr_status_t htt_cmd_body_compile(htt_command_t *command, char *args) {
  htt_executable_t *executable;
  htt_t *htt = htt_command_get_config(command, "htt");

  executable = htt_executable_new(htt->pool, htt->executable, 
                                  htt_command_get_name(command), 
                                  htt_command_get_signature(command), 
                                  htt_command_get_function(command), args, 
                                  htt->cur_file, htt->cur_line);
  htt_executable_set_params(executable, htt_command_get_params(command));
  htt_executable_set_retvars(executable, htt_command_get_retvars(command));
  htt_executable_add(htt->executable, executable);
  htt_stack_push(htt->stack, executable);
  htt->executable = executable;
  return APR_SUCCESS;
}

void htt_exit() {
  if (htt_error == 0) {
    fprintf(stdout, " OK\n");
    fflush(stdout);
  }
  else if (htt_error == 1) {
    fprintf(stderr, " FAILED\n");
    fflush(stderr);
  }
  else if (htt_error == 2) {
    fprintf(stdout, " SKIPPED\n");
    fflush(stdout);
  }
}

void htt_no_output_exit() {
}

void htt_throw_error() {
  htt_error = 1;
  exit(1);
}

void htt_throw_skip() {
  htt_error = 1;
  exit(1);
}

htt_t *htt_new(apr_pool_t *pool) {
  htt_t *htt = apr_pcalloc(pool, sizeof(*htt));
  htt->pool = pool;
  htt->defines = htt_map_new(pool);
  htt->stack = htt_stack_new(pool);
  htt->executable = htt_executable_new(pool, NULL, apr_pstrdup(pool, "global"), NULL,
                                       NULL, NULL, NULL, 0);
  htt_stack_push(htt->stack, htt->executable);

  htt_add_command(htt, "include", "NULL", "<file>+", "include ht3 files", 
                  _cmd_include_compile, NULL);
  htt_add_command(htt, "end", NULL, "", "end a open body", 
                  _cmd_end_compile, NULL);
  htt_add_command(htt, "body", NULL, "", "open a new body",
                  htt_cmd_body_compile, NULL);
  htt_add_command(htt, "function", NULL, "<parameter>*", "define a function",
                  _cmd_func_def_compile, NULL);
  htt_add_command(htt, "echo", NULL, "<string>", "echo a string", 
                  htt_cmd_line_compile, _cmd_echo_function);
  htt_add_command(htt, "set", NULL, "<name>=<value>", "set variable <name> to <value>", 
                  htt_cmd_line_compile, _cmd_set_function);
  htt_add_command(htt, "local", NULL, "<variable>+", "define variable local", 
                  htt_cmd_line_compile, _cmd_local_function);
  htt_add_command(htt, "loop", NULL, "", "open a new body",
                  htt_cmd_body_compile, _cmd_loop_function);
  htt_add_command(htt, "eval", "expression : result", "<expression> <result>", 
                  "Evaluate <expression> and store it in <result>",
                  htt_cmd_line_compile, _cmd_eval_function);
  return htt;
}

void htt_set_log(htt_t *htt, apr_file_t *std, apr_file_t *err, int mode) {
  htt->log = htt_log_new(htt->pool, std, err);
  htt_log_set_mode(htt->log, mode);
}

void htt_add_value(htt_t *htt, const char *key, const char *val) {
  htt_string_t *string = htt_string_new(htt->pool, val);
  htt_map_set(htt->defines, key, string);
}

void htt_set_cur_file_name(htt_t *htt, const char *name) {
  htt->cur_file = name;
}

const char *htt_get_cur_file_name(htt_t *htt) {
  return htt->cur_file;
}

void htt_add_command(htt_t *htt, const char *name, const char *signature, 
                     const char *short_desc, const char *desc,
                     htt_compile_f compile, htt_function_f function) {
  htt_command_t *command;
  command = htt_command_new(htt->pool, name, signature, short_desc, desc,
                            compile, function);
  htt_command_set_config(command, "htt", htt);
  htt_executable_set_config(htt->executable, name, command);
}

htt_command_t *htt_get_command(htt_executable_t *executable, const char *cmd) {
  htt_command_t *command = NULL;
  htt_executable_t *cur = executable;

  command = htt_executable_get_config(cur, cmd);
  while (cur && !command) {
    command = htt_executable_get_config(cur, cmd);
    cur = htt_executable_get_parent(cur);
  }
  return command;
}

apr_status_t htt_compile_buf(htt_t *htt, const char *buf, apr_size_t len) {
  htt_bufreader_t *bufreader = htt_bufreader_buf_new(htt->pool, buf, len);
  return _compile(htt, bufreader);
}

apr_status_t htt_compile_fp(htt_t *htt, apr_file_t *fp) {
  htt_bufreader_t *bufreader = htt_bufreader_file_new(htt->pool, fp);
  return _compile(htt, bufreader);
}

apr_status_t htt_run(htt_t *htt) {
  htt_context_t *context = htt_context_new(NULL, htt->log);
  htt_context_set_vars(context, htt->defines);
  return htt_execute(htt->executable, context);
}

/************************************************************************
 * Private 
 ***********************************************************************/
static apr_status_t _compile(htt_t *htt, htt_bufreader_t *bufreader) {
  char *line;
  apr_status_t status = APR_SUCCESS;
  htt->cur_line = 1;

  while (status == APR_SUCCESS) { 
    status = htt_bufreader_read_line(bufreader, &line);
    for (; *line == ' ' || *line == '\t'; ++line);
    if (*line != '#' && *line != '\0') {
      char *rest;
      char *cmd;
      htt_command_t *command;

      cmd = apr_strtok(line, " ", &rest);
      htt_log(htt->log, HTT_LOG_DEBUG, "%s:%d -> %s[%s]", htt->cur_file, 
              htt->cur_line, cmd, rest);
      command = htt_get_command(htt->executable, cmd);
      if (!command) {
        htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                      "Unknown command \"%s\"", cmd);
        htt_throw_error();
      }
      else {
        const char *old_file_name = htt->cur_file;
        int old_line = htt->cur_line;
        status = htt_command_compile(command, rest);
        htt->cur_file =  old_file_name;
        htt->cur_line = old_line;
      }
    }
    ++htt->cur_line;
  }

  if (htt_stack_elems(htt->stack) != 1) {
    htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                  "Unclosed body on line %s:%d", 
                  htt_executable_get_file(htt->executable), 
                  htt_executable_get_line(htt->executable));
    htt_throw_error();
  }
  return APR_SUCCESS;
}

static apr_status_t _cmd_include_compile(htt_command_t *command, char *args) {
  apr_file_t *fp;
  apr_status_t status;
  htt_t *htt = htt_command_get_config(command, "htt");

  apr_collapse_spaces(args, args);
  if ((status = apr_file_open(&fp, args, APR_READ, APR_OS_DEFAULT, htt->pool)) 
      != APR_SUCCESS) {
    htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                  "Could not open include file \"%s\"", args);
    htt_throw_error();
  }
  htt_set_cur_file_name(htt, args);
  return htt_compile_fp(htt, fp);
}

static apr_status_t _cmd_end_compile(htt_command_t *command, char *args) {
  htt_t *htt = htt_command_get_config(command, "htt");
  htt_stack_pop(htt->stack);
  htt->executable = htt_stack_top(htt->stack);
  if (htt->executable && htt_stack_elems(htt->stack) >= 0) {
    return APR_SUCCESS;
  }
  else {
    apr_status_t status = APR_EINVAL;
    htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                  "Too many closing \"end\"");
    return status;
  }
}

static apr_status_t _cmd_func_def_compile(htt_command_t *command, char *args) {
  htt_t *htt = htt_command_get_config(command, "htt");
  htt_executable_t *executable;
  char *name;
  char *signature;
  char *line = apr_pstrdup(htt->pool, args);
  htt_command_t *new_command;

  name = apr_strtok(line, " ", &signature);
  apr_collapse_spaces(name, name);
  while (*signature == ' ') ++signature;
  new_command = htt_command_new(htt->pool, name, signature, NULL, NULL,
                                _cmd_function_compile, NULL);
  executable = htt_executable_new(htt->pool, htt->executable, name, signature, 
                                  NULL, signature, htt->cur_file, 
                                  htt->cur_line);
  htt_executable_set_params(executable, htt_command_get_params(new_command));
  htt_executable_set_retvars(executable, htt_command_get_retvars(new_command));
  htt_command_set_config(new_command, "htt", htt);
  htt_command_set_config(new_command, "executable", executable);
  htt_executable_set_config(htt->executable, name, new_command);
  htt_stack_push(htt->stack, executable);
  htt->executable = executable;
  return APR_SUCCESS;
}

static apr_status_t _cmd_function_compile(htt_command_t *command, char *args) {
  htt_t *htt = htt_command_get_config(command, "htt");
  htt_executable_t *executable;
  executable = htt_executable_new(htt->pool, htt->executable, 
                                  htt_command_get_name(command), 
                                  htt_command_get_signature(command), 
                                  _cmd_function_function, NULL, htt->cur_file,
                                  htt->cur_line);
  htt_executable_set_raw(executable, args);
  htt_executable_set_config(executable, "__executable", 
                            htt_command_get_config(command, "executable"));
  htt_executable_add(htt->executable, executable);
  return APR_SUCCESS;
}

static apr_status_t _cmd_function_function(htt_executable_t *executable, 
                                           htt_context_t *context, 
                                           apr_pool_t *ptmp, htt_map_t *params, 
                                           htt_stack_t *retvals, char *line) {
  apr_status_t status;
  htt_executable_t *_executable;
  htt_context_t *child_context;
  _executable = htt_executable_get_config(executable, "__executable");
  child_context= htt_context_new(context, htt_context_get_log(context));
  if (params) htt_context_merge_vars(child_context, params);
  status = htt_execute(_executable, child_context);
  _get_retvals(child_context, htt_executable_get_retvars(_executable), 
               retvals, ptmp);
  htt_context_destroy(child_context);
  return status;
}

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

static _loop_config_t *_loop_get_config(htt_context_t *context) {
  _loop_config_t *config;

  config = htt_context_get_config(context, "_loop_config");
  if (config == NULL) {
    config = apr_pcalloc(htt_context_get_pool(context), sizeof(*config));
    htt_context_set_config(context, 
                           apr_pstrdup(htt_context_get_pool(context), 
                                       "_loop_config"), config);
  }
  return config;
}

static apr_status_t _loop_closure(htt_executable_t *executable, 
                                  htt_context_t *context, apr_pool_t *ptmp, 
                                  htt_map_t *params, htt_stack_t *retvars, 
                                  char *line) {
  htt_string_t *retval;
  _loop_config_t *config;
  htt_string_t *count = htt_map_get(htt_context_get_vars(context), "count");
  if (htt_isa_string(count)) {
    config = _loop_get_config(context);
    ++config->i;
    if (config->i > apr_atoi64(htt_string_get(count))) {
      retval = htt_string_new(ptmp, apr_pstrdup(ptmp, "0"));
    }
    else {
      retval = htt_string_new(ptmp, apr_pstrdup(ptmp, "1"));
    }
    htt_stack_push(retvars, retval);
  }
  return APR_SUCCESS;
}

static apr_status_t _cmd_loop_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  htt_function_t *loop_closure;
  htt_context_t *loop_context;
  htt_executable_t *loop_executable;
  htt_map_t *loop_vars;
  htt_string_t *count_str;

  char *count;
  char *index;

  count = apr_strtok(line, " ", &index);

  if (!count || !count[0]) {
      htt_log(htt_context_get_log(context), HTT_LOG_ERROR, 
              "Expect a count");
    return APR_EGENERAL;
  }

  loop_executable = htt_executable_new(htt_context_get_pool(context), 
                                       executable, "_loop_closure", NULL,
                                       _loop_closure, NULL, 
                                       htt_executable_get_file(executable), 
                                       htt_executable_get_line(executable));
  loop_context= htt_context_new(context, htt_context_get_log(context));
  loop_vars = htt_context_get_vars(loop_context);
  count_str = htt_string_new(htt_context_get_pool(loop_context), count);
  htt_map_set(loop_vars, "count", count_str);

  loop_closure = htt_function_new(htt_context_get_pool(loop_context), 
                                  loop_executable, loop_context);
  /* this must return a closure */
  htt_stack_push(retvars, loop_closure);
  return APR_SUCCESS;
}

static apr_status_t _cmd_eval_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  long result;
  htt_string_t *string;
  htt_string_t *expression;
  apr_status_t status;
  htt_eval_t *eval = htt_eval_new(ptmp);
  expression = htt_map_get(params, "expression");
  if ((status = htt_eval(eval, htt_string_get(expression), &result)) 
      == APR_SUCCESS) {
    string = htt_string_new(ptmp, apr_psprintf(ptmp, "%ld", result));
    htt_stack_push(retvars, string);
  }
  htt_eval_free(eval);
  return status;
} 

static void _get_retvals(htt_context_t *context, htt_stack_t *retvars,
                         htt_stack_t *retvals, apr_pool_t *pool) {
  if (retvals && retvars) {
    int i;
    char *cur;
    
    for (i = 0; i < htt_stack_elems(retvars); i++) {
      cur = htt_stack_index(retvars, i);
      fprintf(stderr, "XXX %d :-> %s\n", i, cur);
      if (cur) {
        htt_object_t *val = htt_context_get_var(context, cur);
        if (val) {
          htt_stack_push(retvals, val->clone(val, pool));
        }
      }
    }
  }
}

