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
#include "htt_function.h"
#include "htt_string.h"

/************************************************************************
 * Defines 
 ***********************************************************************/

/************************************************************************
 * Structurs
 ***********************************************************************/
struct htt_command_s {
  const char *name;
  const char *signature;
  const char *short_desc;
  const char *desc;
  void *user_data;
  htt_compile_f compile;
  htt_function_f function;
};

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
 * Interpret reading from given bufreader 
 * @param htt IN instance
 * @param fp IN apr file pointer
 * @return apr status
 */
static apr_status_t _compile(htt_t *htt, htt_bufreader_t *bufreader); 

/**
 * Compile function for include. Just open file and and interpret.
 * @param command IN command
 * @param htt IN instance
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_include_compile(htt_command_t *command, htt_t *htt,
                                         char *args); 

/**
 * Get last body from stack
 * @param command IN command
 * @param htt IN instance
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_end_compile(htt_command_t *command, htt_t *htt,
                                     char *args); 

/**
 * Compile function 
 * @param command IN command
 * @param htt IN instance
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_function_compile(htt_command_t *command, htt_t *htt, 
                                          char *args); 
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
 * function command
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

/************************************************************************
 * Globals 
 ***********************************************************************/
int htt_error = 0;

/************************************************************************
 * Public 
 ***********************************************************************/
apr_status_t htt_cmd_line_compile(htt_command_t *command, htt_t *htt, 
                                  char *args) {
  htt_executable_t *executable;

  executable = htt_executable_new(htt->pool, command->name, command->signature,
                                  command->function, args, htt->cur_file, 
                                  htt->cur_line);
  htt_executable_add(htt->executable, executable);
  return APR_SUCCESS;
}

apr_status_t htt_cmd_body_compile(htt_command_t *command, htt_t *htt, 
                                  char *args) {
  htt_executable_t *executable;

  executable = htt_executable_new(htt->pool, command->name, command->signature, 
                                  command->function, args, htt->cur_file, 
                                  htt->cur_line);
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
  htt->executable = htt_executable_new(pool, apr_pstrdup(pool, "global"), NULL,
                                       NULL, NULL, NULL, 0);
  htt_stack_push(htt->stack, htt->executable);

  htt_add_command(htt, "include", "NULL", "<file>+", "include ht3 files", 
                  _cmd_include_compile, NULL);
  htt_add_command(htt, "end", NULL, "", "end a open body", 
                  _cmd_end_compile, NULL);
  htt_add_command(htt, "body", NULL, "", "open a new body",
                  htt_cmd_body_compile, NULL);
  htt_add_command(htt, "function", NULL, "<parameter>*", "define a function",
                  _cmd_function_compile, _cmd_function_function);
  htt_add_command(htt, "echo", NULL, "<string>", "echo a string", 
                  htt_cmd_line_compile, _cmd_echo_function);
  htt_add_command(htt, "set", NULL, "<name>=<value>", "set variable <name> to <value>", 
                  htt_cmd_line_compile, _cmd_set_function);
  htt_add_command(htt, "local", NULL, "<variable>+", "define variable local", 
                  htt_cmd_line_compile, _cmd_local_function);
  htt_add_command(htt, "loop", NULL, "", "open a new body",
                  htt_cmd_body_compile, _cmd_loop_function);
  return htt;
}

void htt_set_log(htt_t *htt, apr_file_t *std, apr_file_t *err, int mode) {
  htt->log = htt_log_new(htt->pool, std, err);
  htt_log_set_mode(htt->log, mode);
}

void htt_add_value(htt_t *htt, const char *key, const char *val) {
  htt_string_t *string = htt_string_new(htt->pool, val);
  htt_map_set(htt->defines, key, string, htt_string_free);
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
  htt_command_t *command = apr_pcalloc(htt->pool, sizeof(*command));
  command->name = name;
  command->signature = signature;
  command->short_desc = short_desc;
  command->desc = desc;
  command->compile = compile;
  command->function = function;
  htt_executable_set_config(htt->executable, name, command);
}

htt_command_t *htt_get_command(htt_t *htt, const char *cmd) {
  htt_command_t *command;
  htt_executable_t *top = htt->executable;
  int i = 1;

  command = htt_executable_get_config(top, cmd);
  top = htt_stack_index(htt->stack, i);
  while (top && !command) {
    command = htt_executable_get_config(top, cmd);
    top = htt_stack_index(htt->stack, ++i);
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
      command = htt_get_command(htt, cmd);
      if (!command) {
        htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                      "Unknown command \"%s\"", cmd);
        htt_throw_error();
      }
      else {
        const char *old_file_name = htt->cur_file;
        int old_line = htt->cur_line;
        status = command->compile(command, htt, rest);
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

static apr_status_t _cmd_include_compile(htt_command_t *command, htt_t *htt,
                                         char *args) {
  apr_file_t *fp;
  apr_status_t status;

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

static apr_status_t _cmd_end_compile(htt_command_t *command, htt_t *htt,
                                     char *args) {
  htt_stack_pop(htt->stack);
  htt->executable = htt_stack_top(htt->stack);
  /* TODO: test if this a function and register */
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

static apr_status_t _cmd_function_compile(htt_command_t *command, htt_t *htt, 
                                          char *args) {
  htt_executable_t *executable;
  char *name;
  char *signature;
  char *line = apr_pstrdup(htt->pool, args);

  name = apr_strtok(line, " ", &signature);
  if (name) apr_collapse_spaces(name, name);
  while (signature && *signature == ' ') ++signature;
  fprintf(stderr, "XXX: %s %s\n", name, signature);

  executable = htt_executable_new(htt->pool, command->name, command->signature, 
                                  command->function, args, htt->cur_file, 
                                  htt->cur_line);
  htt_stack_push(htt->stack, executable);
  htt->executable = executable;

  return APR_SUCCESS;
}

static apr_status_t _cmd_function_function(htt_executable_t *executable, 
                                           htt_context_t *context, 
                                           apr_pool_t *ptmp, htt_map_t *params, 
                                           htt_stack_t *retvars, char *line) {
  if (params) htt_context_merge_vars(context, params);
  return htt_execute(executable, context);
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
  htt_map_t *vars;
  htt_context_t *cur = context;
  htt_string_t *string;
 
  key = apr_strtok(line, "=", &val);
  while (*val == ' ') ++val;
  apr_collapse_spaces(key, key);
  vars = htt_context_get_vars(cur);
  while (cur && !htt_map_get(vars, key)) {
    cur = htt_context_get_parent(cur);
    if (cur) {
      vars = htt_context_get_vars(cur);
    }
  } 
  if (!cur) {
    cur = htt_context_get_godfather(context);
  }
  if (!vars) {
    vars = htt_context_get_vars(cur);
  }
  string = htt_string_new(htt_context_get_pool(cur), val);
  htt_map_set(vars, key, string, htt_string_free);
  return APR_SUCCESS;
}

static apr_status_t _cmd_local_function(htt_executable_t *executable, 
                                        htt_context_t *context, 
                                        apr_pool_t *ptmp, htt_map_t *params, 
                                        htt_stack_t *retvars, char *line) {
  char *var;
  char *rest;
  htt_map_t *vars;

  htt_string_t *string = htt_string_new(htt_context_get_pool(context), "");
  vars = htt_context_get_vars(context);
  var = apr_strtok(line, " ", &rest);
  while (var) {
    htt_map_set(vars, var, string, htt_string_free);
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
                                       "_loop_closure", NULL, _loop_closure, 
                                       NULL, 
                                       htt_executable_get_file(executable), 
                                       htt_executable_get_line(executable));
  loop_context= htt_context_new(context, htt_context_get_log(context));
  loop_vars = htt_context_get_vars(loop_context);
  count_str = htt_string_new(htt_context_get_pool(loop_context), count);
  htt_map_set(loop_vars, "count", count_str, htt_string_free);

  loop_closure = htt_function_new(htt_context_get_pool(loop_context), 
                                  loop_executable, loop_context);
  /* this must return a closure */
  htt_stack_push(retvars, loop_closure);
  return APR_SUCCESS;
}

