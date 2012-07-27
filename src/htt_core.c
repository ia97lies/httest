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

/* Use STACK from openssl to sort commands */
#include <openssl/ssl.h>

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
#include "htt_store.h"
#include "htt_stack.h"

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
  htt_compile_f compile;
  htt_function_f function;
};

typedef struct htt_compiled_s {
  const char *name;
  const char *file;
  int line;
  htt_function_f function;
  const char *args;
  apr_table_t *body;
} htt_compiled_t;

struct htt_s {
  apr_pool_t *pool;
  htt_store_t *defines;
  htt_log_t *log;
  const char *cur_file;
  int cur_line;
  apr_hash_t *commands;
  htt_stack_t *stack;
  htt_compiled_t *compiled;
};

/**
 * execute a compiled script 
 * @param htt IN instance
 * @param compiled IN compiled body
 * @param worker IN worker for this body
 * @return apr status
 */
static apr_status_t htt_execute(htt_t *htt, htt_compiled_t *compiled, 
                                htt_worker_t *worker); 

/**
 * Interpret reading from given bufreader 
 * @param htt IN instance
 * @param fp IN apr file pointer
 * @return apr status
 */
static apr_status_t htt_compile(htt_t *htt, htt_bufreader_t *bufreader); 

/**
 * Compile function for include. Just open file and and interpret.
 * @param command IN command
 * @param htt IN instance
 * @param args IN argument string
 */
static apr_status_t htt_cmd_include_compile(htt_command_t *command, htt_t *htt,
                                            char *args); 

/**
 * Get last body from stack
 * @param command IN command
 * @param htt IN instance
 * @param args IN argument string
 */
static apr_status_t htt_cmd_end_compile(htt_command_t *command, htt_t *htt,
                                        char *args); 

/************************************************************************
 * Globals 
 ***********************************************************************/
int htt_error = 0;

/************************************************************************
 * Private 
 ***********************************************************************/

static apr_status_t htt_execute(htt_t *htt, htt_compiled_t *compiled, 
                                htt_worker_t *worker) {
  apr_status_t status = APR_SUCCESS;
  int i;
  apr_table_entry_t *e;
  htt_compiled_t *exec;

  e = (apr_table_entry_t *) apr_table_elts(compiled->body)->elts;
  for (i = 0; 
       status == APR_SUCCESS && 
       i < apr_table_elts(compiled->body)->nelts; 
       ++i) {
    int doit = 1;
    exec = (htt_compiled_t *)e[i].val;
    htt_log(htt->log, HTT_LOG_CMD, "%s:%d -> %s %s", exec->file, exec->line, 
            exec->name, exec->args);
    if (exec->function) {
      status = exec->function(worker, exec->args); 
    }
    if (exec->body && doit) {
      htt_worker_t *child_worker = htt_worker_new(worker, 
                                                  htt_worker_get_log(worker));
      status = htt_execute(htt, exec, child_worker);
      htt_log(htt->log, HTT_LOG_CMD, "%s:%d -> end", exec->file, exec->line);
    }
  }

  return status;
}

static apr_status_t htt_compile(htt_t *htt, htt_bufreader_t *bufreader) {
  char *line;
  apr_status_t status = APR_SUCCESS;
  htt->cur_line = 1;

  while (status == APR_SUCCESS && 
         htt_bufreader_read_line(bufreader, &line) == APR_SUCCESS) {
    for (; *line == ' ' || *line == '\t'; ++line);
    if (*line != '#' && *line != '\0') {
      char *rest;
      char *cmd;
      htt_command_t *command;

      cmd = apr_strtok(line, " ", &rest);
      htt_log(htt->log, HTT_LOG_DEBUG, "%s:%d -> %s[%s]", htt->cur_file, htt->cur_line, cmd, rest);
      command = apr_hash_get(htt->commands, cmd, APR_HASH_KEY_STRING);
      if (!command) {
        /* not found */
        /* hook unknown function */
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

  if (htt_stack_elems(htt->stack) != 0) {
    htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                  "Unclosed body on line %s:%d", htt->compiled->file, 
                  htt->compiled->line);
    htt_throw_error();
  }
  return APR_SUCCESS;
}

static apr_status_t htt_cmd_include_compile(htt_command_t *command, htt_t *htt,
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

static apr_status_t htt_cmd_end_compile(htt_command_t *command, htt_t *htt,
                                        char *args) {
  htt_stack_pop(htt->stack);
  htt->compiled = htt_stack_top(htt->stack);
  htt_log(htt->log, HTT_LOG_DEBUG, "pop stack, compiled %x, compiled->body %x",
          htt->compiled, htt->compiled->body);
  if (htt->compiled && htt_stack_elems(htt->stack) >= 0) {
    return APR_SUCCESS;
  }
  else {
    apr_status_t status = APR_EINVAL;
    htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                  "Too many closing \"end\"");
    return status;
  }
}

/************************************************************************
 * Public 
 ***********************************************************************/

apr_status_t htt_cmd_echo_function(htt_worker_t *worker, const char *raw) {
  htt_log(htt_worker_get_log(worker), HTT_LOG_NONE, "%s", raw);
  return APR_SUCCESS;
}

apr_status_t htt_cmd_line_compile(htt_command_t *command, htt_t *htt, 
                                  char *args) {
  htt_compiled_t *compiled = apr_pcalloc(htt->pool, sizeof(*compiled));
  compiled->name = command->name;
  compiled->function = command->function;
  compiled->args = args;
  compiled->file = htt->cur_file;
  compiled->line = htt->cur_line;
  apr_table_addn(htt->compiled->body, apr_pstrdup(htt->pool, ""), 
                 (void *)compiled);
  htt_log(htt->log, HTT_LOG_DEBUG, "add line compiled %x, compiled->body %x",
          htt->compiled, htt->compiled->body);
  return APR_SUCCESS;
}

apr_status_t htt_cmd_body_compile(htt_command_t *command, htt_t *htt, 
                                  char *args) {
  htt_compiled_t *compiled = apr_pcalloc(htt->pool, sizeof(*compiled));
  htt_stack_push(htt->stack, compiled);
  compiled->name = command->name;
  compiled->function = command->function;
  compiled->args = args;
  compiled->file = htt->cur_file;
  compiled->line = htt->cur_line;
  compiled->body = apr_table_make(htt->pool, 20);
  apr_table_addn(htt->compiled->body, apr_pstrdup(htt->pool, ""), 
                 (void *)compiled);
  /* replace htt->compiled with the new one */
  htt_log(htt->log, HTT_LOG_DEBUG, "add body compiled %x, compiled->body %x",
          htt->compiled, htt->compiled->body);
  htt->compiled = compiled;
  htt_log(htt->log, HTT_LOG_DEBUG, "push stack compiled %x, compiled->body %x",
          htt->compiled, htt->compiled->body);
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
  htt->defines = htt_store_new(pool);
  htt->commands = apr_hash_make(pool);
  htt->stack = htt_stack_new(pool);
  htt->compiled = apr_pcalloc(pool, sizeof(htt_compiled_t));
  htt_stack_push(htt->stack, htt->compiled);
  htt->compiled->body = apr_table_make(pool, 20);

  htt_add_command(htt, "include", "file", "<file>", "include a htt file", 
                  htt_cmd_include_compile, NULL);
  htt_add_command(htt, "end", "", "", "end a open body", 
                  htt_cmd_end_compile, NULL);
  htt_add_command(htt, "echo", "string", "<string>", "echo a string", 
                  htt_cmd_line_compile, htt_cmd_echo_function);
  htt_add_command(htt, "body", "", "", "open a new body",
                  htt_cmd_body_compile, NULL);
  return htt;
}

void htt_set_log(htt_t *htt, apr_file_t *std, apr_file_t *err, int mode) {
  htt->log = htt_log_new(htt->pool, std, err);
  htt_log_set_mode(htt->log, mode);
}

void htt_add_value(htt_t *htt, const char *key, const char *val) {
  htt_store_set(htt->defines, key, val);
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
  apr_hash_set(htt->commands, name, APR_HASH_KEY_STRING, command);
}

apr_status_t htt_compile_fp(htt_t *htt, apr_file_t *fp) {
  htt_bufreader_t *bufreader = htt_bufreader_file_new(htt->pool, fp);
  return htt_compile(htt, bufreader);
}

apr_status_t htt_run(htt_t *htt) {
  htt_worker_t *worker = htt_worker_new(NULL, htt->log);
  return htt_execute(htt, htt->compiled, worker);
}

