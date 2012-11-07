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
#include "htt_defines.h"

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
#include <apr_support.h>
#include <apr_hash.h>
#include <apr_base64.h>
#include <apr_env.h>
#include <apr_hooks.h>

#include <pcre.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "htt_modules.h"
#include "htt_bufreader.h"
#include "htt_util.h"
#include "htt_core.h"
#include "htt_log.h"
#include "htt_log_std_appender.h"
#include "htt_map.h"
#include "htt_stack.h"
#include "htt_executable.h"
#include "htt_context.h"
#include "htt_object.h"
#include "htt_function.h"
#include "htt_string.h"
#include "htt_expr.h"
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

typedef struct _counter_config_s {
  int i;
} _counter_config_t;

typedef struct _regex_s {
  int not;
  int hits;
  const char *pattern;
  pcre *pcre;
} _regex_t;

typedef struct _ns_s {
  apr_table_t *regexs;
  char **vars;
  int n_vars;
} _ns_t;

typedef struct _expect_config_s {
  apr_pool_t *pool;
  apr_table_t *ns;
  htt_t *filter_chain;
} _expect_config_t;

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
 * Get expect config from given context
 * @param context IN
 * @return expect config
 */
static _expect_config_t *_get_expect_config(htt_context_t *context); 

/**
 * Get expect context seen from given context
 * @param context IN
 * @return context
 */
static htt_context_t *_get_expect_context(htt_context_t *context); 

/**
 * Interpret reading from given bufreader 
 * @param htt IN instance
 * @param fp IN apr file pointer
 * @param terminate IN if true do add an end at the end of script
 * @return apr status
 */
static apr_status_t _compile(htt_t *htt, htt_bufreader_t *bufreader,
                             int terminate); 

/**
 * Compile function for include. Just open file and and interpret.
 * @param command IN command
 * @param args IN argument string
 * @param compiier IN compiler
 * @return apr status
 */
static apr_status_t _cmd_include_compile(htt_command_t *command, char *args,
                                         void *compiler); 

/**
 * Get last body from stack
 * @param command IN command
 * @param args IN argument string
 * @param compiler IN compiler
 * @return apr status
 */
static apr_status_t _cmd_end_compile(htt_command_t *command, char *args,
                                     void *compiler); 

/**
 * Define a new function and register it
 * @param command IN command
 * @param args IN argument string
 * @param compiler IN compiler
 * @return apr status
 */
static apr_status_t _cmd_func_def_compile(htt_command_t *command, char *args,
                                          void *compiler);

/**
 * Add defined function 
 * @param command IN command
 * @param args IN argument string
 * @param compiler IN compiler
 * @return apr status
 */
static apr_status_t _cmd_function_compile(htt_command_t *command, char *args,
                                          void *compiler); 

/**
 * End command
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_end_function(htt_executable_t *executable, 
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
 * if command
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_if_function(htt_executable_t *executable, 
                                     htt_context_t *context, apr_pool_t *ptmp, 
                                     htt_map_t *params, htt_stack_t *retvars,
                                     char *line);

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
 * req 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_req_function(htt_executable_t *executable, 
                                      htt_context_t *context, 
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line); 

/**
 * filter registers function for content filtering
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_filter_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * wait
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_wait_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line); 

/**
 * expect 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_expect_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * Clean up pcre object
 * @param pcre IN void pointer to pcre
 * @return APR_SUCCESS
 */
static apr_status_t _regex_cleanup(void *pcre);

/**
 * Fill mached parts from buf with help of ovector
 * @param context IN dynamic context
 * @param buf IN buffer
 * @param ovector IN pcre ovector
 * @param ns IN namespace data
 */
void _fill_expected_vars(htt_context_t *context, const char *buf, int *ovector,
                         _ns_t *ns);
/************************************************************************
 * Globals 
 ***********************************************************************/
int htt_error = 0;

/************************************************************************
 * Public 
 ***********************************************************************/
apr_status_t htt_null_closure(htt_executable_t *executable, 
                              htt_context_t *context, apr_pool_t *ptmp, 
                              htt_map_t *params, htt_stack_t *retvars, 
                              char *line) {
  htt_string_t *retval = htt_string_new(ptmp, apr_pstrdup(ptmp, "0"));
  htt_stack_push(retvars, retval);
  return APR_SUCCESS;
}

apr_status_t htt_expect_register(htt_executable_t *executable, 
                                 htt_context_t *context, const char *namespace, 
                                 const char *expr, char **vars, int n) {
  _expect_config_t *config = _get_expect_config(context);
  _ns_t *ns = (void *)apr_table_get(config->ns, namespace);
  if (!ns) {
    ns = apr_pcalloc(config->pool, sizeof(*ns));
    ns->regexs = apr_table_make(config->pool, 5);
    ns->vars = vars;
    ns->n_vars = n;
    apr_table_setn(config->ns, apr_pstrdup(config->pool, namespace), 
                   (void *)ns);
  }

  {
    _regex_t *regex = apr_pcalloc(config->pool, sizeof(*regex));
    const char *error;
    int erroff;
    regex->pcre = pcre_compile(expr, 0, &error, &erroff, NULL);
    regex->pattern = apr_pstrdup(config->pool, expr);
    if (error) {
      apr_status_t status = APR_EGENERAL;
      htt_log_error(htt_context_get_log(context), status, 
                    htt_executable_get_file(executable), 
                    htt_executable_get_line(executable), 
                    "Invalid regular expression at pos %d: %s", erroff, error);
      return status;
    }
    apr_pool_cleanup_register(config->pool, (void *) regex->pcre, 
                              _regex_cleanup, apr_pool_cleanup_null);
    apr_table_addn(ns->regexs, apr_pstrdup(config->pool, expr), (void *)regex);
  }

  return APR_SUCCESS;
}

apr_status_t htt_expect_check(htt_executable_t *executable, 
                              htt_context_t *context) {
  int i;
  apr_table_entry_t *e;
  _expect_config_t *config = _get_expect_config(context);
  apr_status_t status = APR_SUCCESS;
  e = (void *) apr_table_elts(config->ns)->elts;
  for (i = 0; i < apr_table_elts(config->ns)->nelts; i++) {
    int j;
    _ns_t *ns = (void *)e[i].val;
    apr_table_entry_t *r;
    r = (void *) apr_table_elts(ns->regexs)->elts;
    for (j = 0; j < apr_table_elts(ns->regexs)->nelts; j++) {
      _regex_t *regex = (void *)r[j].val;
      if (regex->hits == 0) {
        status = APR_EINVAL;
        htt_log_error(htt_context_get_log(context), status, 
                      htt_executable_get_file(executable), 
                      htt_executable_get_line(executable), 
                      "Unused 'expect %s \"%s\"'", e[i].key, regex->pattern);
      }
    }
  }
  apr_pool_destroy(config->pool);
  htt_context_set_config(context, "expect", NULL);
  return status;
}

apr_status_t htt_expect_assert(htt_executable_t *executable, 
                               htt_context_t *context, const char *namespace,
                               const char *buf, apr_size_t len) {
  apr_size_t _len;
  apr_status_t status = APR_SUCCESS;
  _expect_config_t *config = _get_expect_config(context);
  _ns_t *ns = (void *)apr_table_get(config->ns, namespace);
  if (ns) {
    int i;
    apr_table_entry_t *r;
    if (len == -1) {
      _len = strlen(buf);
    }
    else {
      _len = len;
    }
    r = (void *) apr_table_elts(ns->regexs)->elts;
    for (i = 0; i < apr_table_elts(ns->regexs)->nelts; i++) {
      int *ovector = malloc(sizeof(int) * (ns->n_vars + 1) * 3);
      int rc;
      _regex_t *regex = (void *)r[i].val;
      rc = pcre_exec(regex->pcre, NULL, buf, _len, 0, 0, ovector, 
                     (ns->n_vars + 1) * 3);
      if (rc < 0) {
        status = APR_EINVAL;
        htt_log_error(htt_context_get_log(context), status, 
                      htt_executable_get_file(executable), 
                      htt_executable_get_line(executable), 
                      "Did 'expect %s \"%s\"", namespace, regex->pattern);
      }
      else if (rc == 0) {
        _fill_expected_vars(context, buf, ovector, ns);
        ++regex->hits;
      }
      else {
        ns->n_vars = rc - 1;
        _fill_expected_vars(context, buf, ovector, ns);
        ++regex->hits;
      }
      free(ovector);
    }
  }
  return status;
}

apr_status_t htt_cmd_line_compile(htt_command_t *command, char *args,
                                  void *compiler) {
  htt_executable_t *executable;
  htt_t *htt = compiler;

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

apr_status_t htt_cmd_body_compile(htt_command_t *command, char *args, 
                                  void *compiler) {
  htt_executable_t *executable;
  htt_t *htt = compiler;

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
  htt_error = 2;
  exit(2);
}

void htt_throw_ok() {
  htt_error = 0;
  exit(0);
}

htt_t *htt_new(apr_pool_t *pool) {
  htt_t *htt = apr_pcalloc(pool, sizeof(*htt));
  htt->pool = pool;
  htt->defines = htt_map_new(pool);
  htt->stack = htt_stack_new(pool);
  htt->executable = htt_executable_new(pool, NULL, apr_pstrdup(pool, "global"), NULL,
                                       NULL, NULL, NULL, 0);
  htt_stack_push(htt->stack, htt->executable);
  return htt;
}

void htt_command_register(htt_t *htt) {
  htt_add_command(htt, "include", "NULL", "<file>+", 
                  "include ht3 files", 
                  _cmd_include_compile, NULL);
  htt_add_command(htt, "end", NULL, "", 
                  "end a open body", 
                  _cmd_end_compile, _cmd_end_function);
  htt_add_command(htt, "body", NULL, "", 
                  "open a new body",
                  htt_cmd_body_compile, NULL);
  htt_add_command(htt, "function", NULL, "<parameter>*", 
                  "define a function",
                  _cmd_func_def_compile, NULL);
  htt_add_command(htt, "terminate", NULL, "", 
                  "very last command do wait for resouces", 
                  htt_cmd_line_compile, _cmd_end_function);
  htt_add_command(htt, "loop", NULL, "<n> [<variable>]", 
                  "loop a body <n> times, if <variable> is defined <n> will be "
                  "stored in <variable>",
                  htt_cmd_body_compile, _cmd_loop_function);
  htt_add_command(htt, "if", NULL, "0|1 $expr(\"<expression>\")", "do body if 1",
                  htt_cmd_body_compile, _cmd_if_function);
  htt_add_command(htt, "req", NULL, "<scheme>://<target> <params>",
                  "req connects to a resource",
                  htt_cmd_line_compile, _cmd_req_function);
  htt_add_command(htt, "filter", NULL, "filter function",
                  "add a function as a filter, function must have signature"
                  "function <name> in : out",
                  htt_cmd_line_compile, _cmd_filter_function);
  htt_add_command(htt, "wait", NULL, "[<n>]",
                  "wait for an answer from an requested resource, "
                  "optional could say how many bytes <n>",
                  htt_cmd_line_compile, _cmd_wait_function);
  htt_add_command(htt, "expect", NULL, "<namespace> <regex>",
                  "defines what wait do expect in the receiving stream",
                  htt_cmd_line_compile, _cmd_expect_function);

  htt_modules_command_register(htt);
}

void htt_set_log(htt_t *htt, apr_file_t *std, apr_file_t *err, int mode) {
  htt->log = htt_log_new(htt->pool, 0);
  htt_log_set_appender(htt->log, htt_log_std_appender_new(htt->pool, std, err));
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

apr_pool_t *htt_get_pool(htt_t *htt) {
  return htt->pool;
}

htt_executable_t *htt_get_executable(htt_t *htt) {
  return htt->executable;
}

htt_log_t *htt_get_log(htt_t *htt) {
  return htt->log;
}

void htt_add_command(htt_t *htt, const char *name, const char *signature, 
                     const char *short_desc, const char *desc,
                     htt_compile_f compile, htt_function_f function) {
  htt_command_t *command;
  command = htt_command_new(htt->pool, name, signature, short_desc, desc,
                            compile, function);
  htt_executable_set_command(htt->executable, name, command);
}

htt_command_t *htt_get_command(htt_executable_t *executable, const char *cmd) {
  htt_command_t *command = NULL;
  htt_executable_t *cur = executable;

  command = htt_executable_get_command(cur, cmd);
  while (cur && !command) {
    command = htt_executable_get_command(cur, cmd);
    cur = htt_executable_get_parent(cur);
  }
  return command;
}

apr_status_t htt_compile_buf(htt_t *htt, const char *buf, apr_size_t len) {
  htt_bufreader_t *bufreader = htt_bufreader_buf_new(htt->pool, buf, len);
  return _compile(htt, bufreader, 1);
}

apr_status_t htt_compile_fp(htt_t *htt, apr_file_t *fp) {
  htt_bufreader_t *bufreader = htt_bufreader_file_new(htt->pool, fp);
  return _compile(htt, bufreader, 1);
}

apr_status_t htt_run(htt_t *htt) {
  htt_context_t *context = htt_context_new(NULL, htt->log);
  htt_context_set_vars(context, htt->defines);
  return htt_execute(htt->executable, context);
}

apr_status_t htt_filter_chain(htt_t *filter_chain, htt_context_t *context, 
                              htt_string_t *in, htt_string_t **out) {
  *out = in;
  if (filter_chain) {
    int i;
    apr_table_entry_t *e;
    apr_status_t status = APR_SUCCESS;
    htt_t *htt = filter_chain;
    htt_executable_t *executable = htt->executable;
    apr_table_t *body = htt_executable_get_body(executable);
    htt_string_t *cur_in = in;

    e = (apr_table_entry_t *) apr_table_elts(body)->elts;
    for (i = 0; 
         status == APR_SUCCESS && 
         i < apr_table_elts(body)->nelts; 
         ++i) {
      htt_string_t *result;
      htt_stack_t *retvals;
      htt_function_f function;

      htt_executable_t *exec = (void *)e[i].val;
      htt_map_t *params = htt_map_new(htt_context_get_pool(context));
      htt_map_set(params, "in", cur_in);
      retvals = htt_stack_new(htt_context_get_pool(context));
      function = htt_executable_get_function(exec);
      status = function(exec, context, htt_context_get_pool(context), params, 
                        retvals, NULL); 
      result = htt_stack_pop(retvals);
      if (htt_isa_string(result)) {
        cur_in = result;
      }
      else {
        status = APR_EINVAL;
        htt_log_error(htt_context_get_log(context), status, 
                      htt_executable_get_file(executable), 
                      htt_executable_get_line(executable), 
                      "Expect a string");
      }
    }
    *out = cur_in;
  }
  return APR_SUCCESS;
}

/************************************************************************
 * Private 
 ***********************************************************************/
void _fill_expected_vars(htt_context_t *context, const char *buf, int *ovector,
                         _ns_t *ns) {
  int i;

  for (i = 0; i < ns->n_vars; i++) {
    htt_string_t *var;
    int so = ovector[(i + 1) * 2];
    int eo = ovector[(i + 1) * 2 + 1];

    var = htt_string_n_new(htt_context_get_pool(context), &buf[so], eo-so);
    htt_context_set_var(context, ns->vars[i], var);
  }
}

static apr_status_t _compile(htt_t *htt, htt_bufreader_t *bufreader, 
                             int terminate) {
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
      htt_log(htt->log, HTT_LOG_DEBUG, '=', "compile", "%s:%d -> %s[%s]", 
              htt->cur_file, htt->cur_line, cmd, rest);
      command = htt_get_command(htt->executable, cmd);
      if (!command) {
        status = APR_EGENERAL;
        htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                      "Unknown command \"%s\"", cmd);
        htt_throw_error();
      }
      else {
        const char *old_file_name = htt->cur_file;
        int old_line = htt->cur_line;
        status = htt_command_compile(command, rest, htt);
        htt->cur_file =  old_file_name;
        htt->cur_line = old_line;
      }
    }
    ++htt->cur_line;
  }
  if (terminate) {
    htt_command_compile(htt_get_command(htt->executable, "terminate"), "", htt);
  }

  if (htt_stack_elems(htt->stack) != 1) {
    status = APR_EGENERAL;
    htt_log_error(htt->log, status, htt->cur_file, htt->cur_line, 
                  "Unclosed body on line %s:%d", 
                  htt_executable_get_file(htt->executable), 
                  htt_executable_get_line(htt->executable));
    htt_throw_error();
  }
  return APR_SUCCESS;
}

static apr_status_t _cmd_include_compile(htt_command_t *command, char *args,
                                         void *compiler) {
  apr_file_t *fp;
  apr_status_t status;
  htt_t *htt = compiler;

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

static apr_status_t _cmd_end_compile(htt_command_t *command, char *args,
                                     void *compiler) {
  htt_t *htt = compiler;
  htt_cmd_line_compile(command, args, compiler);
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

static apr_status_t _cmd_func_def_compile(htt_command_t *command, char *args,
                                          void *compiler) {
  htt_t *htt = compiler;
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
  htt_command_set_config(new_command, "executable", executable);
  htt_executable_set_command(htt->executable, name, new_command);
  htt_stack_push(htt->stack, executable);
  htt->executable = executable;
  return APR_SUCCESS;
}

static apr_status_t _cmd_function_compile(htt_command_t *command, char *args,
                                          void *compiler) {
  htt_t *htt = compiler;
  htt_executable_t *executable;
  executable = htt_executable_new(htt->pool, htt->executable, 
                                  htt_command_get_name(command), 
                                  htt_command_get_signature(command), 
                                  _cmd_function_function, NULL, htt->cur_file,
                                  htt->cur_line);
  htt_executable_set_params(executable, htt_command_get_params(command));
  htt_executable_set_retvars(executable, htt_command_get_retvars(command));
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
  child_context = htt_context_new(context, htt_context_get_log(context));
  if (params) htt_context_merge_vars(child_context, params);
  status = htt_execute(_executable, child_context);
  _get_retvals(child_context, htt_executable_get_retvars(_executable), 
               retvals, ptmp);
  htt_context_destroy(child_context);
  return status;
}

static _counter_config_t *_counter_get_config(htt_context_t *context) {
  _counter_config_t *config;

  config = htt_context_get_config(context, "_counter_config");
  if (config == NULL) {
    config = apr_pcalloc(htt_context_get_pool(context), sizeof(*config));
    htt_context_set_config(context, 
                           apr_pstrdup(htt_context_get_pool(context), 
                                       "_counter_config"), config);
  }
  return config;
}

static apr_status_t _loop_closure(htt_executable_t *executable, 
                                  htt_context_t *context, apr_pool_t *ptmp, 
                                  htt_map_t *params, htt_stack_t *retvars, 
                                  char *line) {
  int counter;
  htt_string_t *retval;
  _counter_config_t *config;
  htt_string_t *index = htt_map_get(htt_context_get_vars(context), "index");
  htt_string_t *count = htt_map_get(htt_context_get_vars(context), "count");
  if (htt_isa_string(count)) {
    config = _counter_get_config(context);
    if (htt_isa_string(index)) {
      htt_context_t *parent = htt_context_get_parent(context);
      htt_string_t *index_val;
      index_val = htt_string_new(htt_context_get_pool(parent), 
                                 apr_ltoa(htt_context_get_pool(parent), 
                                          config->i));
      htt_map_set(htt_context_get_vars(parent), htt_string_get(index), 
                  index_val);
    }
    ++config->i;
    counter = apr_atoi64(htt_string_get(count));
    if (counter >= 0 && config->i > counter) {
      retval = htt_string_new(ptmp, apr_pstrdup(ptmp, "0"));
    }
    else {
      retval = htt_string_new(ptmp, apr_pstrdup(ptmp, "1"));
    }
    htt_stack_push(retvars, retval);
  }
  return APR_SUCCESS;
}

static apr_status_t _cmd_end_function(htt_executable_t *executable, 
                                      htt_context_t *context, 
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line) {
  apr_status_t status = htt_expect_check(executable, context);
  if (status == APR_SUCCESS) {
    return htt_run_end_function(executable, context, line);
  }
  else {
    return status;
  }
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
  htt_string_t *index_str;

  char *count;
  char *index;

  count = apr_strtok(line, " ", &index);

  if (!count || !count[0]) {
    apr_status_t status = APR_EGENERAL;
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Expect a count");
    return status;
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
  if (index && index[0]) {
    index_str = htt_string_new(htt_context_get_pool(loop_context), index);
    htt_map_set(loop_vars, "index", index_str);
  }

  loop_closure = htt_function_new(htt_context_get_pool(loop_context), 
                                  loop_executable, loop_context);
  /* this must return a closure */
  htt_stack_push(retvars, loop_closure);
  return APR_SUCCESS;
}

static apr_status_t _if_closure(htt_executable_t *executable, 
                                  htt_context_t *context, apr_pool_t *ptmp, 
                                  htt_map_t *params, htt_stack_t *retvars, 
                                  char *line) {
  htt_string_t *retval;
  _counter_config_t *config;
  htt_string_t *cond = htt_map_get(htt_context_get_vars(context), "cond");

    config = _counter_get_config(context);
    if (config->i == 0) {
      if (htt_isa_string(cond)) {
        retval = htt_string_new(ptmp, apr_pstrdup(ptmp, htt_string_get(cond)));
      }
    }
    else {
      retval = htt_string_new(ptmp, apr_pstrdup(ptmp, "0"));
    }
    htt_stack_push(retvars, retval);
    ++config->i;

  return APR_SUCCESS;
}

static apr_status_t _cmd_if_function(htt_executable_t *executable, 
                                     htt_context_t *context, apr_pool_t *ptmp, 
                                     htt_map_t *params, htt_stack_t *retvars, 
                                     char *line) {
  htt_function_t *if_closure;
  htt_context_t *if_context;
  htt_executable_t *if_executable;
  htt_map_t *if_vars;
  htt_string_t *cond;
  char **argv;
  htt_util_to_argv(line, &argv, ptmp, 0);

  if (argv[0]) {
    if (apr_atoi64(argv[0]) != 0) {
      cond = htt_string_new(ptmp, argv[0]);
    }
    else {
      cond = htt_string_new(ptmp, argv[0]);
    }
  }
  else {
    htt_log_error(htt_context_get_log(context), APR_EGENERAL, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Missing condition in if");
    htt_throw_error();
  }

  if_executable = htt_executable_new(htt_context_get_pool(context), 
                                     executable, "_if_closure", NULL,
                                     _if_closure, NULL, 
                                     htt_executable_get_file(executable), 
                                     htt_executable_get_line(executable));
  if_context= htt_context_new(context, htt_context_get_log(context));
  if_vars = htt_context_get_vars(if_context);
  htt_map_set(if_vars, "cond", cond);

  if_closure = htt_function_new(htt_context_get_pool(if_context), 
                                if_executable, if_context);
  /* this must return a closure */
  htt_stack_push(retvars, if_closure);
  return APR_SUCCESS;
}

static apr_status_t _cmd_req_function(htt_executable_t *executable, 
                                      htt_context_t *context, 
                                      apr_pool_t *ptmp, htt_map_t *params, 
                                      htt_stack_t *retvars, char *line) {
  _get_expect_config(context);
  return htt_run_request_function(executable, context, line);
} 

static apr_status_t _cmd_filter_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  apr_status_t status;
  char *command;
  _expect_config_t *config = _get_expect_config(context);
  htt_bufreader_t *bufreader;
  htt_executable_t *exec;

  if (!config->filter_chain) {
    config->filter_chain = htt_new(config->pool);
    config->filter_chain->log = htt_context_get_log(context);
  }

  apr_collapse_spaces(line, line);
  command = apr_psprintf(config->pool, "%s in out", line);
  bufreader = htt_bufreader_buf_new(config->pool, command, strlen(command));
  exec = htt_get_executable(config->filter_chain);
  htt_executable_set_parent(exec, executable);
  if ((status = _compile(config->filter_chain, bufreader, 0))
      != APR_SUCCESS) {
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Unknown filter function");
  }

  return status;
}

static apr_status_t _cmd_wait_function(htt_executable_t *executable, 
                                       htt_context_t *context, 
                                       apr_pool_t *ptmp, htt_map_t *params, 
                                       htt_stack_t *retvars, char *line) {
  apr_status_t status;
  htt_context_t *top = _get_expect_context(context);
  _expect_config_t *config = _get_expect_config(context);
  status = htt_run_wait_function(executable, top, line, config->filter_chain);
  if (status == APR_SUCCESS) {
    status = htt_expect_check(executable, context);
  }
  return status;
} 

static _expect_config_t *_get_expect_config(htt_context_t *context) {
  _expect_config_t *config = htt_context_get_config(context, "expect");
  if (!config) {
    apr_pool_t *pool;
    apr_pool_create(&pool, htt_context_get_pool(context));
    config = apr_pcalloc(pool, sizeof(*config));
    config->pool = pool;
    config->ns = apr_table_make(pool, 3);
    htt_context_set_config(context, "expect", config);
  }
  return config;
}

static htt_context_t *_get_expect_context(htt_context_t *context) {
  _expect_config_t *config = NULL;
  htt_context_t *cur = context;
  while (cur && config == NULL) {
    config = htt_context_get_config(context, "expect");
    if (!config) {
      cur = htt_context_get_parent(cur);
    }
  }
  if (!cur) {
    cur = htt_context_get_godfather(context);
  }
  return cur;
}

static apr_status_t _regex_cleanup(void *pcre) {
  pcre_free(pcre);
  return APR_SUCCESS;
}

static apr_status_t _cmd_expect_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  apr_status_t status = htt_run_expect_function(executable, context, line);
  if (APR_STATUS_IS_EAGAIN(status)) {
    int i;
    char **argv;
    htt_context_t *top = _get_expect_context(context);
    status = APR_SUCCESS;
    htt_util_to_argv(line, &argv, ptmp, 0);
    for (i = 0; argv[i]; i++);
    if (i >= 2 && i <= 12) {
      return htt_expect_register(executable, top, argv[0], argv[1], &argv[2], 
                                 i-2);
    }
    else if (i <= 12) {
      status = APR_EGENERAL;
      htt_log_error(htt_context_get_log(top), status, 
                    htt_executable_get_file(executable), 
                    htt_executable_get_line(executable), 
                    "Command expect needs 2 arguments, a namespace and a "
                    "regular expression");
    }
    else {
      status = APR_EGENERAL;
      htt_log_error(htt_context_get_log(top), status, 
                    htt_executable_get_file(executable), 
                    htt_executable_get_line(executable), 
                    "Too many vars defined for expect statement, "
                    "max 10 vars allowed");
    }
  }
  return status;
} 

static void _get_retvals(htt_context_t *context, htt_stack_t *retvars,
                         htt_stack_t *retvals, apr_pool_t *pool) {
  if (retvals && retvars) {
    int i;
    char *cur;
    
    for (i = 0; i < htt_stack_elems(retvars); i++) {
      cur = htt_stack_index(retvars, i);
      if (cur) {
        htt_object_t *val = htt_context_get_var(context, cur);
        if (val) {
          htt_stack_push(retvals, val->clone(val, pool));
        }
      }
    }
  }
}

/************************************************************************
 * Hooks 
 ***********************************************************************/
APR_HOOK_STRUCT(
  APR_HOOK_LINK(request_function)
  APR_HOOK_LINK(expect_function)
  APR_HOOK_LINK(wait_function)
  APR_HOOK_LINK(end_function)
)

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(
    htt, HTT, apr_status_t, request_function, 
    (htt_executable_t *executable, htt_context_t *context, const char *line), 
    (executable, context, line), APR_SUCCESS
);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(
    htt, HTT, apr_status_t, expect_function, 
    (htt_executable_t *executable, htt_context_t *context, const char *line), 
    (executable, context, line), APR_EAGAIN
);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(
    htt, HTT, apr_status_t, wait_function, 
    (htt_executable_t *executable, htt_context_t *context, const char *line, 
     htt_t *filter_chain), 
    (executable, context, line, filter_chain), APR_SUCCESS
);

APR_IMPLEMENT_EXTERNAL_HOOK_RUN_FIRST(
    htt, HTT, apr_status_t, end_function, 
    (htt_executable_t *executable, htt_context_t *context, const char *line), 
    (executable, context, line), APR_SUCCESS
);

