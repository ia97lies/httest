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
 * Implementation of the HTTP Test Tool thread module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_strings.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
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
typedef struct _thread_config_s {
  int i;
  apr_pool_t *pool;
  apr_table_t *threads;
  int count;
  apr_thread_mutex_t *mutex;
  apr_thread_mutex_t *sync;
} _thread_config_t;

typedef struct _thread_init_s {
  int count;
  int hold_sync;
} _thread_init_t;

typedef struct _thread_handle_s {
  const char *name;
  htt_executable_t *executable;
  htt_context_t *context;
  _thread_config_t *tc;
  apr_thread_t *thread;
} _thread_handle_t;

typedef struct _thread_stats_s {
  int threads;
} _thread_stats_t;

/**
 * Get thread config from given context
 * @param context IN
 * @return expect config
 */
static _thread_config_t *_get_thread_config(htt_context_t *context); 

/**
 * Thread main loop
 * @param thread IN
 * @param handlev IN void pointer to _thread_handle_t
 * @return NULL
 */
static void * APR_THREAD_FUNC _thread_body(apr_thread_t * thread, void *handlev);

/**
 * Add begin compilation only suitable for threads and only once
 * @param command IN command
 * @param args IN argument string
 * @return apr status
 */
static apr_status_t _cmd_begin_compile(htt_command_t *command, char *args); 

/**
 * thread
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_thread_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * daemon 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_daemon_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * begin function
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_begin_function(htt_executable_t *executable, 
                                        htt_context_t *context, 
                                        apr_pool_t *ptmp, htt_map_t *params, 
                                        htt_stack_t *retvars, char *line); 

/**
 * Join threads for a given context
 * @param executable IN
 * @param context IN
 * @param line IN
 * @return apr status
 */
static apr_status_t _hook_thread_end(htt_executable_t *executable, 
                                     htt_context_t *context, const char *line);

/**
 * Synchronise start of threads with and without a init block 
 * @param executable IN
 * @param context IN
 * @return apr status
 */
static apr_status_t _hook_thread_init_begin(htt_executable_t *executable, 
                                            htt_context_t *context); 

/**
 * Merge all vars from context to isolated context
 * @param isolated IN context not connected to context
 * @param context IN outer context
 */
static void _merge_all_vars(htt_context_t *isolated, htt_context_t *context); 

/**
 * Set a prefix for threads to make log more human readable
 * @param count IN how many threads allready running
 * @param log IN logger
 * @param pool IN
 */
void _set_log_prefix(int count, htt_log_t *log, apr_pool_t *pool); 

/**
 * Get thread stats from a given context
 * @param context IN dynamic context
 * @return thread stats
 */
_thread_stats_t *_get_thread_stats(htt_context_t *context); 
/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t thread_module_init(htt_t *htt) {
  htt_add_command(htt, "thread", NULL, "[<n>]",
                  "start a thread if <n> then start that many threads",
                  htt_cmd_body_compile, _cmd_thread_function);
  htt_add_command(htt, "daemon", NULL, "",
                  "start a daemon, daemons are not joined",
                  htt_cmd_body_compile, _cmd_daemon_function);
  htt_add_command(htt, "begin", NULL, "",
                  "all lines before begin are done before threads on the "
                  "same level do start, only allowed with in thread body",
                  _cmd_begin_compile, _cmd_begin_function);
  htt_hook_begin(_hook_thread_init_begin, NULL, NULL, 0);
  htt_hook_end_function(_hook_thread_end, NULL, NULL, 0);

  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/

static apr_status_t _cmd_begin_compile(htt_command_t *command, char *args) {
  htt_t *htt = htt_command_get_config(command, "htt");
  htt_executable_t *me = htt_get_executable(htt);
  htt_executable_t *parent = htt_executable_get_parent(me);
  if (!parent || htt_executable_get_function(me) != _cmd_thread_function ||
      htt_executable_get_config(me, "__thread_begin")) {
    htt_log_error(htt_get_log(htt), APR_EGENERAL, 
                  htt_executable_get_file(me), 
                  htt_executable_get_line(me), 
                  "begin only allowed in a thread body and only once");
    return APR_EGENERAL;
  }
  htt_executable_set_config(me, "__thread_begin", (void *)me);
  _thread_init_t *thread_init;
  thread_init = htt_executable_get_config(parent, "__thread_init");
  if (!thread_init) {
    thread_init = apr_pcalloc(htt_get_pool(htt), sizeof(*thread_init));
    htt_executable_set_config(parent, "__thread_init", thread_init);
  }
  ++thread_init->count;
  return htt_cmd_line_compile(command, args);
}

static apr_status_t _cmd_thread_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  apr_status_t status;
  apr_threadattr_t *tattr;
  apr_thread_t *thread;
  htt_context_t *parent = htt_context_get_parent(context);
  _thread_config_t *tc = _get_thread_config(parent);
  char *cur;
  char *variable = NULL;
  int count = 1;
  _thread_init_t *thread_init;
  _thread_stats_t *thread_stats;
  thread_init = htt_executable_get_config(htt_executable_get_parent(executable),
                                          "__thread_init");
  thread_stats = _get_thread_stats(parent);
  ++thread_stats->threads;

  while (line && *line == ' ') ++line;
  if (line && line[0]) {
    cur = apr_strtok(line, " ", &variable);
    count = apr_atoi64(cur);
    if (count <= 0) {
      count = 1;
    }
  }

  if (thread_init && !thread_init->hold_sync) {
    apr_thread_mutex_lock(tc->sync);
    thread_init->hold_sync = 1;
    tc->count = thread_init->count;
  }

  if ((status = apr_threadattr_create(&tattr, tc->pool)) 
      == APR_SUCCESS &&
      (status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      == APR_SUCCESS && 
      (status = apr_threadattr_detach_set(tattr, 0))
      == APR_SUCCESS) {

    status = APR_SUCCESS;
    while (count && status == APR_SUCCESS) {
      _thread_handle_t *th = apr_pcalloc(tc->pool, sizeof(*th));
      htt_context_t *child;
      child = htt_context_new(NULL, NULL);
      htt_context_set_log(child, 
                          htt_log_clone(htt_context_get_pool(child), 
                                        htt_context_get_log(parent)));
      _set_log_prefix(thread_stats->threads-1, htt_context_get_log(child),
                      htt_context_get_pool(child));
      if (variable && variable[0]) {
        htt_string_t *tcount;
        tcount = htt_string_new(tc->pool, apr_ltoa(tc->pool, tc->i));
        htt_map_set(htt_context_get_vars(child), variable, tcount);
      }
      _merge_all_vars(child, parent);

      th->name = apr_psprintf(tc->pool, "thread-%d", tc->i);
      th->context = child;
      th->executable = executable;
      th->tc = tc;
      htt_context_set_config(child, "__thread_handle", th);
      /** FIXME: child is never destroyed. If I destroy them after join, I get 
       *         coredumps
       */
      status = apr_thread_create(&thread, tattr, _thread_body, th, tc->pool);
      th->thread = thread;
      apr_table_addn(tc->threads, th->name, (void *)th);
      ++tc->i;
      --count;
    }
  }

  if (status == APR_SUCCESS) {
    htt_executable_t *thread_executable;
    htt_context_t *thread_context;
    htt_function_t *thread_closure;

    thread_executable = htt_executable_new(htt_context_get_pool(context), 
                                           executable, "_thread_closure", NULL,
                                           htt_null_closure, NULL, 
                                           htt_executable_get_file(executable), 
                                           htt_executable_get_line(executable));
    thread_context= htt_context_new(context, htt_context_get_log(context));
    thread_closure = htt_function_new(htt_context_get_pool(thread_context), 
                                      thread_executable, thread_context);
    /* this must return a closure */
    htt_stack_push(retvars, thread_closure);
  }

  if (status != APR_SUCCESS) {
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Could not create thread");
  }
  return status;
}

_thread_stats_t *_get_thread_stats(htt_context_t *context) {
  _thread_stats_t *stats = htt_context_get_config(context, "__thread_stats");
  if (!stats) {
    stats = apr_pcalloc(htt_context_get_pool(context), sizeof(*stats));
    htt_context_set_config(context, "__thread_stats", stats);
  }
  return stats;
}

static apr_status_t _cmd_daemon_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  apr_status_t status;
  apr_threadattr_t *tattr;
  apr_thread_t *thread;
  htt_context_t *parent = htt_context_get_parent(context);
  _thread_config_t *tc = _get_thread_config(parent);

  if ((status = apr_threadattr_create(&tattr, tc->pool)) 
      == APR_SUCCESS &&
      (status = apr_threadattr_stacksize_set(tattr, DEFAULT_THREAD_STACKSIZE))
      == APR_SUCCESS && 
      (status = apr_threadattr_detach_set(tattr, 1))
      == APR_SUCCESS) {
    _thread_handle_t *th = apr_pcalloc(tc->pool, sizeof(*th));
    htt_context_t *child;
    child = htt_context_new(NULL, htt_context_get_log(parent));
    _merge_all_vars(child, context);

    th->name = apr_psprintf(tc->pool, "daemon-%d", tc->i);
    th->context = child;
    th->executable = executable;
    th->tc = tc;
    status = apr_thread_create(&thread, tattr, _thread_body, th, tc->pool);
  }

  if (status == APR_SUCCESS) {
    htt_executable_t *thread_executable;
    htt_context_t *thread_context;
    htt_function_t *thread_closure;

    thread_executable = htt_executable_new(htt_context_get_pool(context), 
                                           executable, "_daemon_closure", NULL,
                                           htt_null_closure, NULL, 
                                           htt_executable_get_file(executable), 
                                           htt_executable_get_line(executable));
    thread_context= htt_context_new(context, htt_context_get_log(context));
    thread_closure = htt_function_new(htt_context_get_pool(thread_context), 
                                      thread_executable, thread_context);
    /* this must return a closure */
    htt_stack_push(retvars, thread_closure);
  }

  if (status != APR_SUCCESS) {
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Could not create daemon");
  }
  return status;
}

static apr_status_t _cmd_begin_function(htt_executable_t *executable, 
                                        htt_context_t *context, 
                                        apr_pool_t *ptmp, htt_map_t *params, 
                                        htt_stack_t *retvars, char *line) {
  _thread_handle_t *th = htt_context_get_config(context, "__thread_handle");
  apr_thread_mutex_lock(th->tc->mutex);
  --th->tc->count;
  if (th->tc->count == 0) {
    apr_thread_mutex_unlock(th->tc->sync);
  }
  apr_thread_mutex_unlock(th->tc->mutex);
  return APR_SUCCESS;
}

static apr_status_t _hook_thread_init_begin(htt_executable_t *executable, 
                                            htt_context_t *context) {
  return APR_SUCCESS;
}

static apr_status_t _hook_thread_end(htt_executable_t *executable, 
                                     htt_context_t *context, const char *line) {
  apr_status_t status = APR_SUCCESS;
  _thread_config_t *tc = htt_context_get_config(context, "thread");
  if (tc) {
    int i;
    apr_table_entry_t *e;
    e = (void *) apr_table_elts(tc->threads)->elts;
    for (i = 0; 
         status == APR_SUCCESS && i < apr_table_elts(tc->threads)->nelts; 
         i++) {
      apr_status_t rc;
      _thread_handle_t *th = (void *)e[i].val;
      rc = apr_thread_join(&status, th->thread);
      if (rc != APR_SUCCESS) {
        htt_log_error(htt_context_get_log(context), rc, 
                      htt_executable_get_file(executable), 
                      htt_executable_get_line(executable), 
                      "Could not join thread %x", th->thread);
        status = rc;
      }
      /** FIXME: child is never destroyed. If I destroy them after join, I get 
       *         coredumps
       */
    }

    apr_thread_mutex_destroy(tc->mutex);
    apr_thread_mutex_destroy(tc->sync);
    apr_pool_destroy(tc->pool);
    htt_context_set_config(context, "thread", NULL);
  }

  return status;
}

static apr_status_t _thread_context_destroy(void *v) {
  htt_context_t *context = v;
  htt_context_destroy(context);
  return APR_SUCCESS;
}

static void * APR_THREAD_FUNC _thread_body(apr_thread_t * thread, 
                                           void *handlev) {
  apr_status_t status;
  _thread_handle_t *handle = handlev;
  htt_context_t *context = handle->context;
  htt_executable_t *executable = handle->executable;

  if (!htt_executable_get_config(executable, "__thread_begin")) {
    apr_thread_mutex_lock(handle->tc->sync);
    apr_thread_mutex_unlock(handle->tc->sync);
  }

  apr_thread_data_set(context, "context", _thread_context_destroy, thread);
  status = htt_execute(executable, context);

  if (status == APR_SUCCESS) {
    apr_thread_exit(thread, status);
  }
  else {
    apr_thread_mutex_lock(handle->tc->mutex);
    {
      htt_executable_t *cur = htt_executable_get_parent(executable);
      while (cur) {
        htt_run_final(cur, context, status);
        cur = htt_executable_get_parent(cur);
      }
      htt_throw_error();
    } 
  }

  return NULL;
}

static _thread_config_t *_get_thread_config(htt_context_t *cur) {
  htt_context_t *context = htt_context_get_godfather(cur);
  _thread_config_t *config = htt_context_get_config(context, "thread");
  if (!config) {
    apr_pool_t *pool;
    apr_pool_create(&pool, htt_context_get_pool(context));
    config = apr_pcalloc(pool, sizeof(*config));
    config->pool = pool;
    apr_thread_mutex_create(&config->mutex, APR_THREAD_MUTEX_DEFAULT, pool);
    apr_thread_mutex_create(&config->sync, APR_THREAD_MUTEX_DEFAULT, pool);
    config->threads = apr_table_make(pool, 10);
    htt_context_set_config(context, "thread", config);
  }
  return config;
}

static void _merge_all_vars(htt_context_t *isolated, htt_context_t *context) {
  htt_map_t *vars;
  htt_map_t *isolated_vars = htt_context_get_vars(isolated);
  htt_context_t *cur = context;
  while (cur) {
    vars = htt_context_get_vars(cur);
    if (vars) {
      htt_map_merge(isolated_vars, vars, htt_context_get_pool(isolated));
    }
    cur = htt_context_get_parent(cur);
  }
}

void _set_log_prefix(int count, htt_log_t *log, apr_pool_t *pool) {
  int i;
  int no_spaces = count * 10;
  char *spaces = apr_pcalloc(pool, no_spaces + 1);
  for (i = 0; i < no_spaces; i++) {
    spaces[i] = ' ';
  }
  htt_log_set_prefix(log, spaces);
}

