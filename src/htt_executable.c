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
 * Implementation of the HTTP Test Tool executable.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_strings.h>

#include "htt_core.h"
#include "htt_util.h"
#include "htt_replacer.h"
#include "htt_context.h"
#include "htt_executable.h"
#include "htt_log.h"
#include "htt_string.h"
#include "htt_function.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_executable_s {
  apr_pool_t *pool;
  const char *name;
  const char *file;
  int line;
  const char *signature;
  htt_function_f function;
  const char *raw;
  apr_table_t *body;
  apr_hash_t *config;
};

/**
 * Replacer to resolve variables in a line
 * @param udata IN context pointer
 * @param name IN name of variable to resolve
 * @return variable value
 */
static const char *_context_replacer(void *udata, const char *name); 

/**
 * Check if closure returns 1 or 0
 * @param closure IN closure for eval doit
 * @param ptmp IN 
 * @return 0 or 1
 */
static int _doit(htt_function_t *closure, apr_pool_t *ptmp); 

/**
 * Handle signature with given line
 * @param pool IN pool to alloc params map
 * @param signature IN parameter signature
 * @param line IN line
 * @return map of parameters
 */
htt_map_t *_handle_signature(apr_pool_t *pool, const char *signature, 
                             char *line);

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_executable_t *htt_executable_new(apr_pool_t *pool, const char *name,
                                     const char *signature, 
                                     htt_function_f function, char *raw, 
                                     const char *file, int line) {
  htt_executable_t *executable = apr_pcalloc(pool, sizeof(*executable));
  executable->pool = pool;
  executable->name = name;
  executable->signature = signature;
  executable->function = function;
  executable->raw = raw;
  executable->file = file;
  executable->line = line;
  executable->config = apr_hash_make(pool);
  return executable;
}

void htt_executable_add(htt_executable_t *executable, 
                        htt_executable_t *addition) {
  if (!executable->body) {
    executable->body = apr_table_make(executable->pool, 20);
  }
  apr_table_addn(executable->body, apr_pstrdup(executable->pool, ""), 
                 (void *)addition);
}

void htt_executable_dump(htt_executable_t *executable) {
  fprintf(stderr, "executable(%p): name=\"%s\", signature=\"%s\", "
          "function=\"%p\", raw=\"%s\", body=\"%p\"\n", executable, 
          executable->name, executable->signature, executable->function, 
          executable->raw, executable->body);
};

void htt_executable_set_raw(htt_executable_t *executable, char *raw) {
  executable->raw = raw;
}

const char *htt_executable_get_file(htt_executable_t *executable) {
  return executable->file;
}

int htt_executable_get_line(htt_executable_t *executable) {
  return executable->line;
}

const char *htt_executable_get_raw(htt_executable_t *executable) {
  return executable->raw;
}

apr_hash_t *htt_executable_get_config(htt_executable_t *executable) {
  return executable->config;
}

htt_function_f htt_executable_get_function(htt_executable_t *executable) {
  return executable->function;
}

apr_status_t htt_execute(htt_executable_t *executable, htt_context_t *context) {
  apr_status_t status = APR_SUCCESS;
  int i;
  apr_table_entry_t *e;
  htt_executable_t *exec;

  e = (apr_table_entry_t *) apr_table_elts(executable->body)->elts;
  for (i = 0; 
       status == APR_SUCCESS && 
       i < apr_table_elts(executable->body)->nelts; 
       ++i) {
    htt_context_t *child_context = NULL;
    int doit = 0;
    char *line;
    apr_pool_t *ptmp;
    htt_stack_t *retvars; 
    htt_map_t *params = NULL;
    htt_function_t *closure = NULL;
    exec = (htt_executable_t *)e[i].val;

    apr_pool_create(&ptmp, htt_context_get_pool(context));
    retvars = htt_stack_new(ptmp);
    line = apr_pstrdup(ptmp, exec->raw);
    line = htt_replacer(ptmp, line, context, _context_replacer);
    params = _handle_signature(ptmp, exec->signature, line);
    htt_executable_dump(exec);
    htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> %s %s", 
            exec->file, exec->line, exec->name, line);
    if (exec->body) {
      child_context= htt_context_new(context, htt_context_get_log(context));
      if (params) htt_context_merge_vars(child_context, params);
    }
    if (exec->function) {
      if (exec->body) {
        status = exec->function(exec, child_context, ptmp, params, retvars, 
                                line); 
        closure = htt_stack_top(retvars);
        if (!htt_isa_function(closure)) {
          htt_log(htt_context_get_log(context), HTT_LOG_ERROR, 
                  "Expect a closure"); 
          return APR_EGENERAL;

        }
      }
      else {
        status = exec->function(exec, context, ptmp, params, retvars, line); 
        /* TODO: store revars if any */
      }
    }
    apr_pool_destroy(ptmp);
    if (closure) {
      doit = _doit(closure, ptmp);
    }
    else {
      doit = 1;
    }
    while (exec->body && doit) {
      status = htt_execute(exec, child_context);
      htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> end", 
              exec->file, exec->line);
      doit = _doit(closure, ptmp);
    }
    if (child_context) {
      htt_context_destroy(child_context);
    }
  }

  return status;
}

/************************************************************************
 * Private
 ***********************************************************************/
static const char *_context_replacer(void *udata, const char *name) {
  htt_context_t *context = udata;
  htt_string_t *string;

  string = htt_context_get_var(context, name); 
  if (htt_isa_string(string)) {
    return htt_string_get(string);
  }
  else {
    return NULL;
  }
}

static int _doit(htt_function_t *closure, apr_pool_t *ptmp) {
  int doit = 0;
  if (closure) {
    htt_string_t *ret;
    htt_stack_t *retvars;
    htt_context_t *context = htt_function_get_context(closure);
    retvars = htt_stack_new(htt_context_get_pool(context));
    htt_function_call(closure, ptmp, NULL, retvars);
    ret = htt_stack_top(retvars);
    if (htt_isa_string(ret) && strcmp(htt_string_get(ret), "1") == 0) {
      doit = 1;
    }
  }
  return doit;
}

htt_map_t *_handle_signature(apr_pool_t *pool, const char *signature, 
                             char *line) {
  if (signature) {
    char *cur;
    char *rest;
    char **argv;
    char *copy = apr_pstrdup(pool, signature);
    int i = 0;
    htt_map_t *params = htt_map_new(pool);

    htt_tokenize_to_argv(line, &argv, pool, 0);

    cur = apr_strtok(copy, " ", &rest);
    while (cur) {
      htt_string_t *string = NULL;
      if (argv[i]) {
        fprintf(stderr, "XXX %s = %s\n", cur, argv[i]);
        string = htt_string_new(pool, argv[i]);
        htt_map_set(params, cur, string, htt_string_free);
      }
      cur = apr_strtok(NULL, " ", &rest);
      ++i;
    }

    return params;
  }
  return NULL;
}

