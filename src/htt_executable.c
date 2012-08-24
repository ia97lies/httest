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
#include "htt_object.h"
#include "htt_string.h"
#include "htt_function.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_executable_s {
  htt_executable_t *parent;
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

typedef struct _context_replacer_s {
  htt_executable_t *executable;
  htt_context_t *context;
  apr_pool_t *ptmp;
} _context_replacer_t;

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
 * @return 0 or 1
 */
static int _doit(htt_function_t *closure); 

/**
 * Handle signature with given line
 * @param pool IN pool to alloc params map
 * @param signature IN parameter signature
 * @param line IN line
 * @param params OUT map of parameters
 * @param retvars OUT return parameters
 */
static void _handle_signature(apr_pool_t *pool, const char *signature, 
                              char *line, htt_map_t **params, 
                              htt_stack_t **retvars); 

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/
htt_executable_t *htt_executable_new(apr_pool_t *pool, htt_executable_t *parent, 
                                     const char *name, const char *signature, 
                                     htt_function_f function, char *raw, 
                                     const char *file, int line) {
  htt_executable_t *executable = apr_pcalloc(pool, sizeof(*executable));
  executable->pool = pool;
  executable->parent = parent;
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

htt_executable_t *htt_executable_get_parent(htt_executable_t *executable) {
  return executable->parent;
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

const char *htt_executable_get_signature(htt_executable_t *executable) {
  return executable->signature;
}

void htt_executable_set_config(htt_executable_t *executable, const char *name,
                               void *data) {
  apr_hash_set(executable->config, name, APR_HASH_KEY_STRING, data);
}

void  *htt_executable_get_config(htt_executable_t *executable, 
                                 const char *name) {
  return apr_hash_get(executable->config, name, APR_HASH_KEY_STRING);
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
    _context_replacer_t *replacer_ctx;
    htt_stack_t *retvals; 
    htt_stack_t *retvars = NULL; 
    htt_map_t *params = NULL;
    htt_function_t *closure = NULL;
    exec = (htt_executable_t *)e[i].val;

    apr_pool_create(&ptmp, htt_context_get_pool(context));
    retvals = htt_stack_new(ptmp);
    line = apr_pstrdup(ptmp, exec->raw);
    replacer_ctx = apr_pcalloc(ptmp, sizeof(*replacer_ctx));
    replacer_ctx->executable = executable;
    replacer_ctx->context = context;
    replacer_ctx->ptmp = ptmp;
    line = htt_replacer(ptmp, line, replacer_ctx, _context_replacer);
    _handle_signature(ptmp, exec->signature, line, &params, &retvars);
    htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> %s %s", 
            exec->file, exec->line, exec->name, line);
    if (!exec->body) {
      if (exec->function) {
        status = exec->function(exec, context, ptmp, params, retvals, line); 
        if (retvars) {
          apr_pool_t *pool;
          char *varname;
          htt_object_t *val;
          int i = 0;
          pool = htt_context_get_pool(context);
          varname = htt_stack_index(retvars, i);
          val = htt_stack_index(retvals, i);
          while (val && varname) {
            htt_context_set_var(context, varname, val->clone(val, pool));
            ++i;
            varname = htt_stack_index(retvars, i);
            val = htt_stack_index(retvals, i);
          }
        }
      }
    }
    else {
      child_context= htt_context_new(context, htt_context_get_log(context));
      if (exec->function) {
        status = exec->function(exec, child_context, ptmp, params, retvals, 
                                line); 
        closure = htt_stack_top(retvals);
        if (!htt_isa_function(closure)) {
          htt_log(htt_context_get_log(context), HTT_LOG_ERROR, 
                  "Expect a closure"); 
          apr_pool_destroy(ptmp);
          return APR_EGENERAL;
        }
      }
      if (closure) {
        doit = _doit(closure);
      }
      else {
        doit = 1;
      }
      while (status == APR_SUCCESS && exec->body && doit) {
        status = htt_execute(exec, child_context);
        htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> end", 
                exec->file, exec->line);
        doit = _doit(closure);
      }
      htt_context_destroy(child_context);
    }
    apr_pool_destroy(ptmp);
  }

  return status;
}

/************************************************************************
 * Private
 ***********************************************************************/
static const char *_context_replacer(void *udata, const char *name) {
  _context_replacer_t *replacer_ctx = udata;
  htt_context_t *context = replacer_ctx->context;
  htt_string_t *string;

  if (strchr(name, '(')) {
    char *rest;
    char *func;
    char *line;
    htt_function_f function;
    const char *signature;
    htt_map_t *params;
    htt_command_t *command;
    htt_executable_t *executable = replacer_ctx->executable;
    apr_pool_t *ptmp = replacer_ctx->ptmp;
    htt_stack_t *retvals = htt_stack_new(ptmp);
    char *copy = apr_pstrdup(ptmp, name);
    func = apr_strtok(copy, "(", &rest);
    line = apr_strtok(NULL, ")", &rest); 
    line = htt_replacer(ptmp, line, replacer_ctx, _context_replacer);
    command = htt_get_command(executable, func);
    if (command) {
      function = htt_get_command_function(command);
      signature = htt_get_command_signature(command);
      _handle_signature(ptmp, signature, line, &params, NULL);
      function(executable, context, ptmp, params, retvals, line); 
      if (retvals) {
        htt_string_t *string = htt_stack_pop(retvals);
        if (htt_isa_string(string)) {
          return htt_string_get(string);
        }
      }
    }
    return NULL;
  }
  else {
    string = htt_context_get_var(context, name); 
    if (htt_isa_string(string)) {
      return htt_string_get(string);
    }
    else {
      return NULL;
    }
  }
}

static int _doit(htt_function_t *closure) {
  int doit = 0;
  if (closure) {
    apr_pool_t *pool;
    htt_string_t *ret;
    htt_stack_t *retvals;
    htt_context_t *context = htt_function_get_context(closure);
    apr_pool_create(&pool, htt_context_get_pool(context));
    retvals = htt_stack_new(pool);
    htt_function_call(closure, pool, NULL, retvals);
    ret = htt_stack_top(retvals);
    if (htt_isa_string(ret) && strcmp(htt_string_get(ret), "1") == 0) {
      doit = 1;
    }
    apr_pool_destroy(pool);
  }
  return doit;
}

static void _handle_signature(apr_pool_t *pool, const char *signature, 
                              char *line, htt_map_t **params, 
                              htt_stack_t **retvars) {
  *params = NULL;
  if (retvars) {
    *retvars = NULL;
  }
  if (signature) {
    char *cur;
    char *rest;
    char **argv;
    char *copy = apr_pstrdup(pool, signature);
    int i = 0;
    *params = htt_map_new(pool);

    htt_util_to_argv(line, &argv, pool, 0);

    cur = apr_strtok(copy, " ", &rest);
    while (cur && strcmp(cur, ":") != 0) {
      if (argv[i]) {
        htt_string_t *string = htt_string_new(pool, argv[i]);
        htt_map_set(*params, cur, string);
        ++i;
      }
      else {
        htt_map_set(*params, cur, NULL);
      }
      cur = apr_strtok(NULL, " ", &rest);
    }
    if (retvars) {
      *retvars = htt_stack_new(pool);
      if (cur && strcmp(cur, ":") == 0) {
        cur = apr_strtok(NULL, " ", &rest);
        while (cur) {
          htt_string_t *string = htt_string_new(pool, NULL);
          htt_map_set(*params, cur, string);
          cur = apr_strtok(NULL, " ", &rest);
        }
      }
      while (argv[i]) {
        htt_stack_push(*retvars, argv[i]);
        ++i;
      }
    }
  }
}

