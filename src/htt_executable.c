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
 * Implementation of the HTTP Test Tool store.
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
 * Split line into parameters
 * @param pool IN pool for allocation
 * @param signature IN parameter signature
 * @param line IN resolved line
 * @param params OUT parameters
 * @param retvars OUT return value parameters
 * @return apr status
 */
static apr_status_t _split_line_to_params(apr_pool_t *pool,
                                          const char *signature, 
                                          const char *line,
                                          htt_store_t **params,
                                          htt_store_t **retvars);

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
    int doit = 1;
    char *line;
    apr_pool_t *ptmp;
    htt_store_t *params = NULL;
    htt_store_t *retvars = NULL;
    exec = (htt_executable_t *)e[i].val;

    apr_pool_create(&ptmp, htt_context_get_pool(context));
    line = apr_pstrdup(ptmp, exec->raw);
    line = htt_replacer(ptmp, line, context, _context_replacer);
    if (exec->signature) {
      apr_status_t status;
      retvars = htt_store_new(ptmp);
      if ((status = _split_line_to_params(ptmp, exec->signature, line, &params,
                                          &retvars)) != APR_SUCCESS) {
      }
    }
    htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> %s %s", 
            exec->file, exec->line, exec->name, line);
    if (exec->function) {
      if (exec->body) {
        child_context= htt_context_new(context, htt_context_get_log(context));
        status = exec->function(exec, child_context, ptmp, params, retvars, 
                                line); 
        htt_function_t *closure = htt_store_get(retvars, "__closure");
        if (!htt_isa_function(closure)) {
          htt_log(htt_context_get_log(context), HTT_LOG_ERROR, 
                  "Expect a closure"); 
          return APR_EGENERAL;

        }
      }
      else {
        status = exec->function(exec, context, ptmp, params, retvars, line); 
      }
    }
    apr_pool_destroy(ptmp);
    /* TODO: get doit decision from executed function 
     * -> lambda function (closure)
     */
    while (exec->body && doit) {
      status = htt_execute(exec, child_context);
      htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> end", 
              exec->file, exec->line);
      /* TODO: get doit decision from executed function 
       * -> lambda function (closure)
       */
      doit = 0;
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

static apr_status_t _split_line_to_params(apr_pool_t *pool,
                                          const char *signature, 
                                          const char *line,
                                          htt_store_t **params,
                                          htt_store_t **retvars) {
  char *key;
  char *rest;
  char *val;
  char *restline;

  char *sigcopy = apr_pstrdup(pool, signature);
  char *linecopy = apr_pstrdup(pool, line);
  htt_store_t *cur = htt_store_new(pool);

  *params = cur;
  *retvars = NULL;

  key = apr_strtok(sigcopy, " ", &rest);
  val = apr_strtok(linecopy, " ", &restline);
  while (key && val) {
    key = apr_strtok(NULL, " ", &rest);
    if (strcmp(key, ":") == 0) {
      cur = htt_store_new(pool);
      *retvars = cur;
    }
    else {
      htt_string_t *string;
      val = apr_strtok(NULL, " ", &restline);
      string = htt_string_new(pool, val);
      htt_store_set(cur, key, string, htt_string_free);
    }
  } 

  return APR_SUCCESS;
}
