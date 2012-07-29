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
#include "htt_context.h"
#include "htt_executable.h"
#include "htt_log.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct htt_executable_s {
  apr_pool_t *pool;
  const char *name;
  const char *file;
  int line;
  htt_function_f function;
  const char *args;
  apr_table_t *body;
};

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Public 
 ***********************************************************************/

htt_executable_t *htt_executable_new(apr_pool_t *pool, const char *name,
                                     htt_function_f function, char *args, 
                                     const char *file, int line) {
  htt_executable_t *executable = apr_pcalloc(pool, sizeof(*executable));
  executable->pool = pool;
  executable->name = name;
  executable->function = function;
  executable->args = args;
  executable->file = file;
  executable->line = line;
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
    int doit = 1;
    exec = (htt_executable_t *)e[i].val;
    htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> %s %s", 
            exec->file, exec->line, exec->name, exec->args);
    if (exec->function) {
      status = exec->function(context, exec->args); 
    }
    if (exec->body && doit) {
      htt_context_t *child_context;
      
      child_context= htt_context_new(context, htt_context_get_log(context));
      status = htt_execute(exec, child_context);
      htt_log(htt_context_get_log(context), HTT_LOG_CMD, "%s:%d -> end", 
              exec->file, exec->line);
    }
  }

  return status;
}


