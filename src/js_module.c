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
 * Implementation of the HTTP Test Tool js module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"
#include <jsapi.h>

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * js_module = "js_module";

typedef struct js_gconf_s {
  int do_read_line;
  apr_size_t length;
} js_gconf_t;

typedef struct js_wconf_s {
  int starting_line_nr; 
  apr_table_t *params;
  apr_table_t *retvars;
  const char *filename;
  apr_size_t length;
  char *buffer;
  JSFunction *func;
} js_wconf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
  
/* The class of the global object. */  
static JSClass global_class = {  
    "global", JSCLASS_GLOBAL_FLAGS,  
    JS_PropertyStub, JS_PropertyStub, JS_PropertyStub, JS_StrictPropertyStub,  
    JS_EnumerateStub, JS_ResolveStub, JS_ConvertStub, JS_FinalizeStub,  
    JSCLASS_NO_OPTIONAL_MEMBERS  
};  

/************************************************************************
 * Local 
 ***********************************************************************/

/**
 * Get js config from global 
 *
 * @param global IN 
 * @return js config
 */
static js_gconf_t *js_get_global_config(global_t *global) {
  js_gconf_t *config = module_get_config(global->config, js_module);
  if (config == NULL) {
    config = apr_pcalloc(global->pool, sizeof(*config));
    module_set_config(global->config, apr_pstrdup(global->pool, js_module), config);
  }
  return config;
}

/**
 * Get js config from worker
 *
 * @param worker IN worker
 * @return js config
 */
static js_wconf_t *js_get_worker_config(worker_t *worker) {
  js_wconf_t *config = module_get_config(worker->config, js_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    config->params = apr_table_make(worker->pbody, 5);
    config->retvars = apr_table_make(worker->pbody, 5);
    module_set_config(worker->config, apr_pstrdup(worker->pbody, js_module), config);
  }
  return config;
}
  
/* The error reporter callback. */  
static void js_log_error(JSContext *cx, const char *message, JSErrorReport *report) {  
  worker_t *worker = JS_GetContextPrivate(cx);
  worker_log_error(worker, "%s:%d:%s", 
                   report->filename ? report->filename : "<no filename=\"filename\">", 
                   report->lineno,  message);  
}  

/**
 * Get variable names for in/out for mapping it to/from js 
 * @param worker IN callee
 * @param line IN command line
 * @return APR_SUCCESS on success
 */
static apr_status_t js_set_variable_names(worker_t *worker, char *line) {
  char *token;
  char *last;

  int input = 1;
  js_wconf_t *config = js_get_worker_config(worker);
  char *data = apr_pstrdup(worker->pbody, line);
 
  /* Get params and returns variable names for later mapping from/to js */
  token = apr_strtok(data, " ", &last);
  while (token) {
    if (strcmp(token, ":") == 0) {
      /* : is separator between input and output vars */
      input = 0;
    }
    else {
      if (input == 1) {
        apr_table_setn(config->params, token, token);
      }
      else if (input == 0) {
        apr_table_setn(config->retvars, token, token);
        input = -1;
      }
      else {
        worker_log_error(worker, "Javascript BLOCKs support only one return value");
        return APR_EGENERAL;
      }
    }
    token = apr_strtok(NULL, " ", &last);
  }
  return APR_SUCCESS;
}

/**
 * Simple js interpreter for js block
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temp pool for this function
 * @return apr status
 */
static apr_status_t block_js_interpreter(worker_t *worker, worker_t *parent, 
                                         apr_pool_t *ptmp) {
  JSRuntime *rt;  
  JSContext *cx;  
  JSObject  *global;
  js_wconf_t *wconf = js_get_worker_config(worker);

  if ((rt = JS_NewRuntime(8 * 1024 * 1024)) == NULL) {
    worker_log_error(worker, "Could not create javascript runtime");
    return APR_EGENERAL;
  } 

  if ((cx = JS_NewContext(rt, 8192)) == NULL) {
    worker_log_error(worker, "Could not create javascript context");
    return APR_EGENERAL;
  }

  JS_SetOptions(cx, JSOPTION_VAROBJFIX | JSOPTION_JIT | JSOPTION_METHODJIT);  
  JS_SetVersion(cx, JSVERSION_LATEST);  
  JS_SetContextPrivate(cx, worker);
  JS_SetErrorReporter(cx, js_log_error);

  if ((global = JS_NewCompartmentAndGlobalObject(cx, &global_class, NULL)) == NULL) {
    worker_log_error(worker, "Could not create javascript compartment");
    return APR_EGENERAL;
  }

  if (!JS_InitStandardClasses(cx, global)) {
    worker_log_error(worker, "Could not initialize javascript standard classes");
    return APR_EGENERAL;
  } 

  if (!wconf->func) {
    int i;
    const char **argv = NULL;
    int argc = apr_table_elts(wconf->params)->nelts; 
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(wconf->params)->elts;

    if (argc) {
      argv = apr_pcalloc(worker->pbody, argc * sizeof(char*));
      for (i = 1; i < argc; i++) {
        argv[i-1] = e[i].key;
      }
    }

    wconf->func = JS_CompileFunction(cx, global, worker->name, argc-1, argv, 
                                          wconf->buffer, wconf->length, 
                                          wconf->filename, 
                                          wconf->starting_line_nr);
    if (wconf->func == NULL) {
      return APR_EINVAL;
    }
  }

  {
    int i;
    jsval rval;  
    JSString *str;
    JSBool ok; 
    int argc = apr_table_elts(wconf->params)->nelts; 
    jsval *jargv = apr_pcalloc(ptmp, argc * sizeof(jsval *)); 
    apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(wconf->params)->elts;

    for (i = 1; i < argc; i++) {
      const char *val = NULL;
      char *param = store_get_copy(worker->params, ptmp, e[i].key);
      val = worker_get_value_from_param(worker, param, ptmp);
      str = JS_NewStringCopyZ(cx, val);
      jargv[i-1] = STRING_TO_JSVAL(str); 
    }

    ok = JS_CallFunction(cx, global, wconf->func, argc-1, jargv, &rval);
    if (ok == JS_FALSE) {
      return APR_EINVAL;
    }
    if (apr_table_elts(wconf->retvars)->nelts && JSVAL_IS_STRING(rval)) {
	  apr_table_entry_t * e;
      str = JS_ValueToString(cx, rval);  
      e = (apr_table_entry_t *) apr_table_elts(wconf->retvars)->elts;
      store_set(worker->vars, store_get(worker->retvars, e[0].key), JS_EncodeString(cx, str));
    }
  }

  JS_DestroyContext(cx);  
  JS_DestroyRuntime(rt);  
  JS_ShutDown();

  return APR_SUCCESS;
}

/************************************************************************
 * Hooks 
 ***********************************************************************/

/**
 * Do load a js block
 * @param global IN
 * @param line INOUT line 
 * @return APR_SUCCESS
 */
static apr_status_t js_block_start(global_t *global, char **line) {
  apr_status_t status;
  if (strncmp(*line, ":JS ", 4) == 0) {
    *line += 4;
    if ((status = worker_new(&global->worker, "", "", global, 
                             block_js_interpreter)) 
        != APR_SUCCESS) {
      return status;
    }
    else {
      js_wconf_t *wconf = js_get_worker_config(global->worker);
      js_gconf_t *gconf = js_get_global_config(global);
      gconf->do_read_line = 1;
      wconf->starting_line_nr = global->line_nr + 1;
      return js_set_variable_names(global->worker, *line);
    }
  }
  return APR_ENOTIMPL;
}

/**
 * Read line of block 
 * @param global IN
 * @param line INOUT line 
 * @return APR_SUCCESS
 */
static apr_status_t js_read_line(global_t *global, char **line) {
  js_gconf_t *gconf = js_get_global_config(global);
  if (gconf->do_read_line) {
    if (*line[0] == 0) {
      *line = apr_pstrdup(global->pool, " ");
    }
    gconf->length += strlen((*line)) + 1;
  }
  return APR_SUCCESS;
}

/**
 * Do load a js block
 * @param global IN
 * @param line INOUT line 
 * @return APR_SUCCESS
 */
static apr_status_t js_block_end(global_t *global) {
  js_gconf_t *gconf = js_get_global_config(global);
  js_wconf_t *wconf = js_get_worker_config(global->worker);
  gconf->do_read_line = 0;
  wconf->filename = global->filename;
  if (gconf->length) {
    int i;
    apr_table_entry_t *e;
    char *buf;

    wconf->buffer = apr_pcalloc(global->worker->pbody, gconf->length);
    buf = wconf->buffer;
    e = (apr_table_entry_t *) apr_table_elts(global->worker->lines)->elts;
    for (i = 0; i < apr_table_elts(global->worker->lines)->nelts; i++) {
      strcpy(buf, e[i].val);
      buf += strlen(e[i].val);
      *buf = '\n';
      ++buf;
    }
    buf = 0;
    /* ignore END which is also calling this hook */
    wconf->length = gconf->length - 4;
  }
  return APR_SUCCESS;
}

/************************************************************************
 * Commands 
 ***********************************************************************/
static apr_status_t block_JS_DUMMY(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t js_module_init(global_t *global) {
  module_command_new(global, "JS", "_MODULE", "", "", NULL);
  htt_hook_block_start(js_block_start, NULL, NULL, 0);
  htt_hook_read_line(js_read_line, NULL, NULL, 0);
  htt_hook_block_end(js_block_end, NULL, NULL, 0);

  return APR_SUCCESS;
}

