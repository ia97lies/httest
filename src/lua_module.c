/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. 
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
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
 * Implementation of the HTTP Test Tool Lua Extention 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <lua5.1/lua.h>
#include <lua5.1/lualib.h>
#include <lua5.1/lauxlib.h>
 
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * lua_module = "lua_module";

typedef struct lua_wconf_s {
  int starting_line_nr; 
  apr_table_t *params;
  apr_table_t *retvars;
} lua_wconf_t;

typedef struct lua_gconf_s {
	int do_read_line;
} lua_gconf_t;

typedef struct lua_reader_s {
  apr_pool_t *pool;
  apr_table_t *lines;
  int i;
  int newline;
  int starting_line_nr; 
} lua_reader_t;

/************************************************************************
 * Private 
 ***********************************************************************/
/**
 * Get lua config from worker
 *
 * @param worker IN worker
 * @return lua config
 */
static lua_wconf_t *lua_get_worker_config(worker_t *worker) {
  lua_wconf_t *config = module_get_config(worker->config, lua_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    config->params = apr_table_make(worker->pbody, 5);
    config->retvars = apr_table_make(worker->pbody, 5);
    module_set_config(worker->config, apr_pstrdup(worker->pbody, lua_module), config);
  }
  return config;
}

/**
 * Get lua config from global 
 *
 * @param global IN 
 * @return lua config
 */
static lua_gconf_t *lua_get_global_config(global_t *global) {
  lua_gconf_t *config = module_get_config(global->config, lua_module);
  if (config == NULL) {
    config = apr_pcalloc(global->pool, sizeof(*config));
    module_set_config(global->config, apr_pstrdup(global->pool, lua_module), config);
  }
  return config;
}

/**
 * Get a new lua reader instance
 * @param worker IN callee
 * @param pool IN
 * @return lua reader instance
 */
static lua_reader_t *lua_new_lua_reader(worker_t *worker, apr_pool_t *pool) {
  lua_wconf_t *wconf = lua_get_worker_config(worker);
  lua_reader_t *reader = apr_pcalloc(pool, sizeof(*reader));
  reader->pool = pool;
  reader->lines = worker->lines;
  reader->starting_line_nr = wconf->starting_line_nr;
	return reader;
}

/**
 * A simple lua line reader
 * @param L in lua state
 * @param ud IN user data
 * @param size OUT len of string
 * @return line
 */
static const char *lua_get_line(lua_State *L, void *ud, size_t *size) {
  lua_reader_t *reader = ud;
  apr_table_entry_t * e;  

  e = (apr_table_entry_t *) apr_table_elts(reader->lines)->elts;
  if (reader->starting_line_nr) {
    --reader->starting_line_nr;
    *size = 1;
    return apr_pstrdup(reader->pool, "\n");
  }
  if (reader->i < apr_table_elts(reader->lines)->nelts) {
    if (reader->newline) {
      reader->newline = 0;
      *size = 1;
      return apr_pstrdup(reader->pool, "\n");
    }
    else {
      const char *line = e[reader->i].val;
      *size = strlen(line);
      ++reader->i;
      reader->newline = 1;
      return line;    
    }
  }
  else {
    return NULL;    
  }
}

/**
 * This is test function
 * @param lua IN lua state
 * @return 0
 */
static int lua_foo(lua_State *lua) {
  worker_t *worker;

  lua_getfield(lua, LUA_REGISTRYINDEX, "htt_worker");
  worker = lua_touserdata(lua, 1);
  fprintf(stderr, "\nXXX foo %p\n", worker);
  return 0;
}

/**
 * Do push the httest version on the stack
 * @param lua IN lua state
 * @return 1
 */
static int lua_version(lua_State *lua) {
  lua_pushstring(lua, PACKAGE_VERSION);
  return 1;
}

/**
 * Receive a HTTP request/response and push status, headers, body, error on
 * the stack.
 * @param lua IN lua state
 * @return 4
 * @TODO: behavour on error, the order on stack would be better the other way 
 *        around.
 */
static int lua_wait(lua_State *lua) {
  apr_status_t status;
  worker_t *worker;
  apr_pool_t *ptmp;
  char *line;
  char *buf;
  sockreader_t *sockreader;
  char *last;
  char *key;
  const char *val = "";
  apr_size_t len;
  apr_ssize_t recv_len = -1;
  apr_size_t peeklen;
  int i;

  buf = NULL;
  len = 0;

  lua_getfield(lua, LUA_REGISTRYINDEX, "htt_worker");
  worker = lua_touserdata(lua, 1);
  apr_pool_create(&ptmp, worker->heartbeat);

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  if (worker->sockreader == NULL) {
    peeklen = worker->socket->peeklen;
    worker->socket->peeklen = 0;
    if ((status = sockreader_new(&sockreader, worker->socket->transport, worker->socket->peek, peeklen, ptmp)) 
        != APR_SUCCESS) {
      luaL_error(lua, "Could not get buffered socket reader");
      return 1;
    }
  }
  else {
    sockreader = worker->sockreader;
  }

  if (worker->headers) {
    apr_table_clear(worker->headers);
  }
  else {
    worker->headers = apr_table_make(worker->pbody, 5);
  }
  
  /** Status line, make that a little fuzzy in reading trailing empty lines of last
   *  request */
  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && line[0] == 0);
  if (line[0] != 0) { 
    lua_pushstring(lua, line);
    if (!strstr(line, "HTTP/") && !strstr(line, "ICAP/")) {
      worker_log(worker, LOG_DEBUG, "Not HTTP or ICAP version in \"%s\", must be HTTP/0.9", line); 
      apr_table_add(worker->headers, "Connection", "close");
      status = sockreader_push_line(sockreader, line);
      goto http_0_9;
    }
  }
  else {
    if (line[0] == 0) {
      luaL_error(lua, "No status line received");
      return 1;
    }
    else {
      luaL_error(lua, "Network error");
      return 1;
    }
  }
 
  /** get headers */
  lua_newtable(lua);
  i = 1;
  while ((status = sockreader_read_line(sockreader, &line)) == APR_SUCCESS && 
         line[0] != 0) {
    char *value;
    /* headers */
    key = apr_strtok(line, ":", &last);
    apr_collapse_spaces(key, key);
    value = last;
    apr_collapse_spaces(value, value);
    lua_pushstring(lua, key);
    lua_pushstring(lua, value);
    lua_settable(lua, -3);
    apr_table_add(worker->headers, key, value);
  }

http_0_9:
  if (status == APR_SUCCESS) {
    /* if recv len is specified use this */
    if (recv_len > 0) {
      len = recv_len;
      if ((status = content_length_reader(sockreader, &buf, &len, "")) 
          != APR_SUCCESS) {
        luaL_error(lua, "Failed to read after %d bytes", len);
        return 1;
      }
    }
    else if (recv_len == 0) {
      buf = NULL; 
    }
    /* else get transfer type */
    else if ((val = apr_table_get(worker->headers, "Content-Length"))) {
      len = apr_atoi64(val);
      if ((status = worker_check_error(worker, content_length_reader(sockreader, &buf, &len, val))) 
          != APR_SUCCESS) {
        luaL_error(lua, "Failed to read content-length body after %d bytes", len);
        return 1;
      }
    }
    else if ((val = apr_table_get(worker->headers, "Transfer-Encoding"))) {
      if ((status = worker_check_error(worker, transfer_enc_reader(sockreader, &buf, &len, val))) 
          != APR_SUCCESS) {
        luaL_error(lua, "Failed to read chunked encoding body after %d bytes", len);
        return 1;
      }
    }
    else if ((val = apr_table_get(worker->headers, "Encapsulated"))) {
      if ((status = worker_check_error(worker, encapsulated_reader(sockreader, &buf, &len, val, apr_table_get(worker->headers, "Preview"))))
          != APR_SUCCESS) {
        luaL_error(lua, "Failed to read encapsulated body after %d bytes", len);
        return 1;
      }
    }
    else if (worker->flags & FLAGS_CLIENT && 
	     (val = apr_table_get(worker->headers, "Connection"))) {
      if ((status = worker_check_error(worker, eof_reader(sockreader, &buf, &len, val))) != APR_SUCCESS) {
        luaL_error(lua, "Failed to read until eof after %d bytes", len);
        return 1;
      }
    }
    
    lua_pushlstring(lua, buf, len); 

    if (worker->flags & FLAGS_AUTO_CLOSE) {
      val = apr_table_get(worker->headers, "Connection");
      if (val && strcasecmp(val, "close") == 0) {
        command_CLOSE(NULL, worker, "do not test expects", ptmp);
      }
    }
  }

  apr_pool_destroy(ptmp);
  return 3;
}

static apr_status_t lua_send(lua_State *lua) {
  const char *line;
  worker_t *worker;

  line = lua_tostring(lua, -1);
  lua_pop(lua, 1);

  lua_getfield(lua, LUA_REGISTRYINDEX, "htt_worker");
  worker = lua_touserdata(lua, 1);

  if (!worker->socket) {
    luaL_error(lua, "Failed to send line, no socket available");
    return 1;
  }
    
  if (strncasecmp(line, "Content-Length: AUTO", 20) == 0) {
    apr_table_add(worker->cache, "Content-Length", "Content-Length");
  }
  else if (strncasecmp(line, "Encapsulated: ", 14) == 0 && strstr(line, "AUTO")) {
    apr_table_add(worker->cache, "Encapsulated", line);
  }
  else if (strncasecmp(line, "Expect: 100-Continue", 20) == 0) {
    apr_table_add(worker->cache, "100-Continue", line);
  }
  else {
    apr_table_add(worker->cache, "PLAIN", line);
  }

  return 0;
}

static const struct luaL_Reg httlib[] = {
  {"foo", lua_foo},
  {"version", lua_version},
  {"wait", lua_wait},
  {"send", lua_send},
  {NULL, NULL}
};

/**
 * Simple lua interpreter for lua block
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temp pool for this function
 * @return apr status
 */
static apr_status_t block_lua_interpreter(worker_t *worker, worker_t *parent, 
                                          apr_pool_t *ptmp) {
	int i;
  apr_table_entry_t *e; 
  lua_reader_t *reader;

  lua_wconf_t *config = lua_get_worker_config(worker);
  lua_State *lua = lua_open();

  luaL_openlibs(lua);
  e = (apr_table_entry_t *) apr_table_elts(config->params)->elts;
  for (i = 1; i < apr_table_elts(config->params)->nelts; i++) {
    const char *val = NULL;
    char *param = store_get_copy(worker->params, ptmp, e[i].key);
    if (strncmp(param, "VAR(", 4) == 0) {
      char *var = param + 4;
      apr_size_t len = strlen(var);
      if (len > 0) {
        var[len-1] = 0;
      }
      val = store_get(worker->vars, var);
      if (!val) {
        val = store_get(worker->locals, var);
      }
      if (!val) {
        val = param;
      }
      }
      else {
        val = param;
      }
    lua_pushstring(lua, val);
    lua_setglobal(lua, e[i].key);
  }
  lua_pushlightuserdata(lua, worker);
  lua_setfield(lua, LUA_REGISTRYINDEX, "htt_worker");
  luaL_register(lua, "htt", httlib);
  reader = lua_new_lua_reader(worker, ptmp);
  if (lua_load(lua, lua_get_line, reader, "@client") != 0 ||
      lua_pcall(lua, 0, LUA_MULTRET, 0) != 0) {
    const char *msg = lua_tostring(lua, -1);
    if (msg == NULL) msg = "(error object is not a string)";
    worker_log_error(worker, "Lua error: %s", msg);
    lua_pop(lua, 1);
    return APR_EGENERAL;
  }
  e = (apr_table_entry_t *) apr_table_elts(config->retvars)->elts;
  for (i = 0; i < apr_table_elts(config->retvars)->nelts; i++) {
    worker_log(worker, LOG_DEBUG, "param: %s; val: %s", e[i].key, e[i].val);
    if (lua_isstring(lua, i + 2)) {
      store_set(worker->vars, store_get(worker->retvars, e[i].key), lua_tostring(lua, i + 2));
    }
  }
  
  lua_close(lua);

  return APR_SUCCESS;
}

/**
 * Get variable names for in/out for mapping it to/from lua
 * @param worker IN callee
 * @param line IN command line
 */
static void lua_set_variable_names(worker_t *worker, char *line) {
  char *token;
  char *last;

  int input = 1;
  lua_wconf_t *config = lua_get_worker_config(worker);
  char *data = apr_pstrdup(worker->pbody, line);
 
  /* Get params and returns variable names for later mapping from/to lua */
  token = apr_strtok(data, " ", &last);
  while (token) {
    if (strcmp(token, ":") == 0) {
      /* : is separator between input and output vars */
      input = 0;
    }
    else {
      if (input) {
        apr_table_setn(config->params, token, token);
      }
      else {
        apr_table_setn(config->retvars, token, token);
      }
    }
    token = apr_strtok(NULL, " ", &last);
  }
}

/************************************************************************
 * Hooks 
 ***********************************************************************/

/**
 * Do load a lua block
 * @param global IN
 * @param line INOUT line 
 * @return APR_SUCCESS
 */
static apr_status_t lua_block_start(global_t *global, char **line) {
  apr_status_t status;
  if (strncmp(*line, ":LUA ", 5) == 0) {
    lua_wconf_t *wconf;
    lua_gconf_t *gconf = lua_get_global_config(global);
    gconf->do_read_line = 1;
    *line += 5;
    if ((status = worker_new(&global->worker, "", "", global, 
                             block_lua_interpreter)) 
        != APR_SUCCESS) {
      return status;
    }
    wconf = lua_get_worker_config(global->worker);
    wconf->starting_line_nr = global->line_nr;
    lua_set_variable_names(global->worker, *line);
    return APR_SUCCESS;
  }
  return APR_ENOTIMPL;
}

/**
 * Read line of block 
 * @param global IN
 * @param line INOUT line 
 * @return APR_SUCCESS
 */
static apr_status_t lua_read_line(global_t *global, char **line) {
  lua_gconf_t *gconf = lua_get_global_config(global);
  if (gconf->do_read_line) {
    if (*line[0] == 0) {
      *line = apr_pstrdup(global->pool, " ");
    }
  }
  return APR_SUCCESS;
}

/**
 * Do load a lua block
 * @param global IN
 * @param line INOUT line 
 * @return APR_SUCCESS
 */
static apr_status_t lua_block_end(global_t *global) {
  lua_gconf_t *gconf = lua_get_global_config(global);
  gconf->do_read_line = 0;
  return APR_SUCCESS;
}

/************************************************************************
 * Commands 
 ***********************************************************************/

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t lua_module_init(global_t *global) {
  htt_hook_block_start(lua_block_start, NULL, NULL, 0);
  htt_hook_read_line(lua_read_line, NULL, NULL, 0);
  htt_hook_block_end(lua_block_end, NULL, NULL, 0);

  return APR_SUCCESS;
}

