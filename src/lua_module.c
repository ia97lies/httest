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
 * Implementation of the HTTP Test Tool Lua Extention 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#define LUA_COMPAT_MODULE
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <apr_sha1.h>

#include "lua_crypto.h"
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
 * @return lua worker config
 */
static lua_wconf_t *lua_get_worker_config(worker_t *worker) {
  lua_wconf_t *wconf = module_get_config(worker->config, lua_module);
  if (wconf == NULL) {
    wconf = apr_pcalloc(worker->pbody, sizeof(*wconf));
    wconf->params = apr_table_make(worker->pbody, 5);
    wconf->retvars = apr_table_make(worker->pbody, 5);
    module_set_config(worker->config, apr_pstrdup(worker->pbody, lua_module), wconf);
  }
  return wconf;
}

/**
 * Get lua config from global 
 *
 * @param global IN 
 * @return lua config
 */
static lua_gconf_t *lua_get_global_config(global_t *global) {
  lua_gconf_t *gconf = module_get_config(global->config, lua_module);
  if (gconf == NULL) {
    gconf = apr_pcalloc(global->pool, sizeof(*gconf));
    module_set_config(global->config, apr_pstrdup(global->pool, lua_module), gconf);
  }
  return gconf;
}

/**
 * Get a new lua reader instance
 * @param worker IN callee
 * @param pool IN
 * @return lua reader instance
 */
static lua_reader_t *lua_new_lua_reader(worker_t *worker, apr_pool_t *pool) {
  lua_wconf_t *wconf = lua_get_worker_config(worker->block);
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
 * Do push the httest version on the stack
 * @lua_return version as a string
 * @param L IN lua state
 * @return 1
 */
static int luam_version(lua_State *L) {
  lua_pushstring(L, PACKAGE_VERSION);
  return 1;
}

/**
 * Execute httest script.
 * @param L IN lua state
 * @return 0
 */
static int luam_interpret(lua_State *L) {
  apr_status_t status;
  apr_pool_t *ptmp;
  worker_t *worker;
  worker_t *parent;
  worker_t *call;
  const char *string;
  apr_table_t *lines;
  char *buffer;
  char *last;
  char *line;
  apr_size_t len;

  if (!lua_isstring(L, -1)) {
    luaL_error(L, "Expect a string to interpret");
    return 1;
  }

  string = lua_tolstring(L, -1, &len);
  lua_pop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, "htt_worker");
  worker = lua_touserdata(L, 1);
  lua_pop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, "htt_parent");
  parent = lua_touserdata(L, 1);
  lua_pop(L, 1);

  apr_pool_create(&ptmp, worker->heartbeat);

  lines = apr_table_make(ptmp, 5);

  call = apr_pcalloc(ptmp, sizeof(*call));
  memcpy(call, worker, sizeof(*call));

  buffer = apr_pcalloc(ptmp, len+1);
  memcpy(buffer, string, len);

  line = apr_strtok(buffer, "\n", &last);
  while (line) {
    while (*line == ' ') { ++line ; }
    if (*line != '\0') {
      apr_table_add(lines, "lua inline", line);
    }
    line = apr_strtok(NULL, "\n", &last);
  }

  call->lines = lines;
  call->interpret = parent->interpret;

  if ((status = call->interpret(call, worker, ptmp)) != APR_SUCCESS) {
    luaL_error(L, "Error: %s(%d)", my_status_str(ptmp, status), status);
    return 1;
  }

  return 0;
}

/**
 * Get variable from httest
 * @param L IN lua state
 * @return 0
 */
static int luam_getvar(lua_State *L) {
  worker_t *worker;
  const char *val;

  const char *var = lua_tostring(L, -1);

  lua_pop(L, 1);

  lua_getfield(L, LUA_REGISTRYINDEX, "htt_worker");
  worker = lua_touserdata(L, 1);
 
  if ((val = worker_var_get(worker, var))) {
    lua_pushstring(L, val);
    return 1;
  }

  return 0;
}

/**
 * Get transport object.
 * @param L IN lua state
 * @return 0
 */
static int luam_transport_get(lua_State *L) {
  worker_t *worker;

  lua_getfield(L, LUA_REGISTRYINDEX, "htt_worker");
  worker = lua_touserdata(L, 1);

  if (!worker->socket || !worker->socket->transport) {
    lua_pushnil(L);
    return 1;
  }

  lua_pushlightuserdata(L, worker->socket->transport);
    
  luaL_getmetatable(L, "htt.transport");
  lua_setmetatable(L, -2);
    
  return 1;
}

/**
 * Get transport object.
 * @param L IN lua state
 * @return 0
 */
static transport_t *lua_checktransport (lua_State *L) {
  void *ud = luaL_checkudata(L, 1, "htt.transport");
  luaL_argcheck(L, ud != NULL, 1, "`transport' expected");
  return (transport_t *)ud;
}

/**
 * Transport read method
 * @param L IN lua state
 * @return 0
 */
static int luam_transport_read(lua_State *L) {
  if (lua_isnumber(L, -1)) {
    apr_status_t status;
    apr_pool_t *pool;
    apr_size_t bytes;
    transport_t *transport;
    char *buffer;

    bytes = lua_tointeger(L, -1);
    transport = lua_checktransport(L);
    apr_pool_create(&pool, NULL);
    buffer = apr_pcalloc(pool, bytes);
    if ((status = transport_read(transport, buffer, &bytes)) != APR_SUCCESS) {
      lua_pushnil(L);
      apr_pool_destroy(pool);
      return 1;
    }
    lua_pushlstring(L, buffer, bytes);
    apr_pool_destroy(pool);
    return 1;
  }
  else {
    luaL_error(L, "Expect number of bytes");
    return 1;
  }
}

/**
 * Transport write method
 * @param L IN lua state
 * @return 0
 */
static int luam_transport_write(lua_State *L) {
  if (lua_isstring(L, -1)) {
    apr_status_t status;
    apr_size_t bytes;
    const char *buffer = lua_tolstring(L, -1, &bytes);
    transport_t *transport = lua_checktransport(L);
    if ((status = transport_write(transport, buffer, bytes)) != APR_SUCCESS) {
      luaL_error(L, "Could not write %d bytes", bytes);
      return 1;
    }
  }
  return 0;
}

/**
 * Transport set timeout method
 * @param L IN lua state
 * @return 0
 */
static int luam_transport_set_timeout(lua_State *L) {
  if (lua_isnumber(L, -1)) {
    apr_status_t status;
    apr_interval_time_t tmo = lua_tointeger(L, -1);
    transport_t *transport = lua_checktransport(L);
    if ((status = transport_set_timeout(transport, tmo * 1000)) != APR_SUCCESS) {
      luaL_error(L, "Could not timeout %d ms", tmo);
      return 1;
    }
  }
  return 0;
}

/**
 * Transport get timeout method
 * @param L IN lua state
 * @return 1
 */
static int luam_transport_get_timeout(lua_State *L) {
  apr_status_t status;
  apr_interval_time_t tmo;
  transport_t *transport = lua_checktransport(L);
  if ((status = transport_get_timeout(transport, &tmo)) != APR_SUCCESS) {
    luaL_error(L, "Could not get timeout");
    return 1;
  }
  else {
    lua_pushinteger(L, tmo/1000);
    return 1;
  }
}

/**
 * Set of htt commands for lua
 */
static const struct luaL_Reg htt_lib_f[] = {
  {"version", luam_version},
  {"interpret", luam_interpret},
  {"getVar", luam_getvar},
  {"getTransport", luam_transport_get},
  {NULL, NULL}
};

static const struct luaL_Reg htt_transport_m[] = {
  {"read", luam_transport_read},
  {"write", luam_transport_write},
  {"setTimeout", luam_transport_set_timeout},
  {"getTimeout", luam_transport_get_timeout},
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
  int failed;
  int i;
  apr_table_entry_t *e; 
  lua_reader_t *reader;

  lua_wconf_t *wconf = lua_get_worker_config(worker->block);
  lua_State *L = luaL_newstate();

  luaL_openlibs(L);
  e = (apr_table_entry_t *) apr_table_elts(wconf->params)->elts;
  for (i = 1; i < apr_table_elts(wconf->params)->nelts; i++) {
    const char *val = NULL;
    char *param = store_get_copy(worker->params, ptmp, e[i].key);
    val = worker_get_value_from_param(worker, param, ptmp);
    lua_pushstring(L, val);
    lua_setglobal(L, e[i].key);
  }
  luaopen_crypto(L);
  lua_pushlightuserdata(L, parent);
  lua_setfield(L, LUA_REGISTRYINDEX, "htt_parent");
  lua_pushlightuserdata(L, worker);
  lua_setfield(L, LUA_REGISTRYINDEX, "htt_worker");
  luaL_newmetatable(L, "htt.transport");
  lua_pushvalue(L, -1);  /* pushes the metatable */
  lua_setfield(L, -2, "__index");  /* metatable.__index = metatable */
  luaL_register(L, NULL, htt_transport_m);
  luaL_register(L, "htt", htt_lib_f);
  lua_pop(L, -1);
  lua_pop(L, -1);
  reader = lua_new_lua_reader(worker, ptmp);
#if ( LUA_VERSION_NUM == 501 )		
  failed = (lua_load(L, lua_get_line, reader, "@client") != 0 || 
            lua_pcall(L, 0, LUA_MULTRET, 0) != 0);
#elif ( LUA_VERSION_NUM  == 502 )
  failed = (lua_load(L, lua_get_line, reader, "@client", NULL) != 0 || 
            lua_pcall(L, 0, LUA_MULTRET, 0) != 0);
#else
  #error this lua version is not supported
#endif
  if (failed) {
    const char *msg = lua_tostring(L, -1);
    if (msg == NULL) {
      msg = "(error object is not a string)";
    }
    worker_log_error(worker, "Lua error: %s", msg);
    lua_pop(L, 1);
    return APR_EGENERAL;
  }
  e = (apr_table_entry_t *) apr_table_elts(wconf->retvars)->elts;
  for (i = 0; i < apr_table_elts(wconf->retvars)->nelts; i++) {
    worker_log(worker, LOG_DEBUG, "param: %s; val: %s", e[i].key, e[i].val);
    if (lua_isstring(L, i + 1)) {
      store_set(worker->vars, store_get(worker->retvars, e[i].key), lua_tostring(L, i + 1));
    }
  }
  
  lua_close(L);

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
  lua_wconf_t *wconf = lua_get_worker_config(worker);
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
        apr_table_setn(wconf->params, token, token);
      }
      else {
        apr_table_setn(wconf->retvars, token, token);
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
    if ((status = worker_new(&global->cur_worker, "", "", global, 
                             block_lua_interpreter)) 
        != APR_SUCCESS) {
      return status;
    }
    wconf = lua_get_worker_config(global->cur_worker);
    wconf->starting_line_nr = global->line_nr;
    lua_set_variable_names(global->cur_worker, *line);
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
/**
 * _LUA:CALL
 * @param worker IN thread data object
 * @param data IN
 * @return APR_SUCCESS or APR_EGENERAL
 */
static apr_status_t block_LUA_CALL(worker_t * worker, worker_t *parent,
                                   apr_pool_t *ptmp) {
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t lua_module_init(global_t *global) {
  apr_status_t status;
  module_command_new(global, "LUA", "_MODULE", "", "", NULL);

  if ((status = module_command_new(global, "LUA", "_CALL", "<lua-function> <args>",
	                           "Call a lua function loaded by BLOCK:LUA",
	                           block_LUA_CALL)) != APR_SUCCESS) {
    return status;
  }

  htt_hook_block_start(lua_block_start, NULL, NULL, 0);
  htt_hook_read_line(lua_read_line, NULL, NULL, 0);
  htt_hook_block_end(lua_block_end, NULL, NULL, 0);

  return APR_SUCCESS;
}

