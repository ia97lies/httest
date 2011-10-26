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

typedef struct lua_reader_s {
  apr_pool_t *pool;
  apr_table_t *lines;
  int i;
  int newline;
} lua_reader_t;

/**
 * Get a new lua reader instance
 * @param worker IN callee
 * @param pool IN
 * @return lua reader instance
 */
static lua_reader_t *lua_new_lua_reader(worker_t *worker, apr_pool_t *pool) {
  lua_reader_t *reader = apr_pcalloc(pool, sizeof(*reader));
  reader->pool = pool;
  reader->lines = worker->lines;
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

/************************************************************************
 * Hooks 
 ***********************************************************************/
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
	apr_table_t *param_iterator= store_get_table(worker->params, ptmp);
	apr_table_entry_t *e = (apr_table_entry_t *) apr_table_elts(param_iterator)->elts;
  lua_reader_t *reader;
  lua_State *lua = lua_open();
  luaL_openlibs(lua);
  for (i = 0; i < apr_table_elts(param_iterator)->nelts; i++) {
		worker_log(worker, LOG_DEBUG, "param: %s; val: %s", e[i].key, e[i].val);
	}
  reader = lua_new_lua_reader(worker, ptmp);
  if (lua_load(lua, lua_get_line, reader, "@client") != 0) {
    const char *msg = lua_tostring(lua, -1);
    if (msg == NULL) msg = "(error object is not a string)";
    worker_log_error(worker, "Lua error: %s", msg);
    lua_pop(lua, 1);
    return APR_EGENERAL;
  }
  lua_pcall(lua, 0, LUA_MULTRET, 0);
  lua_close(lua);

  return APR_SUCCESS;
}

/**
 * Do load a lua block
 * @param global IN
 * @param line INOUT line 
 * @return APR_SUCCESS
 */
static apr_status_t lua_block_start(global_t *global, char **line) {
  apr_status_t status;
  if (strncmp(*line, "Lua:", 4) == 0) {
    *line += 4;
    if ((status = worker_new(&global->worker, "", "", global, 
                             block_lua_interpreter)) 
        != APR_SUCCESS) {
      return status;
    }
    return APR_SUCCESS;
  }
  return APR_ENOTIMPL;
}

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Do run a lua script, but with no data exchange for the moment
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN variable name 
 * @return APR_SUCCESS
 */
static apr_status_t block_LUA_RUN(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  lua_State *lua;
  const char *filename = store_get(worker->params, "1");

  if (!filename) {
    worker_log_error(worker, "Need a lua file to run");
  }

  lua = lua_open();
  luaL_openlibs(lua);
  luaL_dofile(lua, filename);
  lua_close(lua);

  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t lua_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "LUA", "_LOAD",
                                   "<file>",
                                   "Load lua <file>",
                                   block_LUA_RUN)) != APR_SUCCESS) {
    return status;
  }

  htt_hook_block_start(lua_block_start, NULL, NULL, 0);

  return APR_SUCCESS;
}

