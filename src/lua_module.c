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
  /** need to initialize and load it on the first call */
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
  }
  return APR_SUCCESS;
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

