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
 * Implementation of the HTTP Test Tool sys module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * WHICH command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN varname
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_THREAD_GET_NUMBER(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *copy;
  char *result;
 
  copy = store_get(worker->params, "1");
 
  result  = apr_psprintf(worker->pbody, "%d", worker->which);
  worker_var_set(parent, copy, result);
  
  return APR_SUCCESS;
}

/**
 * LOCK command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_PROC_LOCK(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;

  if ((status = apr_thread_mutex_lock(worker->sync_mutex)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * UNLOCK command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN unused
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_PROC_UNLOCK(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;

  if ((status = apr_thread_mutex_unlock(worker->sync_mutex)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * PID command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN variable
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_PROC_GET_PID(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *copy = store_get(worker->params, "1");

  worker_var_set(parent, copy, apr_psprintf(worker->pbody, "%u", getpid()));
  
  return APR_SUCCESS;
}

/**
 * DETACH command to run process in background
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_PROC_DETACH(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  return apr_proc_detach(1);
}


/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t sys_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "THREAD", "_GET_NUMBER",
	                           "<var>",
	                           "Stores the number of current thread",
	                           block_THREAD_GET_NUMBER)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "PROC", "_LOCK",
	                           "",
	                           "Draws lock, for CLIENT/SERVER synchronization",
	                           block_PROC_LOCK)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "PROC", "_UNLOCK",
	                           "",
	                           "Release lock, for CLIENT/SERVER synchronization",
	                           block_PROC_UNLOCK)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "PROC", "_GET_PID",
	                           "<var>",
	                           "Store PID into a <var>",
	                           block_PROC_GET_PID)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "PROC", "_DETACH",
	                           "",
	                           "Detach process to background for daemonize",
	                           block_PROC_DETACH)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

