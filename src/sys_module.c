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
 * Implementation of the HTTP Test Tool sys module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * sys_module = "sys_module";
typedef struct sys_gconf_s {
  apr_thread_mutex_t *sync;
} sys_gconf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/

/**
 * Get ssl config from global 
 *
 * @param global IN global 
 * @return ssl config
 */
static sys_gconf_t *sys_get_global_config(global_t *global) {
  sys_gconf_t *config = module_get_config(global->config, sys_module);
  if (config == NULL) {
    lock(global->mutex);
    config = module_get_config(global->config, sys_module);
    if (config == NULL) {
      config = apr_pcalloc(global->pool, sizeof(*config));
      module_set_config(global->config, apr_pstrdup(global->pool, sys_module), config);
      if (apr_thread_mutex_create(&config->sync, APR_THREAD_MUTEX_DEFAULT, 
                                  global->pool) != APR_SUCCESS) {
        config = NULL;
      }
    }
    unlock(global->mutex);
  }
  return config;
}

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
  sys_gconf_t *gconf = sys_get_global_config(worker->global);

  if (gconf == NULL) {
    worker_log(worker, LOG_ERR, "Could not create lock mutex");
    return APR_EGENERAL;
  }

  if ((status = apr_thread_mutex_lock(gconf->sync)) != APR_SUCCESS) {
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
  sys_gconf_t *gconf = sys_get_global_config(worker->global);

  if (gconf == NULL) {
    worker_log(worker, LOG_ERR, "Could not create lock mutex");
    return APR_EGENERAL;
  }

  if ((status = apr_thread_mutex_unlock(gconf->sync)) != APR_SUCCESS) {
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
 * @param worker IN callee
 * @param parent IN caller
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_PROC_DETACH(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  return apr_proc_detach(1);
}

/**
 * Sleep for a given time (ms)
 *
 * @param self IN command
 * @param worker IN callee
 * @param parent IN caller
 * @param data IN 
 *
 * @return APR_SUCCESS or apr error code
 */
static apr_status_t block_SYS_SLEEP(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  const char *copy = store_get(worker->params, "1");

  if ((status = worker_flush(worker, ptmp)) != APR_SUCCESS) {
    return status;
  }

  apr_sleep(apr_atoi64(copy) * 1000);
  return APR_SUCCESS;
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
  if ((status = module_command_new(global, "SYS", "_SLEEP",
	                           "<miliseconds>", 
				   "Sleep for defined amount of time",
	                           block_SYS_SLEEP)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

