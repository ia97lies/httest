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
 * Implementation of the HTTP Test Tool dso module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_dso.h>
#include "htt/dso.h"
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct dso_gconf_s {
  apr_hash_t *transport_objs;
} dso_gconf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
const char * dso_module = "dso_module";

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * Get stat config from global 
 *
 * @param global IN 
 * @return stat config
 */
static dso_gconf_t *dso_get_global_config(global_t *global) {
  dso_gconf_t *config = module_get_config(global->config, dso_module);
  if (config == NULL) {
    config = apr_pcalloc(global->pool, sizeof(*config));
    config->transport_objs = apr_hash_make(global->pool);
    module_set_config(global->config, apr_pstrdup(global->pool, dso_module), config);
  }
  return config;
}

/**
 * Get os socket descriptor
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t dso_transport_os_desc_get(void *data, int *desc) {
  return APR_ENOTIMPL;
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t dso_transport_set_timeout(void *data, apr_interval_time_t t) {
  return APR_SUCCESS;
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t dso_transport_get_timeout(void *data, apr_interval_time_t *t) {
  return APR_SUCCESS;
}

/**
 * read from socket
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t dso_transport_read(void *data, char *buf, apr_size_t *size) {
  transport_dso_t *transport_dso = data;
  return transport_dso->read(transport_dso->custom_handle(), buf, size);
}

/**
 * write to socket
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t dso_transport_write(void *data, const char *buf, apr_size_t size) {
  transport_dso_t *transport_dso = data;
  return transport_dso->write(transport_dso->custom_handle(), buf, size);
}

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Load transport object so
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary ptmp
 * @return status
 */
static apr_status_t block_LOAD_TRANSPORT_DSO(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  const char *path;
  const char *name;
  apr_dso_handle_t *dso;
  global_t *global = worker->global;
  dso_gconf_t *gconf = dso_get_global_config(global);

  if ((status = module_check_global(worker)) == APR_SUCCESS) {
    worker_log(worker, LOG_INFO, "LOAD_TRANSPORT_DSO");
    path = store_get(worker->params, "1");
    if (!path) {
      worker_log(worker, LOG_ERR, "Expect a path to shared library");
      return APR_EINVAL;
    }

    name = store_get(worker->params, "2");
    if (!name) {
      worker_log(worker, LOG_ERR, "Expect a unique name for this object");
      return APR_EINVAL;
    }

    if ((status = apr_dso_load(&dso, path, global->pool)) != APR_SUCCESS) {
      char buf[BLOCK_MAX+1];
      worker_log(worker, LOG_ERR, "Can not load \"%s\" library", path);
      apr_dso_error(dso, buf, BLOCK_MAX);
      worker_log_buf(worker, LOG_ERR, '+', buf, strlen(buf));
      return status;
    }

    apr_hash_set(gconf->transport_objs, apr_pstrdup(global->pool, name), APR_HASH_KEY_STRING, dso);
  }
  return status;
}

/**
 * Load transport object so
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary ptmp
 * @return status
 */
static apr_status_t block_GET_TRANSPORT_OBJECT(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status = APR_SUCCESS;
  const char *name;
  const char *sym;
  const char *config;
  transport_t *transport;
  apr_dso_handle_t *dso;
  apr_dso_handle_sym_t dso_sym;
  transport_dso_t *transport_dso;
  global_t *global = worker->global;
  dso_gconf_t *gconf = dso_get_global_config(global);

  name = store_get(worker->params, "1");
  if (!name) {
    worker_log(worker, LOG_ERR, "Expect name loaded share library");
    return APR_EINVAL;
  }

  if ((dso = apr_hash_get(gconf->transport_objs, name, APR_HASH_KEY_STRING)) == NULL) {
    worker_log(worker, LOG_ERR, "Requested share library not found");
    return APR_EINVAL;
  }

  sym = store_get(worker->params, "2");
  if (!sym) {
    worker_log(worker, LOG_ERR, "Expect a unique name for this object");
    return APR_EINVAL;
  }

  if ((status = apr_dso_sym(&dso_sym, dso, sym)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Can not load \"%s\" object", sym);
    return status;
  }

  transport_dso = (transport_dso_t *)dso_sym;

  config = store_get(worker->params, "3");
  if (config) {
    if ((status = transport_dso->configure(transport_dso->custom_handle(), 
                                           config)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Configure failed, see logs of your dso module");
      return status;
    }
  }

  /* build up a httest transport object */
  transport = transport_new(transport_dso, worker->pbody, 
			    dso_transport_os_desc_get, 
			    dso_transport_set_timeout,
			    dso_transport_get_timeout,
			    dso_transport_read, 
			    dso_transport_write);

  worker_get_socket(worker, name, apr_pstrcat(global->pool, "000:", sym, NULL));
  transport_register(worker->socket, transport);
  
  return status;
}

apr_status_t my_func(const char *string) {
  return APR_SUCCESS;
}

/**
 * call a dso function of type apr_status_t func(const char *string)
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary ptmp
 * @return status
 */
static apr_status_t block_FUNC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status = APR_SUCCESS;
  const char *sym;
  const char *string;
  apr_dso_handle_t *dso;
  func_dso_f func;
  apr_dso_handle_sym_t *func_sym_address = (apr_dso_handle_sym_t*)(&func);
  global_t *global = worker->global;

  sym = store_get(worker->params, "1");
  if (!sym) {
    worker_log(worker, LOG_ERR, "Expect function name");
    return APR_EINVAL;
  }

  if ((status = apr_dso_load(&dso, NULL, global->pool)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Can not load \"%s\" object", sym);
    return status;
  }

  /*Effectively fills 'func'*/
  if ((status = apr_dso_sym(func_sym_address, dso, sym)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Can not call \"%s\" object", sym);
    return status;
  }

  string= store_get(worker->params, "2");
  if (!string) {
    worker_log(worker, LOG_ERR, "Expect string to handover to function");
    return APR_EINVAL;
  }
  
  return func(string);
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t dso_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "DSO", "LOAD_TRANSPORT_DSO",
	                           "<path-to-transport-dso> <name>",
	                           "A shared library which implents an own transport object will be loaded.\n"
							   "The dso is stored with a <name>.",
	                           block_LOAD_TRANSPORT_DSO)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "DSO", "_GET_TRANSPORT_OBJECT",
	                           "<name-of-transport-dso> <symbol-name>",
	                           "Get transport object by its symbol name.",
	                           block_GET_TRANSPORT_OBJECT)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "DSO", "_FUNC",
	                           "<dso-function-to-call> <string>",
	                           "The dso function is of type \'apr_status_t func(const char *string)\'.",
	                           block_FUNC)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
}

