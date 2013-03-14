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
 * Implementation of the HTTP Test Tool annotation module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

extern int success;
/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/

/************************************************************************
 * Commands 
 ***********************************************************************/
static apr_status_t block_ANNOTATION_SKIP(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  const char *value;
  const char *ref;

  if ((status = module_check_global(worker)) != APR_SUCCESS) {
    return status;
  }
  value = store_get(worker->params, "1");
  ref = store_get(worker->params, "2");

  if (value && ref && strcmp(value, ref) == 0) {
    success = 2;
    exit(2);
  }

  return APR_SUCCESS;
}

static apr_status_t block_ANNOTATION_ONLY(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  const char *value;
  const char *ref;

  if ((status = module_check_global(worker)) != APR_SUCCESS) {
    return status;
  }
  value = store_get(worker->params, "1");
  ref = store_get(worker->params, "2");

  if (!value || !ref || strcmp(value, ref) != 0) {
    success = 2;
    exit(2);
  }

  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t annotation_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "@", "SKIP",
	                           "<value> <reference>",
	                           "Skip test if value equal reference",
	                           block_ANNOTATION_SKIP)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "@", "ONLY",
	                           "<value> <reference>",
	                           "Run test only if value equal reference else skip",
	                           block_ANNOTATION_ONLY)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

