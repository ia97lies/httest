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
 * Implementation of the HTTP Test Tool skeleton module 
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
static apr_status_t block_STAT_DUMMY(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t stat_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "STAT", "_DUMMY",
	                           "<foo>",
	                           "Bla bla bla.",
	                           block_STAT_DUMMY)) != APR_SUCCESS) {
    /** htt_hook_read_line: GLOBAL commands */
    /** htt_hook_read_pre_headers */
    /** htt_hook_read_status_line */
    /** htt_hook_read_header */
    /** htt_hook_read_buf */
    /** htt_hook_WAIT_end */
    return status;
  }
  return APR_SUCCESS;
}

