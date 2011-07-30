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
 * Implementation of the HTTP Test Tool date module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

/************************************************************************
 * Commands 
 ***********************************************************************/
static apr_status_t block_DATE_DUMMY(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  return APR_SUCCESS;
}

/**
 * TIME command stores time in a variable [ms]
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN variable name 
 *
 * @return APR_SUCCESS
 */
apr_status_t block_DATE_GET_TIME(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *var = store_get(worker->params, "1");

  if (!var) {
    worker_log_error(worker, "Need a variable name to store time");
  }
  
  worker_var_set(worker, var, apr_off_t_toa(worker->pbody, apr_time_as_msec(apr_time_now())));

  return APR_SUCCESS;
}

/**
 * STRFTIME command
 *
 * @param self IN command
 * @param worker IN thread data object
 * @param data IN time [ms] "format" variable
 *
 * @return APR_SUCCESS or APR_EGENERAL on wrong parameters
 */
apr_status_t block_DATE_FORMAT(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  const char *time;
  const char *fmt;
  const char *var;
  const char *type;
  char *timefmt;
  apr_size_t len;
  apr_time_exp_t  tm;
  apr_time_t timems;

  time = store_get(worker->params, "1"); 
  fmt = store_get(worker->params, "2");
  var = store_get(worker->params, "3");
  type = store_get(worker->params, "4");

  if (!time) {
    worker_log(worker, LOG_ERR, "Time not specified");
    return APR_EGENERAL;
  }
  if (!fmt) {
    worker_log(worker, LOG_ERR, "Format not specified");
    return APR_EGENERAL;
  }
  if (!var) {
    worker_log(worker, LOG_ERR, "Variable not specified");
    return APR_EGENERAL;
  }

  timems = apr_atoi64(time);
  
  timefmt = apr_pcalloc(worker->pbody, 255);
  
  if (type && strncasecmp(type, "Local", 5) == 0) {
    if ((status = apr_time_exp_lt(&tm, timems * 1000)) != APR_SUCCESS) { 
      return status;
    }
  }
  else {
    if ((status = apr_time_exp_gmt(&tm, timems * 1000)) != APR_SUCCESS) { 
      return status;
    }
  }
  
  if ((status = apr_strftime(timefmt, &len, 254, fmt, &tm)) != APR_SUCCESS) {
    return status;
  }

  worker_var_set(worker, var, timefmt);
  
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t date_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "DATE", "_GET_TIME",
	                           "<var>",
	                           "Stores the current time [ms] into <var>",
	                           block_DATE_GET_TIME)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "DATE", "_FORMAT",
	                           "<var>",
	                           "<time> <format> <variable> [Local|GMT]",
	                           block_DATE_FORMAT)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

