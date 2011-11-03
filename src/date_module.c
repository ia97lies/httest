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
const char * date_module = "date_module";
apr_time_t start_time;

typedef struct date_wconf_s {
  apr_time_t start_time;
} date_wconf_t;

/************************************************************************
 * Commands 
 ***********************************************************************/

/**
 * Get lua config from worker
 *
 * @param worker IN worker
 * @return lua config
 */
static date_wconf_t *date_get_worker_config(worker_t *worker) {
  date_wconf_t *config = module_get_config(worker->config, date_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    config->start_time = start_time;
    module_set_config(worker->config, apr_pstrdup(worker->pbody, date_module), config);
  }
  return config;
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
  
  worker_var_set(parent, var, apr_off_t_toa(worker->pbody, apr_time_as_msec(apr_time_now())));

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

  worker_var_set(parent, var, timefmt);
  
  return APR_SUCCESS;
}

/**
 * SYNC command
 *
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool 
 *
 * @return APR_SUCCESS
 */
apr_status_t block_DATE_SYNC(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_time_t seconds;
  apr_time_t next_full;

  const char *first = store_get(worker->params, "1"); 
  apr_time_t now = apr_time_now();

  if (!first || strcmp(first, "second") == 0) {
    seconds = apr_time_sec(now) + 1;
    next_full = apr_time_from_sec(seconds);
  }
  else if (first && strcmp(first, "minute") == 0) {
    seconds = apr_time_sec(now) + (60 - (apr_time_sec(now) % 60));
    next_full = apr_time_from_sec(seconds);
  }

  apr_sleep(next_full - now);
  
  return APR_SUCCESS;
}

/**
 * TIMER command
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool 
 * @return APR_SUCCESS
 */
apr_status_t block_DATE_TIMER(worker_t *worker, worker_t *parent, 
                              apr_pool_t *ptmp) {

  const char *cmd;
  const char *var;
  date_wconf_t *wconf = date_get_worker_config(worker);

  apr_time_t cur = apr_time_now();

  cmd = store_get(worker->params, "1");
  var = store_get(worker->params, "2");
  
  if (strcasecmp(cmd, "GET") == 0) {
    if (var && var[0] != 0) {
      worker_var_set(worker, var, 
		     apr_off_t_toa(ptmp, 
				   apr_time_as_msec(cur - wconf->start_time)));
    }
  }
  else if (strcasecmp(cmd, "RESET") == 0) {
    wconf->start_time = apr_time_now();
  }
  else {
    worker_log_error(worker, "Timer command %s not implemented", cmd);
  }
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t date_module_init(global_t *global) {
  apr_status_t status;
  start_time = apr_time_now();
  if ((status = module_command_new(global, "DATE", "_GET_TIME",
	                           "<var>",
	                           "Stores the current time [ms] into <var>",
	                           block_DATE_GET_TIME)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "DATE", "_FORMAT",
	                           "<time> <format> <variable> [Local|GMT]",
				   "Do format <time> with <format> and stores it in <variable>. "
				   "Local is default.",
	                           block_DATE_FORMAT)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "DATE", "_SYNC",
	                           "[second|minute]",
				   "Default wait the next full second. "
				   "Optional wait the next full minute.", 
	                           block_DATE_SYNC)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "DATE", "_TIMER",
	                           "GET|RESET [<variable>]",
				   "Stores time duration from last reset or from start of test.",
	                           block_DATE_TIMER)) != APR_SUCCESS) {
    return status;
  }


  return APR_SUCCESS;
}

