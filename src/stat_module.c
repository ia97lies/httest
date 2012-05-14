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
typedef struct stat_time_s {
  apr_time_t min;
  apr_time_t avr;
  apr_time_t max;
  apr_time_t total;
} stat_time_t;

typedef struct stat_s {
  int sent_reqs;
  apr_size_t recv_bytes;
  apr_size_t sent_bytes;
  stat_time_t recv_time;
  stat_time_t sent_time;
  apr_time_t sent_time_total;
} stat_t;

typedef struct stat_wconf_s {
  apr_time_t start_time;
  stat_t stat;
} stat_wconf_t;

typedef struct stat_gconf_s {
  int on;
  stat_t stat;
} stat_gconf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
const char * stat_module = "stat_module";

/************************************************************************
 * Local 
 ***********************************************************************/

/**
 * Get stat config from global 
 *
 * @param global IN 
 * @return stat config
 */
static stat_gconf_t *stat_get_global_config(global_t *global) {
  stat_gconf_t *config = module_get_config(global->config, stat_module);
  if (config == NULL) {
    config = apr_pcalloc(global->pool, sizeof(*config));
    module_set_config(global->config, apr_pstrdup(global->pool, stat_module), config);
  }
  return config;
}

/**
 * Get stat config from worker
 *
 * @param worker IN worker
 * @return stat config
 */
static stat_wconf_t *stat_get_worker_config(worker_t *worker) {
  stat_wconf_t *config = module_get_config(worker->config, stat_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, apr_pstrdup(worker->pbody, stat_module), config);
  }
  return config;
}

/**
 * Test if statistic is turned on 
 * @param global IN global config
 * @param line IN read line
 */
static apr_status_t stat_read_line(global_t *global, char **line) {
  if (strncmp(*line, "STAT:ON", 7) == 0) {
    stat_gconf_t *gconf = stat_get_global_config(global);
    gconf->on = 1;
  }
  return APR_SUCCESS;
}

/**
 * Is called after line is sent
 * @param worker IN callee
 * @param line IN line sent
 * @return APR_SUCCESS
 */
static apr_status_t stat_line_sent(worker_t *worker, line_t *line) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on) {
    if (wconf->start_time == 0) {
      wconf->start_time = apr_time_now();
    }
    wconf->stat.sent_bytes += line->len;
    if (strncmp(line->info, "NOCRLF", 6) != 0) {
      wconf->stat.sent_bytes += 2;
    }
  }
  return APR_SUCCESS;
}

/**
 * Is before request receive
 * @param worker IN callee
 * @param line IN line sent
 * @return APR_SUCCESS
 */
static apr_status_t stat_read_pre_headers(worker_t *worker) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on && worker->flags & FLAGS_CLIENT) {
    apr_time_t now = apr_time_now();
    apr_time_t duration = now - wconf->start_time;
    wconf->start_time = now;
    wconf->stat.sent_time_total += duration;
    ++wconf->stat.sent_reqs;
    if (duration > wconf->stat.sent_time.max) {
      wconf->stat.sent_time.max = duration;
    }
    if (duration < wconf->stat.sent_time.min) {
      wconf->stat.sent_time.min = duration;
    }
  }
  return APR_SUCCESS;
}

/**
 * Get status line to count 200, 302, 400 and 500 errors 
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_read_status_line(worker_t *worker, char *status_line) {
  return APR_SUCCESS;
}

/**
 * Measure response time
 * @param worker IN callee
 * @param status IN apr status
 * @return received status 
 */
static apr_status_t stat_WAIT_end(worker_t *worker, apr_status_t status) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on && worker->flags & FLAGS_CLIENT) {
    apr_time_t now = apr_time_now();
    apr_time_t duration = now - wconf->start_time;
    wconf->start_time = 0;
    wconf->stat.recv_time.total += duration;
    ++wconf->stat.sent_reqs;
    if (duration > wconf->stat.recv_time.max) {
      wconf->stat.recv_time.max = duration;
    }
    if (duration < wconf->stat.recv_time.min) {
      wconf->stat.recv_time.min = duration;
    }
  }
  return status;
}

/**
 * Collect all data and store it in global
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_worker_finally(worker_t *worker) {
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(worker->global);
  if (gconf->on && worker->flags & FLAGS_CLIENT) {
    apr_thread_mutex_lock(worker->mutex);
    if (wconf->stat.sent_time.max > gconf->stat.sent_time.max) {
      gconf->stat.sent_time.max = wconf->stat.sent_time.max;
    }
    if (wconf->stat.recv_time.max > gconf->stat.recv_time.max) {
      gconf->stat.recv_time.max = wconf->stat.recv_time.max;
    }
    if (wconf->stat.sent_time.min < gconf->stat.sent_time.min) {
      gconf->stat.sent_time.min = wconf->stat.sent_time.min;
    }
    if (wconf->stat.recv_time.min < gconf->stat.recv_time.min) {
      gconf->stat.recv_time.min = wconf->stat.recv_time.min;
    }
    gconf->stat.sent_time_total += wconf->stat.sent_time_total;
    gconf->stat.recv_time.total += wconf->stat.recv_time.total;
    gconf->stat.sent_reqs += wconf->stat.sent_reqs;
    apr_thread_mutex_unlock(worker->mutex);
  }
  return APR_SUCCESS;
}

/**
 * Display collected data
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_worker_joined(global_t *global) {
  stat_gconf_t *gconf = stat_get_global_config(global);
  if (gconf->on) {
    gconf->stat.recv_time.avr = gconf->stat.recv_time.total/gconf->stat.sent_reqs;
    gconf->stat.sent_time.avr = gconf->stat.sent_time_total/gconf->stat.sent_reqs;
  }
  return APR_SUCCESS;
}

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
    return status;
  }
  htt_hook_worker_joined(stat_worker_joined, NULL, NULL, 0);
  htt_hook_worker_finally(stat_worker_finally, NULL, NULL, 0);
  htt_hook_WAIT_end(stat_WAIT_end, NULL, NULL, 0);
  htt_hook_read_status_line(stat_read_status_line, NULL, NULL, 0);
  htt_hook_read_pre_headers(stat_read_pre_headers, NULL, NULL, 0);
  htt_hook_read_line(stat_read_line, NULL, NULL, 0);
  return APR_SUCCESS;
}

