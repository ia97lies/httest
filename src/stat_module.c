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
  apr_time_t cur;
  apr_time_t min;
  apr_time_t avr;
  apr_time_t max;
  apr_time_t total;
} stat_time_t;

typedef struct stat_count_s {
  int reqs;
  int conns;
  int less[10];
  int status[600];
} stat_count_t;

typedef struct stat_s {
  stat_count_t count;
  apr_size_t recv_bytes;
  apr_size_t sent_bytes;
  stat_time_t conn_time;
  stat_time_t recv_time;
  stat_time_t sent_time;
  apr_time_t sent_time_total;
} stat_t;

typedef struct stat_wconf_s {
  apr_time_t start_time;
  int cur_status;
  const char *request_line;
  stat_t stat;
} stat_wconf_t;

typedef struct stat_gconf_s {
  int on;
#define STAT_GCONF_OFF 0
#define STAT_GCONF_ON  1
#define STAT_GCONF_LOG 2 
  apr_file_t *log_file;
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

  if (strncmp(*line, "STAT:", 5) == 0) {
    char *cur;
    char *last;

    apr_strtok(*line, ":", &last);
    cur = apr_strtok(NULL, ":", &last);
    if (strcmp(cur, "ON") == 0) {
      stat_gconf_t *gconf = stat_get_global_config(global);
      gconf->on = STAT_GCONF_ON;
    }
    else if (strcmp(cur, "OFF") == 0) {
      stat_gconf_t *gconf = stat_get_global_config(global);
      gconf->on |= STAT_GCONF_OFF;
    }
    else if (strncmp(cur, "LOG ", 4) == 0) {
      apr_status_t status;
      char *filename;
      stat_gconf_t *gconf = stat_get_global_config(global);
      gconf->on |= STAT_GCONF_LOG;
      apr_strtok(cur, " ", &last);
      filename = apr_strtok(NULL, " ", &last);
      if ((status = apr_file_open(&gconf->log_file, filename, 
                                  APR_READ|APR_WRITE|APR_CREATE|APR_APPEND|APR_XTHREAD, 
                                  APR_OS_DEFAULT, global->pool)) != APR_SUCCESS) {
        fprintf(stderr, "Could not open log file \"%s\"", filename);
        return status;
      }
    }
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

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    if (wconf->start_time == 0) {
      ++wconf->stat.count.reqs;
      wconf->start_time = apr_time_now();
      wconf->request_line = line->buf;
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
static apr_status_t stat_WAIT_begin(worker_t *worker) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    apr_time_t now = apr_time_now();
    apr_time_t duration = now - wconf->start_time;
    wconf->start_time = now;
    wconf->stat.sent_time.cur = duration;
    wconf->stat.sent_time_total += duration;
    if (duration > wconf->stat.sent_time.max) {
      wconf->stat.sent_time.max = duration;
    }
    if (duration < wconf->stat.sent_time.min || wconf->stat.sent_time.min == 0) {
      wconf->stat.sent_time.min = duration;
    }
  }
  return APR_SUCCESS;
}

/**
 * Get status line length and count 200, 302, 400 and 500 errors 
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_read_status_line(worker_t *worker, char *line) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    char *cur;
    wconf->stat.recv_bytes += strlen(line) + 2;
    if ((cur = strstr(line, " "))) {
      int status;
      ++cur;
      status = apr_atoi64(cur);
      ++wconf->stat.count.status[status];
      wconf->cur_status = status;
    }

  }   
  return APR_SUCCESS;
}

/**
 * Get line length
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_read_header(worker_t *worker, char *line) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    wconf->stat.recv_bytes += strlen(line) + 2;
  }   
  return APR_SUCCESS;
}

/**
 * Get buf length
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_read_buf(worker_t *worker, char *buf, apr_size_t len) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    wconf->stat.recv_bytes += len + 2;
  }   
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

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    int i;
    apr_time_t compare;
    apr_time_t now = apr_time_now();
    apr_time_t duration = now - wconf->start_time;
    wconf->start_time = 0;
    wconf->stat.recv_time.cur = duration;
    wconf->stat.recv_time.total += duration;
    if (duration > wconf->stat.recv_time.max) {
      wconf->stat.recv_time.max = duration;
    }
    if (duration < wconf->stat.recv_time.min || wconf->stat.recv_time.min == 0) {
      wconf->stat.recv_time.min = duration;
    }
    for (i = 0, compare = 1; i < 10; i++, compare *= 2) {
      apr_time_t t = apr_time_sec(wconf->stat.sent_time.cur + wconf->stat.recv_time.cur);
      if (t < compare) {
        ++wconf->stat.count.less[i];
        break;
      }
    }
  }
  if (gconf->on & STAT_GCONF_LOG && worker->flags & FLAGS_CLIENT) {
    apr_pool_t *pool;
    char *date_str;

    apr_pool_create(&pool, NULL);
    date_str = apr_palloc(pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(date_str, apr_time_now());
    apr_file_printf(gconf->log_file, "[%s] \"%s\" %d %"APR_TIME_T_FMT" %"APR_TIME_T_FMT"\n", 
                    date_str,  wconf->request_line, wconf->cur_status, 
                    wconf->stat.sent_time.cur, wconf->stat.recv_time.cur);
    apr_pool_destroy(pool);
  }
  return status;
}

/**
 * Start connect timer
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_pre_connect(worker_t *worker) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    wconf->stat.conn_time.cur = apr_time_now();
    ++wconf->stat.count.conns;
  }
  return APR_SUCCESS;
}

/**
 * Stop connect timer and measure connection time
 * @param worker IN callee
 * @param line IN received status line
 * @return APR_SUCCESS
 */
static apr_status_t stat_post_connect(worker_t *worker) {
  global_t *global = worker->global;
  stat_wconf_t *wconf = stat_get_worker_config(worker);
  stat_gconf_t *gconf = stat_get_global_config(global);

  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    apr_time_t duration = apr_time_now() - wconf->stat.conn_time.cur;
    wconf->stat.conn_time.cur = duration;
    wconf->stat.conn_time.total += duration;
    if (duration > wconf->stat.conn_time.max) {
      wconf->stat.conn_time.max = duration;
    }
    if (duration < wconf->stat.conn_time.min || wconf->stat.conn_time.min == 0) {
      wconf->stat.conn_time.min = duration;
    }

  }
  return APR_SUCCESS;
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
  if (gconf->on & STAT_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    int i;
    apr_thread_mutex_lock(worker->mutex);
    if (wconf->stat.sent_time.max > gconf->stat.sent_time.max) {
      gconf->stat.sent_time.max = wconf->stat.sent_time.max;
    }
    if (wconf->stat.recv_time.max > gconf->stat.recv_time.max) {
      gconf->stat.recv_time.max = wconf->stat.recv_time.max;
    }
    if (wconf->stat.conn_time.max > gconf->stat.conn_time.max) {
      gconf->stat.conn_time.max = wconf->stat.conn_time.max;
    }
    if (wconf->stat.sent_time.min < gconf->stat.sent_time.min || gconf->stat.sent_time.min == 0) {
      gconf->stat.sent_time.min = wconf->stat.sent_time.min;
    }
    if (wconf->stat.recv_time.min < gconf->stat.recv_time.min || gconf->stat.recv_time.min == 0) {
      gconf->stat.recv_time.min = wconf->stat.recv_time.min;
    }
    if (wconf->stat.conn_time.min < gconf->stat.conn_time.min || gconf->stat.conn_time.min == 0) {
      gconf->stat.conn_time.min = wconf->stat.conn_time.min;
    }
    gconf->stat.sent_bytes += wconf->stat.sent_bytes;
    gconf->stat.recv_bytes += wconf->stat.recv_bytes;
    gconf->stat.sent_time_total += wconf->stat.sent_time_total;
    gconf->stat.recv_time.total += wconf->stat.recv_time.total;
    gconf->stat.conn_time.total += wconf->stat.conn_time.total;
    gconf->stat.count.reqs += wconf->stat.count.reqs;
    gconf->stat.count.conns += wconf->stat.count.conns;
    for (i = 0; i < 10; i++) {
      gconf->stat.count.less[i] += wconf->stat.count.less[i];
    }
    for (i = 0; i < 600; i++) {
      gconf->stat.count.status[i] += wconf->stat.count.status[i];
    }
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
  if (gconf->on & STAT_GCONF_ON) {
    int i; 
    apr_time_t time;
    gconf->stat.sent_time.avr = gconf->stat.sent_time_total/gconf->stat.count.reqs;
    gconf->stat.recv_time.avr = gconf->stat.recv_time.total/gconf->stat.count.reqs;
    gconf->stat.conn_time.avr = gconf->stat.conn_time.total/gconf->stat.count.conns;
    fprintf(stdout, "\ntotal reqs: %d\n", gconf->stat.count.reqs);
    fprintf(stdout, "total conns: %d\n", gconf->stat.count.conns);
    fprintf(stdout, "send bytes: %d\n", gconf->stat.sent_bytes);
    fprintf(stdout, "received bytes: %d\n", gconf->stat.recv_bytes);
    for (i = 0, time = 1; i < 10; i++, time *= 2) {
      if (gconf->stat.count.less[i]) {
        fprintf(stdout, "%d request%s less than %"APR_TIME_T_FMT" seconds\n", 
                gconf->stat.count.less[i], gconf->stat.count.less[i]>1?"s":"", time);
      }
    }
    for (i = 0; i < 600; i++) {
      if (gconf->stat.count.status[i]) {
        fprintf(stdout, "status %d: %d\n", i, gconf->stat.count.status[i]);
      }
    }
    fprintf(stdout, "\nconn min: %"APR_TIME_T_FMT" max: %"APR_TIME_T_FMT " avr: %"APR_TIME_T_FMT "\n", 
            gconf->stat.conn_time.min, gconf->stat.conn_time.max, gconf->stat.conn_time.avr);
    fprintf(stdout, "sent min: %"APR_TIME_T_FMT" max: %"APR_TIME_T_FMT " avr: %"APR_TIME_T_FMT "\n", 
            gconf->stat.sent_time.min, gconf->stat.sent_time.max, gconf->stat.sent_time.avr);
    fprintf(stdout, "recv min: %"APR_TIME_T_FMT" max: %"APR_TIME_T_FMT " avr: %"APR_TIME_T_FMT "\n", 
            gconf->stat.recv_time.min, gconf->stat.recv_time.max, gconf->stat.recv_time.avr);
    fflush(stdout);
  }
  if (gconf->on & STAT_GCONF_ON) {
    apr_file_close(gconf->log_file);
  }
  return APR_SUCCESS;
}

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Do log every request to a file.
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temp pool
 */
static apr_status_t block_STAT_LOG(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  /* first param is format */
  /* second param is file */
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t stat_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "STAT", "_LOG",
	                           "<foo>",
	                           "Bla bla bla.",
	                           block_STAT_LOG)) != APR_SUCCESS) {
    return status;
  }
  htt_hook_worker_joined(stat_worker_joined, NULL, NULL, 0);
  htt_hook_worker_finally(stat_worker_finally, NULL, NULL, 0);
  htt_hook_WAIT_end(stat_WAIT_end, NULL, NULL, 0);
  htt_hook_read_status_line(stat_read_status_line, NULL, NULL, 0);
  htt_hook_WAIT_begin(stat_WAIT_begin, NULL, NULL, 0);
  htt_hook_read_header(stat_read_header, NULL, NULL, 0);
  htt_hook_read_buf(stat_read_buf, NULL, NULL, 0);
  htt_hook_line_sent(stat_line_sent, NULL, NULL, 0);
  htt_hook_read_line(stat_read_line, NULL, NULL, 0);
  htt_hook_pre_connect(stat_pre_connect, NULL, NULL, 0);
  htt_hook_post_connect(stat_post_connect, NULL, NULL, 0);
  return APR_SUCCESS;
}

