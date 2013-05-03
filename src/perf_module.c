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
#include "tcp_module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct perf_time_s {
  apr_time_t cur;
  apr_time_t min;
  apr_time_t avr;
  apr_time_t max;
  apr_time_t total;
} perf_time_t;

typedef struct perf_count_s {
  int reqs;
  int conns;
  int less[10];
  int status[600];
} perf_count_t;

typedef struct perf_s {
  perf_count_t count;
  apr_size_t recv_bytes;
  apr_size_t sent_bytes;
  perf_time_t conn_time;
  perf_time_t recv_time;
  perf_time_t sent_time;
  apr_time_t sent_time_total;
} perf_t;

typedef struct perf_wconf_s {
  apr_time_t WAIT_time;
  int cur_status;
  const char *request_line;
  perf_t stat;
} perf_wconf_t;

typedef struct perf_host_s {
  char *name;
  int clients;
  int state;
#define PERF_HOST_NONE      0
#define PERF_HOST_CONNECTED 1
#define PERF_HOST_ERROR 2
  apr_thread_mutex_t *sync;
  socket_t *socket; 
  worker_t *worker;
  int flags;
#define PERF_HOST_FLAGS_NONE 0
#define PERF_HOST_FLAGS_GLOBALS_DIST 1
} perf_host_t;

typedef struct perf_rampup_s {
  apr_size_t cur_clients;
  apr_size_t clients;
  apr_time_t interval;
} perf_rampup_t;

typedef struct perf_gconf_threads_s {
#define PERF_GCONF_FLAGS_NONE   0 
#define PERF_GCONF_FLAGS_DIST   1 
#define PERF_GCONF_FLAGS_RAMPUP 2 
  perf_rampup_t rampup;
  apr_hash_t *my_threads;
  apr_hash_t *host_and_ports;
  apr_hash_index_t *cur_host_i;
  perf_host_t *cur_host;
} perf_gconf_threads_t;


typedef struct perf_gconf_s {
  int on;
#define PERF_GCONF_OFF  0
#define PERF_GCONF_ON   1
#define PERF_GCONF_LOG  2 
  int flags;
  perf_t stat;
  apr_file_t *log_file;
  perf_gconf_threads_t clients;
} perf_gconf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
const char * perf_module = "perf_module";
apr_time_t start_time;

/************************************************************************
 * Local 
 ***********************************************************************/

/**
 * Get stat config from global 
 *
 * @param global IN 
 * @return stat config
 */
static perf_gconf_t *perf_get_global_config(global_t *global) {
  perf_gconf_t *config = module_get_config(global->config, perf_module);
  if (config == NULL) {
    config = apr_pcalloc(global->pool, sizeof(*config));
    config->clients.host_and_ports = apr_hash_make(global->pool);
    config->clients.my_threads = apr_hash_make(global->pool);
    module_set_config(global->config, apr_pstrdup(global->pool, perf_module), config);
  }
  return config;
}

/**
 * Get stat config from worker
 *
 * @param worker IN worker
 * @return stat config
 */
static perf_wconf_t *perf_get_worker_config(worker_t *worker) {
  perf_wconf_t *config = module_get_config(worker->config, perf_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, apr_pstrdup(worker->pbody, perf_module), config);
  }
  return config;
}

/**
 * Is called after line is sent
 * @param worker IN callee
 * @param line IN line sent
 * @return APR_SUCCESS
 */
static apr_status_t perf_line_sent(worker_t *worker, line_t *line) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    if (wconf->WAIT_time == 0) {
      ++wconf->stat.count.reqs;
      wconf->WAIT_time = apr_time_now();
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
static apr_status_t perf_WAIT_begin(worker_t *worker) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    apr_time_t now = apr_time_now();
    apr_time_t duration = now - wconf->WAIT_time;
    wconf->WAIT_time = now;
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
static apr_status_t perf_read_status_line(worker_t *worker, char *line) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
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
static apr_status_t perf_read_header(worker_t *worker, char *line) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
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
static apr_status_t perf_read_buf(worker_t *worker, char *buf, apr_size_t len) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
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
static apr_status_t perf_WAIT_end(worker_t *worker, apr_status_t status) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
    int i;
    apr_time_t compare;
    apr_time_t now = apr_time_now();
    apr_time_t duration = now - wconf->WAIT_time;
    wconf->WAIT_time = 0;
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
  if (gconf->on & PERF_GCONF_LOG && worker->flags & FLAGS_CLIENT) {
    apr_pool_t *pool;
    char *date_str;

    apr_pool_create(&pool, NULL);
    date_str = apr_palloc(pool, APR_RFC822_DATE_LEN);
    apr_rfc822_date(date_str, apr_time_now());
    apr_file_printf(gconf->log_file, "[%s] \"%s\" %d %s %"APR_TIME_T_FMT" %"APR_TIME_T_FMT"\n", 
                    date_str,  wconf->request_line, wconf->cur_status, 
                    status == APR_SUCCESS ? "OK" : "FAILED",
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
static apr_status_t perf_pre_connect(worker_t *worker) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
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
static apr_status_t perf_post_connect(worker_t *worker) {
  global_t *global = worker->global;
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(global);

  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
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
static apr_status_t perf_worker_finally(worker_t *worker) {
  perf_wconf_t *wconf = perf_get_worker_config(worker);
  perf_gconf_t *gconf = perf_get_global_config(worker->global);
  if (gconf->on & PERF_GCONF_ON && worker->flags & FLAGS_CLIENT) {
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
static apr_status_t perf_worker_joined(global_t *global) {
  perf_gconf_t *gconf = perf_get_global_config(global);
  if (gconf->on & PERF_GCONF_ON) {
    int i; 
    apr_time_t time;
    float seconds;
    gconf->stat.sent_time.avr = gconf->stat.sent_time_total/gconf->stat.count.reqs;
    gconf->stat.recv_time.avr = gconf->stat.recv_time.total/gconf->stat.count.reqs;
    gconf->stat.conn_time.avr = gconf->stat.conn_time.total/gconf->stat.count.conns;
    fprintf(stdout, "\ntotal reqs: %d\n", gconf->stat.count.reqs);
    fprintf(stdout, "total conns: %d\n", gconf->stat.count.conns);
    fprintf(stdout, "send bytes: %"APR_SIZE_T_FMT"\n", gconf->stat.sent_bytes);
    fprintf(stdout, "received bytes: %"APR_SIZE_T_FMT"\n", gconf->stat.recv_bytes);
    seconds = (float)(apr_time_now() - start_time)/ APR_USEC_PER_SEC;
    
    fprintf(stdout, "test duration: %02f\n", seconds);
    if (seconds > 0) {
      fprintf(stdout, "request per second: %02f\n", gconf->stat.count.reqs/seconds);
    }
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
  if (gconf->on & PERF_GCONF_LOG) {
    apr_file_close(gconf->log_file);
  }
  return APR_SUCCESS;
}

/**
 * Get cur host from hash
 * @param gconf IN global config
 * @param worker IN store worker for cur host
 * @return cur host
 */
static perf_host_t *perf_get_cur_host(perf_gconf_t *gconf, worker_t *worker) {
  void *val = NULL;
  if (gconf->clients.cur_host_i) {
    apr_hash_this(gconf->clients.cur_host_i, NULL, NULL, &val);
  }
  gconf->clients.cur_host = val;
  if (gconf->clients.cur_host) {
    gconf->clients.cur_host->worker = worker;
  }
  return val;
}

/**
 * Get first remote host from hash
 * @param global IN global instance
 * @param worker IN store worker for first host
 * @return cur host
 */
static perf_host_t *perf_get_first_host(global_t *global, worker_t *worker) {
  perf_gconf_t *gconf = perf_get_global_config(global);
  gconf->clients.cur_host_i = apr_hash_first(global->pool, gconf->clients.host_and_ports);
  return perf_get_cur_host(gconf, worker);
}

/**
 * Get next remote host from hash
 * @param global IN global instance
 * @param worker IN store worker for next host
 * @return cur host
 */
static perf_host_t *perf_get_next_host(global_t *global, worker_t *worker) {
  perf_gconf_t *gconf = perf_get_global_config(global);
  gconf->clients.cur_host_i = apr_hash_next(gconf->clients.cur_host_i);
  return perf_get_cur_host(gconf, worker);
}

/**
 * Serialize to httestd
 * @param worker IN callee
 * @param fmt IN format
 * @param ... IN
 * @return apr_status_t
 */
static apr_status_t perf_serialize(perf_host_t *host, char *fmt, ...) {
  char *tmp;
  va_list va;
  apr_pool_t *pool;

  apr_pool_create(&pool, NULL);
  va_start(va, fmt);
  tmp = apr_pvsprintf(pool, fmt, va);
  transport_write(host->socket->transport, tmp, strlen(tmp));
  va_end(va);
  apr_pool_destroy(pool);

  return APR_SUCCESS;
}

/**
 * Iterate all variables, modules and blocks for serialization
 * @param global IN global context
 * @param host IN remote host
 * @return APR_SUCCESS
 */
static apr_status_t perf_serialize_globals(global_t *global, perf_host_t *host) {
  int i;
  apr_table_t *vars;
  apr_table_t *shared;
  apr_table_entry_t *e;
  apr_pool_t *ptmp;

  if (!host->flags & PERF_HOST_FLAGS_GLOBALS_DIST) {
    apr_pool_create(&ptmp, NULL);
    vars = store_get_table(global->vars, ptmp);
    e = (apr_table_entry_t *) apr_table_elts(vars)->elts;
    for (i = 0; i < apr_table_elts(vars)->nelts; ++i) {
      perf_serialize(host, "SET %s=%s\n", e[i].key, e[i].val);
    }
    if (global->shared) {
      shared = store_get_table(global->shared, ptmp);
      e = (apr_table_entry_t *) apr_table_elts(shared)->elts;
      for (i = 0; i < apr_table_elts(shared)->nelts; ++i) {
        perf_serialize(host, "GLOBAL %s=%s\n", e[i].key, e[i].val);
      }
    }
    apr_pool_destroy(ptmp);
    host->flags |= PERF_HOST_FLAGS_GLOBALS_DIST; 
  }
  return APR_SUCCESS;
}

/**
 * Iterate all lines of client
 * @param global IN global context
 * @param host IN remote host
 * @return APR_SUCCESS
 */
static apr_status_t perf_serialize_clients(global_t *global, perf_host_t *host) {
  int i;
  apr_pool_t *ptmp;
  apr_table_entry_t *e;

  if (host->clients > 0) {
    apr_pool_create(&ptmp, NULL);
    perf_serialize(host, "CLIENT %d\n", host->clients);
    e = (apr_table_entry_t *) apr_table_elts(host->worker->lines)->elts;
    for (i = 0; i < apr_table_elts(host->worker->lines)->nelts; ++i) {
      perf_serialize(host, "%s\n", e[i].val);
    }
    perf_serialize(host, "END\n");
    apr_pool_destroy(ptmp);
    host->clients = 0;
  }
  return APR_SUCCESS;
}

/**
 * Iterate all lines of client
 * @param global IN global context
 * @param host IN remote host
 * @return APR_SUCCESS
 */
static apr_status_t perf_serialize_servers(global_t *global, perf_host_t *host, 
                                           char *port_info) {
  int i;
  apr_pool_t *ptmp;
  apr_table_entry_t *e;

  if (host->clients > 0) {
    apr_pool_create(&ptmp, NULL);
    perf_serialize(host, "SERVER %s\n", port_info);
    e = (apr_table_entry_t *) apr_table_elts(host->worker->lines)->elts;
    for (i = 0; i < apr_table_elts(host->worker->lines)->nelts; ++i) {
      perf_serialize(host, "%s\n", e[i].val);
    }
    perf_serialize(host, "END\n");
    apr_pool_destroy(ptmp);
    host->clients = 0;
  }
  return APR_SUCCESS;
}

/**
 * Supervisor thread wait for remote host is done
 * @param thread IN thread handle
 * @param selfv IN void pointer to perf host struct
 * @return NULL
 */
static void * APR_THREAD_FUNC perf_thread_super(apr_thread_t * thread, 
                                                void *selfv) {
  perf_host_t *host = selfv;
  apr_status_t status;
  apr_pool_t *pool;
  apr_size_t len = 1;
  char *buf;
  sockreader_t *sockreader;

  apr_pool_create(&pool, NULL);
  apr_thread_mutex_lock(host->sync);
  status = transport_read(host->socket->transport, buf, &len);

  if ((status = sockreader_new(&sockreader, host->socket->transport,
                               NULL, 0, pool)) == APR_SUCCESS) {
    status = sockreader_read_line(sockreader, &buf); 
    while (status == APR_SUCCESS) {
      logger_log(host->worker->logger, LOG_INFO, "[%s]: %s", host->name, buf);
      status = sockreader_read_line(sockreader, &buf); 
    }
    worker_log(host->worker, LOG_INFO, "Remote host finished: %d\n", status);
  }
  else {
    worker_log(host->worker, LOG_ERR, "Lost connection to remote host \"%s\"\n", 
               host->name);
  }

  apr_thread_mutex_unlock(host->sync);
  apr_pool_destroy(pool);

  apr_thread_exit(thread, APR_SUCCESS);
  return NULL;
}

/**
 * Cleanup for thread data
 * @param selfv IN void pointer to perf host struct
 * @return APR_SUCCESS
 */
static apr_status_t perf_host_cleanup(void *selfv) {
  return APR_SUCCESS;
}

/**
 * Distribute host to remote host, start a supervisor thread
 * @param worker IN callee
 * @param host IN host to distribute to
 * @param thread OUT thread handle
 * @return supervisor thread handle
 */
static apr_status_t perf_distribute_host(worker_t *worker, 
                                         perf_host_t *host,
                                         apr_thread_t **thread) {
  apr_status_t status;
  global_t *global = worker->global;
  apr_pool_t *ptmp;

  *thread = NULL;
  apr_pool_create(&ptmp, NULL);
  if ((host->state != PERF_HOST_CONNECTED) &&
      (host->state != PERF_HOST_ERROR)) {
    char *portname;
    char *hostport = apr_pstrdup(ptmp, host->name);
    char *hostname = apr_strtok(hostport, ":", &portname);
    
    worker_get_socket(worker, hostname, portname);

    if ((status = tcp_connect(worker, hostname, portname)) != APR_SUCCESS) {
      host->state = PERF_HOST_ERROR;
      worker_log(worker, LOG_ERR, "Could not connect to httestd \"%s\" SKIP", 
                       host->name);
      apr_pool_destroy(ptmp);
      return status;
    }
    htt_run_connect(worker);
    host->state = PERF_HOST_CONNECTED;
    ++host->clients;
    host->socket = worker->socket;
    if ((status = apr_thread_mutex_create(&host->sync, 
                                          APR_THREAD_MUTEX_DEFAULT,
                                          global->pool)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not create supervisor thread sync mutex for remote host");
      apr_pool_destroy(ptmp);
      return status;
    }
    apr_thread_mutex_lock(host->sync);
    if ((status = apr_thread_create(thread, global->tattr, perf_thread_super,
                                    host, global->pool)) 
        != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not create supervisor thread for remote host");
      apr_pool_destroy(ptmp);
      return status;
    }
    if ((status = apr_thread_data_set(host, "host", 
                                      perf_host_cleanup, *thread)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Could not store remote host to thread");
      apr_pool_destroy(ptmp);
      return status;
    }
  }
  else if (host->state == PERF_HOST_ERROR) {
    worker_log(worker, LOG_ERR, "Could not connect to httestd \"%s\" SKIP", host->name);
    apr_pool_destroy(ptmp);
    return APR_ECONNREFUSED;
  }
  else {
    ++host->clients;
  }

  apr_pool_destroy(ptmp);
  return APR_SUCCESS;
}

/**
 * Distribute client worker.
 * @param worker IN callee
 * @param func IN concurrent function to call
 * @param new_thread OUT thread handle of concurrent function
 * @return APR_ENOTHREAD if there is no schedul policy, else any apr status.
 */
static apr_status_t perf_client_create(worker_t *worker, apr_thread_start_t func, apr_thread_t **new_thread) {
  global_t *global = worker->global;
  perf_gconf_t *gconf = perf_get_global_config(global);
  apr_status_t status = APR_ENOTHREAD;
  
  if (gconf->flags & PERF_GCONF_FLAGS_DIST) {
    if (!gconf->clients.cur_host_i) {
      worker_log(worker, LOG_INFO, "Distribute CLIENT to my self");
      perf_get_first_host(global, worker);
      status = APR_ENOTHREAD;
    }
    else {
      /* distribute to remote host */
      worker_log(worker, LOG_INFO, "Distribute CLIENT to %s", 
                 gconf->clients.cur_host->name);
      status = perf_distribute_host(worker, gconf->clients.cur_host, new_thread);
      if (*new_thread) {
        apr_hash_set(gconf->clients.my_threads, *new_thread, sizeof(*new_thread),
                     new_thread);
      }
      if (status != APR_SUCCESS) {
        status = APR_ENOTHREAD;
      }
      perf_get_next_host(global, worker);
    }
  }

  if (gconf->flags & PERF_GCONF_FLAGS_RAMPUP) {
    if (gconf->clients.rampup.cur_clients >= gconf->clients.rampup.clients) {
      if (gconf->flags & PERF_GCONF_FLAGS_DIST) {
        perf_host_t *host = perf_get_cur_host(gconf, worker);
        if (host && host->state == PERF_HOST_CONNECTED) {
          perf_serialize_globals(global, host);
          perf_serialize_clients(global, host);
          perf_serialize(host, "START\n");
        }
      }
      apr_sleep(gconf->clients.rampup.interval);
      gconf->clients.rampup.cur_clients = 0;
    } 
    else {
      ++gconf->clients.rampup.cur_clients;
    }
  }

  return status;
}

/**
 * Distribute server worker.
 * @param worker IN callee
 * @param func IN concurrent function to call
 * @param new_thread OUT thread handle of concurrent function
 * @return APR_ENOTHREAD if there is no schedul policy, else any apr status.
 */
static apr_status_t perf_server_create(worker_t *worker, apr_thread_start_t func, apr_thread_t **new_thread) {
  if (strstr(worker->additional, "->")) {
    apr_status_t status;
    char *distribute_to;
    char *remote_host;
    char *server_port_info;
    char *last;
    global_t *global = worker->global;
    perf_host_t *host = apr_pcalloc(global->pool, sizeof(*host));
    perf_gconf_t *gconf = perf_get_global_config(global);

    distribute_to = apr_pstrdup(global->pool, worker->additional);
    server_port_info = apr_strtok(distribute_to, "->", &last);
    remote_host = apr_strtok(NULL, "->", &last);
    apr_collapse_spaces(remote_host, remote_host);
    host->name = remote_host;
    host->worker = worker;
    worker_log(worker, LOG_DEBUG, "distribute server to \"%s\"\n", remote_host);
    status = perf_distribute_host(worker, host, new_thread);
    if (status != APR_SUCCESS) {
      status = APR_EINVAL;
      worker_log(worker, LOG_ERR, "Can not serialize server to remote host \"%s\"", remote_host);
    }
    else {
      apr_hash_set(gconf->clients.my_threads, *new_thread, sizeof(*new_thread),
                   new_thread);
      perf_serialize_globals(global, host);
      perf_serialize_servers(global, host, server_port_info);
      perf_serialize(host, "GO\n");
      perf_serialize(host, "EXIT OK\n");
      apr_sleep(apr_time_from_sec(1));
      worker_log(worker, LOG_DEBUG, "unlock %s", worker->name);
      apr_thread_mutex_unlock(worker->sync_mutex);
    }
    return status;
  }
  return APR_ENOTHREAD;
}

/**
 * Distribute client to remote host, we know now how many.
 * @param worker IN callee
 * @param thread IN thread handle of concurrent function
 * @return APR_ENOTHREAD if there is no schedul policy, else any apr status.
 */
static apr_status_t perf_thread_start(global_t *global, apr_thread_t *thread) {
  perf_host_t *host;
  perf_gconf_t *gconf = perf_get_global_config(global);
  if (apr_hash_get(gconf->clients.my_threads, thread, sizeof(thread))) {
    if ((apr_thread_data_get((void **)&host, "host", thread) == APR_SUCCESS) && host) {
      apr_thread_mutex_unlock(host->sync);
      perf_serialize_globals(global, host);
      perf_serialize_clients(global, host);
      perf_serialize(host, "GO\n");
      perf_serialize(host, "EXIT OK\n");
    }
  }
  return APR_SUCCESS;
}

/************************************************************************
 * Commands 
 ***********************************************************************/

/**
 * PERF:DISTRIBUTE command
 * @param worker IN thread data object
 * @param data IN
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t block_PERF_DISTRIBUTE(worker_t * worker, worker_t *parent,
                                          apr_pool_t *ptmp) {
  apr_status_t status;
  global_t *global = worker->global;
  perf_host_t *host = apr_pcalloc(global->pool, sizeof(*host));
  perf_gconf_t *gconf = perf_get_global_config(global);

  if ((status = module_check_global(worker)) != APR_SUCCESS) {
    return status;
  }
  gconf->flags |= PERF_GCONF_FLAGS_DIST;
  host->name = store_get_copy(worker->params, global->pool, "1");
  apr_hash_set(gconf->clients.host_and_ports, host->name, APR_HASH_KEY_STRING, host);
  return APR_SUCCESS;
}

/**
 * PERF:LOG command
 * @param worker IN thread data object
 * @param data IN
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t block_PERF_STAT(worker_t * worker, worker_t *parent,
                                    apr_pool_t *ptmp) {
  apr_status_t status;
  global_t *global = worker->global;
  perf_host_t *host = apr_pcalloc(global->pool, sizeof(*host));
  perf_gconf_t *gconf = perf_get_global_config(global);
  const char *param;

  if ((status = module_check_global(worker)) != APR_SUCCESS) {
    return status;
  }
  param = store_get(worker->params, "1");
  if (strcmp(param, "ON") == 0) {
    gconf->on = PERF_GCONF_ON;
  }
  else if (strcmp(param, "OFF") == 0) {
    gconf->on |= PERF_GCONF_OFF;
  }
  else if (strcmp(param, "LOG") == 0) {
    apr_status_t status;
    const char *filename;
    gconf->on |= PERF_GCONF_LOG;
    filename = store_get(worker->params, "2");
    if (filename) {
      if ((status = apr_file_open(&gconf->log_file, filename, 
                                  APR_READ|APR_WRITE|APR_CREATE|APR_APPEND|APR_XTHREAD, 
                                  APR_OS_DEFAULT, global->pool)) != APR_SUCCESS) {
        worker_log(worker, LOG_ERR, "Could not open log file \"%s\"", filename);
        return status;
      }
    }
    else {
      worker_log(worker, LOG_ERR, "No file specified for PERF:LOG command");
      return APR_EINVAL;
    }
  }

  return APR_SUCCESS;
}

/**
 * PERF:RAMPUP command
 * @param worker IN thread data object
 * @param data IN
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t block_PERF_RAMPUP(worker_t * worker, worker_t *parent,
                                      apr_pool_t *ptmp) {
  apr_status_t status;
  global_t *global = worker->global;
  perf_host_t *host = apr_pcalloc(global->pool, sizeof(*host));
  perf_gconf_t *gconf = perf_get_global_config(global);
  const char *clients_str;
  const char *interval_str;

  status = APR_SUCCESS;
  if ((status = module_check_global(worker)) == APR_SUCCESS) {
    clients_str = store_get(worker->params, "1");
    interval_str = store_get(worker->params, "2");
    if (clients_str && interval_str) {
      gconf->flags |= PERF_GCONF_FLAGS_RAMPUP;
      gconf->clients.rampup.clients = apr_atoi64(clients_str);
      /* apr_time_from_msec available in apr 1.4.x */
      gconf->clients.rampup.interval = 1000 * apr_atoi64(interval_str);
    }
    else if (!clients_str) {
      worker_log(worker, LOG_ERR, "Number of clients per interval not specified");
      status = APR_ENOENT;
    }
    else {
      worker_log(worker, LOG_ERR, "Interval not specified");
      status = APR_ENOENT;
    }
  }

  return status;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t perf_module_init(global_t *global) {
  apr_status_t status;

  start_time = apr_time_now();
  if ((status = module_command_new(global, "PERF", "STAT", 
                                   "ON|OFF|LOG <filename>",
				   "print statistics at end of test, option LOG "
                                   "do additional write all requests to <filename>",
	                           block_PERF_STAT)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "PERF", "RAMPUP", 
                                   "<clients> per <interval>",
				   "Start <clients> per <interval> [ms], "
                                   "<clients> per <interval> are started all "
                                   "together",
	                           block_PERF_RAMPUP)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "PERF", "DISTRIBUTED", 
                                   "<host>:<port>",
				   "Distribute CLIENT to <host>:<port>, "
                                   "need an agent on this host",
	                           block_PERF_DISTRIBUTE)) != APR_SUCCESS) {
    return status;
  }

  htt_hook_client_create(perf_client_create, NULL, NULL, 0);
  htt_hook_server_create(perf_server_create, NULL, NULL, 0);
  htt_hook_thread_start(perf_thread_start, NULL, NULL, 0);
  htt_hook_worker_joined(perf_worker_joined, NULL, NULL, 0);
  htt_hook_worker_finally(perf_worker_finally, NULL, NULL, 0);
  htt_hook_pre_connect(perf_pre_connect, NULL, NULL, 0);
  htt_hook_post_connect(perf_post_connect, NULL, NULL, 0);
  htt_hook_line_sent(perf_line_sent, NULL, NULL, 0);
  htt_hook_WAIT_begin(perf_WAIT_begin, NULL, NULL, 0);
  htt_hook_read_status_line(perf_read_status_line, NULL, NULL, 0);
  htt_hook_read_header(perf_read_header, NULL, NULL, 0);
  htt_hook_read_buf(perf_read_buf, NULL, NULL, 0);
  htt_hook_WAIT_end(perf_WAIT_end, NULL, NULL, 0);
  return APR_SUCCESS;
}

