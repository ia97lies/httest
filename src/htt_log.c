/**
 * Copyright 2006 Christian Liesch
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
 * Implementation of htt log.
 */

#include <apr.h>
#include <apr_pools.h>
#include <apr_strings.h>
#include "htt_util.h"
#include "htt_log.h"
#include "htt_log_appender.h"

struct htt_log_s {
  apr_pool_t *pool;
  int prev_mode;
  int mode;
  int level;
  long unsigned int id;
  htt_log_appender_t *appender;
};

/************************************************************************
 * Globals
 ***********************************************************************/

const char *mode_str[] = {
 "NONE",
 "ERROR",
 "WARN",
 "INFO",
 "CMD",
 "DEBUG",
  NULL
};

/************************************************************************
 * Public 
 ***********************************************************************/

htt_log_t * htt_log_new(apr_pool_t *pool, long unsigned int id) {
  htt_log_t *log = apr_pcalloc(pool, sizeof(*log));
  log->pool = pool;
  log->id = id;
  log->mode = HTT_LOG_INFO;;
  return log;
}

htt_log_t * htt_log_clone(apr_pool_t *pool, htt_log_t *log, 
                          long unsigned int id) {
  htt_log_t *new_log = htt_log_new(pool, id);
  new_log->mode = log->mode;
  new_log->level = log->level;
  new_log->appender = log->appender;
  return new_log;
}

void htt_log_set_appender(htt_log_t *log, htt_log_appender_t *appender) {
  log->appender = appender;
}

void htt_log_set_mode(htt_log_t *log, int mode) {
  log->prev_mode = log->mode;
  log->mode = mode;
}

void htt_log_unset_mode(htt_log_t *log, int mode) {
  log->mode = log->prev_mode;
}

void htt_log_set_level(htt_log_t *log, int level) {
  log->level = level;
}

void htt_log_va(htt_log_t *log, int mode, char direction, const char *custom,
                char *fmt, va_list va) {
  if (log->mode >= mode) {
    char *tmp;
    apr_pool_t *pool;

    apr_pool_create(&pool, log->pool);
    tmp = apr_pvsprintf(pool, fmt, va);
    htt_log_appender_print(log->appender, log->level, direction, log->id, 
                           mode, custom?custom:"null", tmp, 0);
    apr_pool_destroy(pool);
  }
}

void htt_log(htt_log_t *log, int mode, char direction, const char *custom, 
             char *fmt, ...) {
  if (log->mode >= mode) {
    va_list va;

    va_start(va, fmt);
    htt_log_va(log, mode, direction, custom, fmt, va);
  }
}

void htt_log_debug(htt_log_t *log, char *fmt, ...) {
  if (log->mode >= HTT_LOG_DEBUG) {
    va_list va;

    va_start(va, fmt);
    htt_log_va(log, HTT_LOG_DEBUG, '=', NULL, fmt, va);
  }
}

void htt_log_error(htt_log_t *log, apr_status_t status, const char *file, 
                   int pos, const char *fmt, ...) {
  if (log->mode >= HTT_LOG_ERROR) {
    char *tmp;
    va_list va;
    apr_pool_t *pool;

    apr_pool_create(&pool, log->pool);
    va_start(va, fmt);
    tmp = apr_pvsprintf(pool, fmt, va);
    tmp = apr_psprintf(pool, "%s:%d: error: %s(%d): %s", file, pos,
                       htt_util_status_str(pool, status), status, tmp);
    htt_log_appender_print(log->appender, log->level, '=', log->id, 
                           log->mode, "error", tmp, 0);
    va_end(va);
    apr_pool_destroy(pool);
  }
}

void htt_log_buf(htt_log_t *log, int mode, char direction, const char *custom,
                 const char *buf, int len) {
  if (log->mode >= mode) {
    char *cur;
    char *null="<null>";

    if (!buf) {
      buf = null;
      len = strlen(buf);
    }
    
    while ((cur = strchr(buf, '\n'))) {
      apr_size_t len = cur - buf;
      if (buf[len] == '\r') {
        --len;
      }
      htt_log_appender_print(log->appender, log->level, direction, log->id, 
                             mode, custom?custom:"null", buf, len);
      buf = cur + 1;
    }
  }
}

