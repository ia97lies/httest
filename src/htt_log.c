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

struct htt_log_s {
  apr_pool_t *pool;
  apr_file_t *out; 
  apr_file_t *err; 
  int prev_mode;
  int mode;
  const char *prefix;
};

htt_log_t * htt_log_new(apr_pool_t *pool, apr_file_t *out, apr_file_t *err) {
  htt_log_t *log = apr_pcalloc(pool, sizeof(*log));
  log->pool = pool;
  log->out = out;
  log->err = err;
  log->mode = HTT_LOG_INFO;;
  log->prefix = apr_pstrdup(pool, "");
  return log;
}

void htt_log_set_mode(htt_log_t *log, int mode) {
  log->prev_mode = log->mode;
  log->mode = mode;
}

void htt_log_unset_mode(htt_log_t *log, int mode) {
  log->mode = log->prev_mode;
}

void htt_log_set_prefix(htt_log_t *log, const char *prefix) {
  log->prefix = apr_pstrdup(log->pool, prefix);
}

void htt_log(htt_log_t *log, int mode, char *fmt, ...) {
  if (log->mode >= mode) {
    char *tmp;
    va_list va;
    apr_pool_t *pool;

    apr_pool_create(&pool, log->pool);
    va_start(va, fmt);
    if (log->mode == HTT_LOG_ERROR) {
      tmp = apr_pvsprintf(pool, fmt, va);
      apr_file_printf(log->err, "\n%-88s", tmp);
    }
    else {
      tmp = apr_pvsprintf(pool, fmt, va);
      apr_file_printf(log->out, "\n%s%s", log->prefix, tmp);
    }
    va_end(va);
    apr_pool_destroy(pool);
  }
}

void htt_log_buf(htt_log_t *log, int mode, const char *buf, int len, 
                 char *prefix) {
  if (log->mode >= mode) {
    int i;
    int j;
    int max_line_len;
    int line_len;
    char *null="<null>";
    apr_file_t *fd = log->out;
    apr_pool_t *pool;
    char * outbuf;

    if (!buf) {
      buf = null;
      len = strlen(buf);
    }
    
    if (mode == HTT_LOG_ERROR) {
      fd = log->err;
    }

    if (prefix) {
      apr_file_printf(fd, "\n%s%s", log->prefix, prefix);
    }
    
    /* find longest line */
    i = 0;
    max_line_len = 0;
    line_len = 0;
    while (i < len) {
      while (i < len && buf[i] != '\r' && buf[i] != '\n') {
        if (buf[i] >= 0x20) {
          line_len++;
        }
        else {
          line_len+=4;
        }
        i++;
      }
      while (i < len && (buf[i] == '\r' || buf[i] == '\n')) {
        if (i != len -1) {
          if (buf[i] == '\n') {
            line_len+= 1 + strlen(log->prefix) + (prefix?strlen(prefix):0);
          }
        }
        i++;
      }
      if (line_len > max_line_len) {
        max_line_len = line_len;
      }
      line_len = 0;
    }
    
    apr_pool_create(&pool, log->pool);
    outbuf = apr_pcalloc(pool, max_line_len + 100);

    /* log lines */
    i = 0;
    while (i < len) {
      j = 0;
      while (i < len && buf[i] != '\r' && buf[i] != '\n') {
        if (buf[i] >= 0x20) {
          sprintf(&outbuf[j], "%c", buf[i]);
          j++;
        }
        else {
          sprintf(&outbuf[j], "0x%02x ", (unsigned char)buf[i]);
          j+=4;
        }
        i++;
      }
      while (i < len && (buf[i] == '\r' || buf[i] == '\n')) {
        if (i != len -1) {
          if (buf[i] == '\n') {
            sprintf(&outbuf[j], "%c", buf[i]);
            j++;
            sprintf(&outbuf[j], "%s%s", log->prefix, prefix?prefix:"");
            j+= strlen(log->prefix) + (prefix?strlen(prefix):0);
          }
        }
        i++;
      }
      apr_file_printf(fd, "%s", outbuf);
      outbuf[0] = 0;
    }
    
    apr_pool_destroy(pool);
  }
}

void htt_log_outbuf(htt_log_t *log, int mode, const char *buf, int len) {
  htt_log_buf(log, mode, buf, len, ">");
}

void htt_log_inbuf(htt_log_t *log, int mode, const char *buf, int len) {
  htt_log_buf(log, mode, buf, len, "<");
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
    apr_file_printf(log->err, "\n%-88s", tmp);
    va_end(va);
    apr_pool_destroy(pool);
  }

}


