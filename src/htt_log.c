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
#include "htt_log.h"

struct htt_log_s {
  FILE *std; 
  FILE *err; 
  int mode;
  const char *prefix;
};

/**
 * Create a new log instance
 * @param pool IN
 * @param std IN file desc for stdout
 * @param err IN file desc for errout
 * @param prefix IN prefix i.e. spaces
 * @return htt log instance
 */
htt_log_t * htt_log_make(apr_pool_t *pool, FILE *std, FILE *err, 
                         int mode, const char *prefix) {
  htt_log_t *log = apr_pcalloc(pool, sizeof(*log));
  log->std = std;
  log->err = err;
  log->mode = mode;
  log->prefix = prefix;
  return log;
}

/**
 * Log formated text
 * @param log IN instance
 * @param mode IN log mode
 * @param fmt IN format
 * @param ... IN format parameters
 */
void htt_log(htt_log_t *log, int mode, char *fmt, ...) {
  if (log->mode >= mode) {
    char *tmp;
    va_list va;
    apr_pool_t *pool;

    apr_pool_create(&pool, NULL);
    va_start(va, fmt);
    if (log->mode == LOG_ERR) {
      tmp = apr_pvsprintf(pool, fmt, va);
      fprintf(log->err, "\n%-88s", tmp);
      fflush(log->err);
    }
    else {
      fprintf(stdout, "\n%s", log->prefix);
      vfprintf(stdout, fmt, va);
      fflush(stdout);
    }
    va_end(va);
    apr_pool_destroy(pool);
  }
}

/**
 * Log formated buffer
 * @param log IN instance
 * @param mode IN log mode
 * @param buf IN buffer to log
 * @param len IN buffer len to log 
 * @param prefix IN for input/output buffer
 */
void htt_log_buf(htt_log_t *log, int mode, const char *buf, int len, 
                 char *prefix) {
  if (log->mode >= mode) {
    int i;
    int j;
    int max_line_len;
    int line_len;
    char *null="<null>";
    FILE *fd = log->std;
    apr_pool_t *pool;
    char * outbuf;

    if (!buf) {
      buf = null;
      len = strlen(buf);
    }
    
    if (mode == LOG_ERR) {
      fd = log->err;
    }

    if (prefix) {
      fprintf(fd, "\n%s%s", log->prefix, prefix);
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
    
    apr_pool_create(&pool, NULL);
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
      fprintf(fd, "%s", outbuf);
      fflush(fd);
      outbuf[0] = 0;
    }
    
    apr_pool_destroy(pool);
  }
}

/**
 * Log formated output buffer
 * @param log IN instance
 * @param mode IN log mode
 * @param buf IN buffer to log
 * @param len IN buffer len to log 
 */
void htt_log_outbuf(htt_log_t *log, int mode, const char *buf, int len) {
  htt_log_buf(log, mode, buf, len, ">");
}

/**
 * Log formated input buffer
 * @param log IN instance
 * @param mode IN log mode
 * @param buf IN buffer to log
 * @param len IN buffer len to log 
 */
void htt_log_inbuf(htt_log_t *log, int mode, const char *buf, int len) {
  htt_log_buf(log, mode, buf, len, "<");
}

/**
 * Log error
 * @param log IN instance
 * @param position IN file and line
 * @param fmt IN format
 * @param ... IN format parameters
 */

void htt_log_error(htt_log_t *log, char *position, char *fmt, ...) {
}


