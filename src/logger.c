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
 * Implementation of the HTTP Test Tool logger.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <config.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_env.h>

#include <apr.h>
#include <apr_lib.h>
#include <apr_errno.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_thread_proc.h>
#include <apr_thread_cond.h>
#include <apr_thread_mutex.h>
#include <apr_portable.h>
#include <apr_hash.h>
#include <apr_base64.h>
#include <apr_hooks.h>
#include <apr_env.h>

#include "defines.h"
#include "util.h"
#include "replacer.h"
#include "regex.h"
#include "file.h"
#include "transport.h"
#include "socket.h"
#include "worker.h"

#include "logger.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct logger_s {
  int mode;
  apr_thread_mutex_t *mutex;
  const char *file_and_line;
  global_t *global;
  /* this has to be moved to appender */
  apr_file_t *out;
  apr_file_t *err;
};

/************************************************************************
 * Forward declaration 
 ***********************************************************************/


/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * Constructor for logger
 * @param mode IN logger mode set outside
 * @param out IN output file descriptor
 * @param err IN output error file descriptor
 * @return logger
 */
logger_t *logger_new(global_t *global, int mode, apr_file_t *out,
                     apr_file_t *err) {
  logger_t *logger = apr_pcalloc(global->pool, sizeof(*logger));
  logger->global = global;
  logger->mode = mode;
  logger->out = out;
  logger->err = err;
  return logger;
}

/**
 * a simple log mechanisme with va args
 * @param worker IN thread data object
 * @param log_mode IN log mode
 *                    LOG_DEBUG for a lot of infos
 *                    LOG_INFO for much infos
 *                    LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void worker_log_va(worker_t * worker, int log_mode, char *fmt, va_list va) {
  if (worker->log_mode >= log_mode) {
    char *tmp;
    apr_pool_t *pool;

    apr_pool_create(&pool, NULL);
    if (worker->log_mutex) apr_thread_mutex_lock(worker->log_mutex);
    if (log_mode == LOG_ERR) {
      tmp = apr_pvsprintf(pool, fmt, va);
      tmp = apr_psprintf(pool, "%s: error: %s", worker->file_and_line?worker->file_and_line:"<none>",
                         tmp);
      if (worker->global->log_thread_no) {
        apr_file_printf(worker->err, "\n%d:%-88s", worker->which, tmp);
      }
      else {
        apr_file_printf(worker->err, "\n%-88s", tmp);
      }
      apr_file_flush(worker->err);
    }
    else {
      tmp = apr_pvsprintf(pool, fmt, va);
      if (worker->global->log_thread_no) {
        apr_file_printf(worker->out, "\n%d:%s", worker->which, worker->prefix);
      }
      else {
        apr_file_printf(worker->out, "\n%s", worker->prefix);
      }
      apr_file_printf(worker->out, "%s", tmp);
      apr_file_flush(worker->out);
    }
    if (worker->log_mutex) apr_thread_mutex_unlock(worker->log_mutex);
    apr_pool_destroy(pool);
  }
}

/**
 * a simple log mechanisme
 * @param worker IN thread data object
 * @param log_mode IN log mode
 *                    LOG_DEBUG for a lot of infos
 *                    LOG_INFO for much infos
 *                    LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void worker_log(worker_t * worker, int log_mode, char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  worker_log_va(worker, log_mode, fmt, va);
  va_end(va);
}

/**
 * a simple error log mechanisme
 * @param worker IN thread data object
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void worker_log_error(worker_t * worker, char *fmt, ...) {

  if (worker->log_mode >= LOG_ERR) {
    va_list va;
    va_start(va, fmt);
    worker_log_va(worker, LOG_ERR, fmt, va);
    va_end(va);
  }
}

/**
 * a simple log buf mechanisme
 * @param worker IN thread data object
 * @param log_mode IN log mode
 *                    LOG_DEBUG for a lot of infos
 *                    LOG_INFO for much infos
 *                    LOG_ERR for only very few infos
 * @param buf IN buf to print (binary data allowed)
 * @param prefix IN prefix before buf
 * @param len IN buf len
 */
void worker_log_buf(worker_t * worker, int log_mode, const char *buf,
                    char *prefix, apr_size_t len) {

  if (worker->log_mode >= log_mode) {
    apr_size_t i;
    apr_size_t j;
    char *null="<null>";

    if (!buf) {
      buf = null;
      len = strlen(buf);
    }
    
    i = 0;
    j = 0;
    do {
      for (; i < len && buf[i] != '\n'; i++); 
      ++i;
      if (worker->log_mutex) apr_thread_mutex_lock(worker->log_mutex);
      if (worker->global->log_thread_no) {
        apr_file_printf(worker->out, "\n%d:%s%s", worker->which, 
                        worker->prefix, prefix?prefix:"");
      }
      else {
        apr_file_printf(worker->out, "\n%s%s", worker->prefix, prefix?prefix:"");
      }

      for (; j < i; j++) {
        if ((unsigned char)buf[j] == '\n') {
          /*
          apr_size_t l = 2;
          apr_file_write(worker->out, "\\n", &l);
          */
        }
        else if ((unsigned char)buf[j] == '\r') {
          /*
          apr_size_t l = 2;
          apr_file_write(worker->out, "\\r", &l);
          */
        }
        else if ((unsigned char)buf[j] < 0x20) {
          apr_file_putc('.', worker->out);
        }
        else {
          apr_file_putc(buf[j], worker->out);
        }
      }
      if (worker->log_mutex) apr_thread_mutex_unlock(worker->log_mutex);
    } while (i < len);
  }
  apr_file_flush(worker->out);
}

