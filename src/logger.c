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
#include "appender.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct logger_s {
  int mode;
  int id;
  int group;
  const char *file_and_line;
  apr_thread_mutex_t *mutex;
  appender_t *appender;
};

/************************************************************************
 * Forward declaration 
 ***********************************************************************/


/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * Constructor for logger
 * @param pool IN pool
 * @param mode IN logger mode set outside
 * @param id IN thread id 
 * @return logger
 */
logger_t *logger_new(apr_pool_t *pool, int mode, int id) {
  logger_t *logger = apr_pcalloc(pool, sizeof(*logger));
  logger->mode = mode;
  logger->id = id;

  return logger;
}

/**
 * Clone an existing logger
 * @param mode IN logger mode set outside
 * @param out IN output file descriptor
 * @param err IN output error file descriptor
 * @return logger
 */
logger_t *logger_clone(apr_pool_t *pool, logger_t *origin, int id) {
  logger_t *logger = logger_new(pool, origin->mode, id);
  logger->mutex = origin->mutex;
  logger->group = origin->group;
  logger->appender = origin->appender;
  return logger;
}

/**
 * Add an appender
 * @param logger IN instance
 * @param appender IN appender to add
 */
void logger_add_appender(logger_t *logger, appender_t *appender) {
  logger->appender = appender;
}

/**
 * Update internal stuff id can change from command to command
 * @param logger IN logger instance
 * @param file_and_line IN file and line string
 */
void logger_update(logger_t *logger, const char *file_and_line) {
  logger->file_and_line = file_and_line;
}

/**
 * Set group id
 * @param logger IN logger instance
 * @param group IN group id
 */
void logger_set_group(logger_t *logger, int group) {
  logger->group = group;
}

/**
 * a simple log mechanisme with va args
 * @param logger IN thread data object
 * @param mode IN log mode
 *                LOG_DEBUG for a lot of infos
 *                LOG_INFO for much infos
 *                LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void logger_log_va(logger_t * logger, int mode, char *fmt, va_list va) {
  if (logger->mode >= mode) {
    char *tmp;
    apr_pool_t *pool;

    apr_pool_create(&pool, NULL);
    if (logger->mutex) apr_thread_mutex_lock(logger->mutex);
    if (mode == LOG_ERR) {
      tmp = apr_pvsprintf(pool, fmt, va);
      tmp = apr_psprintf(pool, "%s: error: %s", 
                         logger->file_and_line?logger->file_and_line:"<none>",
                         tmp);
      appender_print(logger->appender, 1, logger->id, logger->group, '=', NULL, 
                     tmp, strlen(tmp));
    }
    else {
      tmp = apr_pvsprintf(pool, fmt, va);
      appender_print(logger->appender, 0, logger->id, logger->group, '=', NULL, 
                     tmp, strlen(tmp));
    }
    if (logger->mutex) apr_thread_mutex_unlock(logger->mutex);
    apr_pool_destroy(pool);
  }
}

/**
 * a simple log mechanisme
 * @param logger IN thread data object
 * @param mode IN log mode
 *                LOG_DEBUG for a lot of infos
 *                LOG_INFO for much infos
 *                LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void logger_log(logger_t * logger, int mode, char *fmt, ...) {
  va_list va;
  va_start(va, fmt);
  logger_log_va(logger, mode, fmt, va);
  va_end(va);
}

/**
 * a simple error log mechanisme
 * @param logger IN thread data object
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */
void logger_log_error(logger_t * logger, char *fmt, ...) {

  if (logger->mode >= LOG_ERR) {
    va_list va;
    va_start(va, fmt);
    logger_log_va(logger, LOG_ERR, fmt, va);
    va_end(va);
  }
}

/**
 * a simple log buf mechanisme
 * @param logger IN thread data object
 * @param mode IN log mode
 *                LOG_DEBUG for a lot of infos
 *                LOG_INFO for much infos
 *                LOG_ERR for only very few infos
 * @param dir IN <,>,+,=
 * @param buf IN buf to print (binary data allowed)
 * @param len IN buf len
 */
void logger_log_buf(logger_t * logger, int mode, char dir, const char *buf,
                    apr_size_t len) {

  if (logger->mode >= mode) {
    appender_print(logger->appender, 0, logger->id, logger->group, dir, NULL, 
                   buf, len);
  }
}

/**
 * Set log mode
 * @param logger IN logger instance
 * @param mode IN log mode
 */
void logger_set_mode(logger_t *logger, int mode) {
  logger->mode = mode;
}
/**
 * Get log mode
 * @param logger IN logger instance
 */
int logger_get_mode(logger_t *logger) {
  return logger->mode;
}
