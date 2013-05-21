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
typedef struct logger_entry_s {
  int lo_mode;
  int hi_mode;
  appender_t *appender;
} logger_entry_t;

struct logger_s {
  apr_pool_t *pool;
  int mode;
  int id;
  int group;
  apr_table_t *appenders;
  int lo_mode;
  int hi_mode;
  appender_t *appender;
};

/************************************************************************
 * Forward declaration 
 ***********************************************************************/
static void logger_print(logger_t *logger, int mode, const char *pos, 
                         int thread, int group, char dir, const char *custom, 
                         const char *buf, apr_size_t len);

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
  logger->pool = pool;
  logger->appenders = apr_table_make(pool, 5);

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
  logger->group = origin->group;
  logger->appender = origin->appender;
  logger->hi_mode = origin->hi_mode;
  logger->lo_mode = origin->lo_mode;
  logger->pool = pool;
  logger->appenders = apr_table_copy(pool, origin->appenders);
  return logger;
}

/**
 * Add an appender
 * @param logger IN instance
 * @param appender IN appender to add
 * @param name IN appender name
 * @param lo_mode IN the higgest mode
 * @param hi_mode IN the lowest mode
 */
void logger_set_appender(logger_t *logger, appender_t *appender, 
                         const char *name, int lo_mode, int hi_mode) {
  logger_entry_t *entry = apr_pcalloc(logger->pool, sizeof(*entry));
  entry->lo_mode = lo_mode;
  entry->hi_mode = hi_mode;
  entry->appender = appender;
  apr_table_setn(logger->appenders, apr_pstrdup(logger->pool, name), 
                 (void *)entry);
}

/**
 * Delete given appender
 * @param logger IN instance
 * @param name IN name of appender to delete
 */
void logger_del_appender(logger_t *logger, const char *name) {
  apr_table_unset(logger->appenders, name);
}

/**
 * Set group id
 * @param logger IN logger instance
 * @param group IN group id
 */
void logger_set_group(logger_t *logger, int group) {
  logger->group = group;
}

static void logger_print(logger_t *logger, int mode, const char *pos, 
                         int thread, int group, char dir, const char *custom, 
                         const char *buf, apr_size_t len) {
  int i;
  apr_table_entry_t *e;

  e = (apr_table_entry_t *) apr_table_elts(logger->appenders)->elts;
  for (i = 0; i < apr_table_elts(logger->appenders)->nelts; ++i) {
    logger_entry_t *le = (void *)e[i].val;
    if (mode <= le->hi_mode && mode >= le->lo_mode) {
      appender_print(le->appender, mode, pos, logger->id, logger->group, dir, custom, 
                     buf, len);
    }
  }
}

/**
 * a simple log mechanisme with va args
 * @param logger IN thread data object
 * @param mode IN log mode
 *                LOG_DEBUG for a lot of infos
 *                LOG_INFO for much infos
 *                LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param va IN params for format strings as va_list
 */
void logger_log_va(logger_t * logger, int mode, const char *pos, char *fmt, 
                   va_list va) {
  if (logger->mode >= mode) {
    char *tmp;
    apr_pool_t *pool;

    apr_pool_create(&pool, NULL);
    tmp = apr_pvsprintf(pool, fmt, va);
    logger_print(logger, mode, pos, logger->id, logger->group, '=', NULL, tmp, 
                 strlen(tmp));
    apr_pool_destroy(pool);
  }
}
 
/**
 * log formated 
 * @param worker IN thread data object
 * @param mode IN log mode
 *                LOG_DEBUG for a lot of infos
 *                LOG_INFO for much infos
 *                LOG_ERR for only very few infos
 * @param fmt IN printf format string
 * @param ... IN params for format strings
 */

void logger_log(logger_t * logger, int log_mode, const char *pos, char *fmt, 
                ...) {
  va_list va;
  va_start(va, fmt);
  logger_log_va(logger, log_mode, pos, fmt, va);
  va_end(va);
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
    logger_print(logger, mode, NULL, logger->id, logger->group, dir, NULL, buf, len);
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
