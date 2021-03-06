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
 * Implementation of the HTTP Test Tool log appender.
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

#include "appender.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
struct appender_s {
  printer_f printer;
  void *user_data;
  apr_thread_mutex_t *mutex;
};

/************************************************************************
 * Forward declaration 
 ***********************************************************************/


/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * Constructor for log appender
 * @param pool IN pool
 * @param printer IN printer function
 * @param user_data IN user_data for printing
 * @return appender
 */
appender_t *appender_new(apr_pool_t *pool, printer_f printer, void *user_data) {
  appender_t *appender = apr_pcalloc(pool, sizeof(*appender));
  appender->user_data = user_data;
  appender->printer = printer;

  return appender;
}

/**
 * Get user data
 * @param appender IN instance
 * @return user_data pointer
 */
void *appender_get_user_data(appender_t *appender) {
  return appender->user_data;
}

/**
 * Set mutex to std appender
 * @param appender IN appender instance
 * @param mutex IN mutex
 * @note: If set to NULL, no lock can be draw
 */
void appender_set_mutex(appender_t *appender, apr_thread_mutex_t *mutex) {
  appender->mutex = mutex;
}

/**
 * Get registered mutex
 * @param appender IN appender instance
 * @return mutex
 */
apr_thread_mutex_t *appender_get_mutex(appender_t *appender) {
  return appender->mutex;
}

void appender_lock(appender_t *appender) {
  if (appender->mutex) apr_thread_mutex_lock(appender->mutex);
}

void appender_unlock(appender_t *appender) {
  if (appender->mutex) apr_thread_mutex_unlock(appender->mutex);
}

/**
 * Print buf
 * @param appender IN appender instance
 * @param mode IN one of the defined mode int logger.h
 * @param pos IN filename and position or NULL if none
 * @param thread IN thread id
 * @param group IN group id
 * @param dir IN <,>,+,=
 * @param custom IN custom string may be NULL
 * @param buf IN buffer to print
 * @param len IN buffer length
 */
void appender_print(appender_t *appender, int mode, const char *pos, 
                    int thread, int group, char dir, const char *custom, 
                    const char *buf, apr_size_t len) {
  if (appender->printer) {
    appender->printer(appender, mode, pos, thread, group, dir, custom, buf, len);
  }
}

