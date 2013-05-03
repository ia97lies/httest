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
 * Implementation of the HTTP Test Tool std appender.
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
#include "appender_std.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct appender_std_s {
  int flags;
  apr_thread_mutex_t *mutex;
  apr_file_t *out;
  apr_file_t *err;
} appender_std_t;

#define APPENDER_STD_PFX "                      "

/************************************************************************
 * Forward declaration 
 ***********************************************************************/
void appender_std_printer(appender_t *appender, int mode, const char *pos,
                          int thread, int group, char dir, const char *custom,
                          const char *buf, apr_size_t len);

/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * Constructor for std appender
 * @param pool IN pool
 * @param out IN output file
 * @param err IN error output file
 * @param flags IN APPENDER_STD_THREAD_NO: print thread no
 *                 APPENDER_STD_COLOR: print colored
 *                 APPENDER_NONE: no extention
 * @return appender
 */
appender_t *appender_std_new(apr_pool_t *pool, apr_file_t *out, 
                             apr_file_t *err, int flags) {
  appender_t *appender;
  appender_std_t *std = apr_pcalloc(pool, sizeof(*std));
  std->out = out;
  std->err = err;
  std->flags = flags;
  if (apr_thread_mutex_create(&std->mutex, APR_THREAD_MUTEX_DEFAULT,
                              pool) != APR_SUCCESS) {
    apr_file_printf(std->err, "\nCould not create log mutex");
    return NULL;
  }

  appender = appender_new(pool, appender_std_printer, std);

  return appender;
}

/**
 * Simple appender printer
 * @param appender IN appender instance
 * @param is_error IN error
 * @param thread IN thread id
 * |@param group IN group id
 * @param dir IN >,<,+,=
 * @param custom IN custom string
 * @param buf IN buffer to print
 * @param len IN buffer len
 */
void appender_std_printer(appender_t *appender, int mode, const char *pos,
                          int thread, int group, char dir, const char *custom, 
                          const char *buf, apr_size_t len) {
  apr_size_t i;
  apr_size_t j;
  apr_size_t k;
  char *null="";
  apr_file_t *cur;
  appender_std_t *std = appender_get_user_data(appender);

  if (!buf) {
    buf = null;
    len = strlen(buf);
  }

  if (mode == LOG_ERR) {
    cur = std->err;
  }
  else {
    cur = std->out;
  }

  i = 0;
  j = 0;
  do {
    for (; i < len && buf[i] != '\n'; i++); 
    ++i;
    /* set color on dir \e[1;31mFAILED\e[0m */
    apr_thread_mutex_lock(std->mutex);
    if (mode != LOG_ERR) {
      if (std->flags & APPENDER_STD_THREAD_NO) {
        apr_file_printf(cur, "\n%d:", thread);
      }
      else {
        apr_file_printf(cur, "\n");
      }
    }
    else {
      if (pos) {
        apr_file_printf(cur, "\n%s: error: ", pos);
      }
      else {
        apr_file_printf(cur, "\nerror: ");
      }
    }
    for (k = 0; k < group; k++) {
      apr_file_printf(cur, APPENDER_STD_PFX);
    }
    if (dir == '>' || dir == '<' || dir == '+') {
      apr_file_printf(cur, "%c", dir);
    }

    for (; j < i; j++) {
      if ((unsigned char)buf[j] == '\n' ||
          (unsigned char)buf[j] == '\r' || 
          (unsigned char)buf[j] == '\0') {
        /* do nothing */
      }
      else if ((unsigned char)buf[j] < 0x20) {
        apr_file_putc('.', cur);
      }
      else {
        apr_file_putc(buf[j], cur);
      }
    }
    apr_file_flush(cur);
    apr_thread_mutex_unlock(std->mutex);
  } while (i < len);
}

