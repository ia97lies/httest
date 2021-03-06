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
  apr_file_t *out;
} appender_std_t;

#define APPENDER_STD_PFX "                      "

/* \e is not ESC on windows */
#define ESC "\x1b"

/************************************************************************
 * Forward declaration 
 ***********************************************************************/
void appender_std_printer(appender_t *appender, int mode, const char *pos,
                          int thread, int group, char dir, const char *custom,
                          const char *buf, apr_size_t len);

/************************************************************************
 * Implementation
 ***********************************************************************/
static void appender_std_prefix(appender_std_t *std, int mode, const char *pos,
                                int thread, int group, char dir, 
                                const char *custom) {
  /* check if prefix is needed */
  if (dir == '-') {
    return;
  }

  /* set color on dir \e[1;31mFAILED\e[0m */
  if (std->flags & APPENDER_STD_COLOR) {
    if (dir == '<') {
      apr_file_printf(std->out, "\x1b[0;35m");
    }
    else if (dir == '>') {
      apr_file_printf(std->out, "\x1b[0;34m");
    }
  }

  if (std->flags & APPENDER_STD_THREAD_NO) {
    apr_file_printf(std->out, "\n%d:", thread);
  }
  else {
    apr_file_printf(std->out, "\n");
  }
  if (mode == LOG_ERR) {
    if (pos) {
      apr_file_printf(std->out, "%s: error: ", pos);
    }
    else {
      apr_file_printf(std->out, "error: ");
    }
  }
  else {
    int i;
    for (i = 0; i < group; i++) {
      apr_file_printf(std->out, APPENDER_STD_PFX);
    }
  }
  if (dir == '>' || dir == '<' || dir == '+') {
    apr_file_putc(dir, std->out);
  }
}

/**
 * Constructor for std appender
 * @param pool IN pool
 * @param out IN output file
 * @param flags IN APPENDER_STD_THREAD_NO: print thread no
 *                 APPENDER_STD_COLOR: print colored
 *                 APPENDER_NONE: no extention
 * @return appender
 */
appender_t *appender_std_new(apr_pool_t *pool, apr_file_t *out, int flags) {
  appender_t *appender;
  appender_std_t *std = apr_pcalloc(pool, sizeof(*std));
  std->out = out;
  std->flags = flags;
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
  appender_std_t *std = appender_get_user_data(appender);

  if (!buf) {
    buf = "";
    len = strlen(buf);
  }

  if (std->out) {
    apr_size_t i = 0;
    apr_size_t j = 0;
    do {
      int mark = 0;
      for (; i < len && buf[i] != '\n'; i++) {
        if ((unsigned char)buf[i] < 0x20) {
          mark = 1;
        }
      }
      appender_lock(appender);
      appender_std_prefix(std, mode, pos, thread, group, dir, custom);
      if (mark) {
        for (; j < i; j++) {
          if ((unsigned char)buf[j] == '\n' ||
              (unsigned char)buf[j] == '\r' || 
              (unsigned char)buf[j] == '\0') {
            /* do nothing */
          }
          else if ((unsigned char)buf[j] < 0x20) {
            apr_file_putc('.', std->out);
          }
          else {
            apr_file_putc(buf[j], std->out);
          }
        }
      }
      else {
        apr_size_t l = i-j;
        apr_file_write(std->out, &buf[j], &l);
        j += l;
      }
      ++i;
      ++j;
      if (std->flags & APPENDER_STD_COLOR) {
        apr_file_printf(std->out, ESC "[0m");
      }
      apr_file_flush(std->out);
      appender_unlock(appender);
    } while (i < len);
  }
}

