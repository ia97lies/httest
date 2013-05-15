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
 * Implementation of the HTTP Test Tool simple appender.
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


/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct appender_simple_s {
  apr_file_t *out;
} appender_simple_t;

/************************************************************************
 * Forward declaration 
 ***********************************************************************/
void appender_simple_printer(appender_t *appender, int mode, const char *pos,
                             int thread, int group, char dir, const char *custom,
                             const char *buf, apr_size_t len);

/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * Constructor for simple appender
 * @param pool IN pool
 * @param out IN output file
 * @return appender
 */
appender_t *appender_simple_new(apr_pool_t *pool, apr_file_t *out) {
  appender_t *appender;
  appender_simple_t *simple = apr_pcalloc(pool, sizeof(*simple));
  simple->out = out;
  appender = appender_new(pool, appender_simple_printer, simple);

  return appender;
}

/**
 * Simple appender printer
 * @param appender IN appender instance
 * @param mode IN mode 
 * @param thread IN thread id
 * |@param group IN group id
 * @param dir IN >,<,+,=
 * @param custom IN custom string
 * @param buf IN buffer to print
 * @param len IN buffer len
 */
void appender_simple_printer(appender_t *appender, int mode, const char *pos,
                             int thread, int group, char dir, const char *custom, 
                             const char *buf, apr_size_t len) {
  appender_simple_t *simple = appender_get_user_data(appender);

  if (!buf) {
    buf = "";
    len = strlen(buf);
  }


  if (simple->out) {
    apr_size_t i = 0;
    apr_size_t j = 0;
    do {
      for (; i < len && buf[i] != '\n'; i++); 
      ++i;
      apr_file_printf(simple->out, "\n%c:", dir);

      for (; j < i; j++) {
        if ((unsigned char)buf[j] == '\n') {
        }
        else if ((unsigned char)buf[j] == '\r') {
        }
        else if ((unsigned char)buf[j] == '\0') {
        }
        else if ((unsigned char)buf[j] < 0x20) {
          apr_file_putc('.', simple->out);
        }
        else {
          apr_file_putc(buf[j], simple->out);
        }
      }
      apr_file_flush(simple->out);
    } while (i < len);
  }
}

