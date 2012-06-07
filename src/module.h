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
 * Interface of the HTTP Test Tool module.
 */

#ifndef HTTEST_MODULE_H
#define HTTEST_MODULE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

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
#include <apr_env.h>

#include <pcre.h>
#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#include "defines.h"
#include "util.h"
#include "regex.h"
#include "file.h"
#include "socket.h"
#include "worker.h"
#include "module.h"

#ifdef _WINDOWS
  /* on windows the inclusion of windows.h/wincrypt.h causes
   * X509_NAME and a few more to be defined, so reincluding
   * ossl_typ.h at the end in order to undefine these...
   */
  #undef HEADER_OPENSSL_TYPES_H
  #include <openssl/ossl_typ.h>

  /* windows has no uint8_t without inclusion of stdint.h */
  typedef unsigned __int8 uint8_t;

  /* windows has no netinet/in.h */
  #define HAVE_NO_NETINET
  #include <winsock.h>

  /* for js */
  #define XP_WIN
#endif

typedef apr_status_t (*module_init_f)(global_t *global);
typedef struct module_s {
  module_init_f module_init;
} module_t;

apr_status_t module_command_new(global_t *global, const char *module, 
                                const char *command, 
				const char *short_desc, const char *desc, 
				interpret_f function); 

void * module_get_config(apr_hash_t *config, const char *module);
void module_set_config(apr_hash_t *config, const char *module, void *data); 
apr_status_t module_check_global(worker_t *worker); 

#endif
