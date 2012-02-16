#!/bin/bash

LIST=$1

TEMPLATE=src/modules.c.tmpl
TARGET=src/modules.c

#init
cat > $TARGET << EOF
/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "module.h"

extern module_t modules[];

/* MODULES_DECLARATION */
apr_status_t sys_module_init(global_t *global);
apr_status_t math_module_init(global_t *global);
apr_status_t coder_module_init(global_t *global);
apr_status_t date_module_init(global_t *global);
apr_status_t binary_module_init(global_t *global);
apr_status_t websocket_module_init(global_t *global);
apr_status_t socks_module_init(global_t *global);
apr_status_t udp_module_init(global_t *global);
apr_status_t tcp_module_init(global_t *global);
apr_status_t ssl_module_init(global_t *global);

module_t modules[] = {
  /* MODULES_REGISTRATION */
  { sys_module_init },
  { math_module_init },
  { coder_module_init },
  { date_module_init },
  { binary_module_init },
  { websocket_module_init },
  { socks_module_init },
  { udp_module_init },
  { tcp_module_init },
  { ssl_module_init },
  { NULL }
};

EOF

for I in $LIST; do
  echo $I
  awk -v i=$I '
    /.*/ { print $0 }
    /\/\/MODULES_DECLARATION\/\// { printf("apr_status_t %s_module_init(global_t *global);\n", i); }
    /\/\/MODULES_REGISTRATION\/\// { printf("  { %s_module_init },\n", i); }
    ' < $TARGET >${TARGET}.tmp
  mv ${TARGET}.tmp $TARGET 
done

