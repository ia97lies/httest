#!/bin/bash

LIST=$1

TEMPLATE=src/modules.c.tmpl
TARGET=modules.c

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

//MODULES_DECLARATION//

module_t modules[] = {
  //MODULES_REGISTRATION//
  { NULL }
};

EOF

for I in $LIST; do
  sed < $TARGET >${TARGET}.tmp \
    -e "s/\/\/MODULES_DECLARATION\/\//\/\/MODULES_DECLARATION\/\/\napr_status_t ${I}_module_init(global_t *global);/g" \
    -e "s/\/\/MODULES_REGISTRATION\/\//\/\/MODULES_REGISTRATION\/\/\n  { ${I}_module_init },/g"
  mv ${TARGET}.tmp $TARGET 
done
