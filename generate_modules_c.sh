#!/bin/bash

LIST=$1

TARGET=src/htt_modules.c

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

#include "htt_modules.h"

extern htt_module_t htt_modules[];

/* MODULES_DECLARATION */
EOF

for I in $LIST; do
  echo "apr_status_t ${I}_module_init(htt_t *htt);" >> $TARGET
done

cat >> $TARGET << EOF

htt_module_t htt_modules[] = {
  /* MODULES_REGISTRATION */
EOF

for I in $LIST; do
  echo "  { ${I}_module_init }," >> $TARGET
done

cat >> $TARGET << EOF
  { NULL }
};

apr_status_t htt_modules_init(htt_t *htt) {
  int i;

  for (i = 0; htt_modules[i].module_init; i++) {
    apr_status_t status;
    if ((status = htt_modules[i].module_init(htt)) != APR_SUCCESS) {
      return status;
    }
  }
  return APR_SUCCESS;
}

EOF

