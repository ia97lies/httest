/**
 * Copyright 2010 Christian Liesch
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
 * Implementation of the HTTP Test Tool exception module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_strings.h>
#include "htt_modules.h"
#include "htt_defines.h"
#include "htt_core.h"
#include "htt_string.h"
#include "htt_util.h"
#include "htt_expr.h"
#include "htt_function.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t exception_module_init(htt_t *htt) {
  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/

