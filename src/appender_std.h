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
 * Interface of the HTTP Test Tool standard appender
 */

#ifndef HTTEST_APPENDER_STD_H
#define HTTEST_APPENDER_STD_H

#include "appender.h"

#define APPENDER_STD_NONE 0x00
#define APPENDER_STD_THREAD_NO 0x01
#define APPENDER_STD_COLOR 0x02

appender_t *appender_std_new(apr_pool_t *pool, apr_file_t *out, 
                             apr_file_t *err, int flags);

#endif
