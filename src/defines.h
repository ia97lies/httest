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
 * Global defines for the HTTP Test Tool.
 */

#ifndef HTTEST_DEFINES_H
#define HTTEST_DEFINES_H

#define BLOCK_MAX 8192
#define VAR_ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

#define USE_SSL

/* even httest requires APR >= 1.3, these HT_* macros
 * provides the compatibility to APR 1.2 allowing the
 * latest version of httest to be on older Linux
 * distributions, e.g. CentOS 5) */
#if (APR_MAJOR_VERSION <= 1)
#if (APR_MINOR_VERSION <= 2)
#define HT_POOL_CREATE(p) apr_pool_create(p, NULL)
#define HT_OPEN_STDERR(f, o, p) { int _lfd = STDERR_FILENO; \
    apr_os_file_put(f, &_lfd, o | APR_FOPEN_WRITE, p); }
#define HT_OPEN_STDOUT(f, o, p) { int _lfd = STDOUT_FILENO; \
    apr_os_file_put(f, &_lfd, o | APR_FOPEN_WRITE, p); }
#endif
#endif
#ifndef HT_POOL_CREATE
#define HT_POOL_CREATE(p) apr_pool_create_unmanaged_ex(p, NULL, NULL)
#define HT_OPEN_STDERR(f, o, p) apr_file_open_flags_stderr(f, o, p)
#define HT_OPEN_STDOUT(f, o, p) apr_file_open_flags_stdout(f, o, p)
#endif

#if defined(WIN32)
typedef unsigned long uint32_t; 
typedef long long uint64_t;
typedef unsigned long uint32_t;
typedef long int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
#endif
#endif
