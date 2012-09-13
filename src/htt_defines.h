/**
 * Copyright 2012 Christian Liesch
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

#ifndef HTT_DEFINES_H
#define HTT_DEFINES_H

#define HTT_BLOCK_MAX 8192
#define HTT_ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"

#ifndef DEFAULT_THREAD_STACKSIZE
#define DEFAULT_THREAD_STACKSIZE 262144 
#endif

#define USE_SSL

#if defined(WIN32)
typedef unsigned long uint32_t; 
typedef long long uint64_t;
typedef unsigned long uint32_t;
typedef long int32_t;
typedef unsigned short uint16_t;
typedef short int16_t;
#endif
#endif
