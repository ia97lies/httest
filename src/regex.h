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
 * Interface of the HTTP Test Tool regex.
 */

#ifndef HTTEST_REGEX_H
#define HTTEST_REGEX_H

typedef struct regex_s regex_t;
typedef struct regmatch_s regmatch_t;
struct regmatch_s {
  int rm_so;
  int rm_eo;
};

regex_t *pregcomp(apr_pool_t * p, const char *pattern,
                  const char **error, int *erroff); 
int regexec(regex_t * preg, const char *data, apr_size_t len,
            apr_size_t nmatch, regmatch_t pmatch[], int eflags); 
int regdidmatch(regex_t * preg); 
const char *regexpattern(regex_t *reg);

#endif
