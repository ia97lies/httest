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
 * Implementation of the HTTP Test Tool regex.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <pcre.h>

#include <apr.h>
#include <apr_strings.h>

#include "defines.h"
#include "regex.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

struct regex_s {
  const char *pattern;
  int match;
  void *re_pcre;
  apr_size_t re_nsub;
  apr_size_t re_erroffset;
};

#ifndef POSIX_MALLOC_THRESHOLD
#define POSIX_MALLOC_THRESHOLD (10)
#endif


/************************************************************************
 * Forward declaration 
 ***********************************************************************/

static apr_status_t regex_cleanup(void *preg); 


/************************************************************************
 * Implementation 
 ***********************************************************************/

/**
 * Compile a pattern to a regular expression
 *
 * @param p IN pool
 * @param pattern IN pattern to compile
 * @param error IN error string
 * @param erroff IN offset into pattern wherer compilation fails
 *
 * @return regular express on success else NULL
 */
regex_t *pregcomp(apr_pool_t * p, const char *pattern,
                  const char **error, int *erroff) {
  regex_t *preg = apr_palloc(p, sizeof *preg);

  preg->match = 0;
  preg->pattern = apr_pstrdup(p, pattern);

  preg->re_pcre = pcre_compile(pattern, 0, error, erroff, NULL);
  preg->re_erroffset = *erroff;

  if (preg->re_pcre == NULL)
    return NULL;

  pcre_fullinfo((const pcre *)preg->re_pcre, NULL, PCRE_INFO_CAPTURECOUNT, &(preg->re_nsub));

  apr_pool_cleanup_register(p, (void *) preg, regex_cleanup,
                            apr_pool_cleanup_null);

  return preg;
}

/**
 * Execute a string on a compiled regular expression
 *
 * @param preg IN regular expression
 * @param data IN data to parse
 * @param len IN data length
 * @param nmatch IN number of matches
 * @param pmatch IN offest of matched substrings
 * @param eflags IN extended flags see pcre.h
 *
 * @return 0 on success
 */
int regexec(regex_t * preg, const char *data, apr_size_t len,
            apr_size_t nmatch, regmatch_t pmatch[], int eflags) {
  int rc;
  int options = 0;
  int *ovector = NULL;
  int small_ovector[POSIX_MALLOC_THRESHOLD * 3];
  int allocated_ovector = 0;

  ((regex_t *) preg)->re_erroffset = (apr_size_t) (-1); /* Only has meaning after compile */

  if (nmatch > 0) {
    if (nmatch <= POSIX_MALLOC_THRESHOLD) {
      ovector = &(small_ovector[0]);
    }
    else {
      ovector = (int *) malloc(sizeof(int) * nmatch * 3);
      allocated_ovector = 1;
    }
  }

  rc = pcre_exec((const pcre *) preg->re_pcre, NULL, data,
                 len, 0, options, ovector, nmatch * 3);

  if (rc == 0)
    rc = nmatch;                /* All captured slots were filled in */

  if (rc >= 0) {
    apr_size_t i;
    for (i = 0; i < (apr_size_t) rc; i++) {
      pmatch[i].rm_so = ovector[i * 2];
      pmatch[i].rm_eo = ovector[i * 2 + 1];
    }
    if (allocated_ovector)
      free(ovector);
    for (; i < nmatch; i++)
      pmatch[i].rm_so = pmatch[i].rm_eo = -1;
    ++preg->match;
    return 0;
  }
  else {
    if (allocated_ovector)
      free(ovector);
    return rc;
  }
}

/**
 * returns number of matches on this regular expression
 *
 * @param preg IN regular expression
 *
 * @return number of matches
 */
int regdidmatch(regex_t * preg) {
  return preg->match;
}

/**
 * return pattern of compiled regex
 * @param preg IN regular expression
 * @return pattern
 */
const char *regexpattern(regex_t *reg) {
  return reg->pattern;
}

/**
 * Clean up function for pool cleanup
 *
 * @preg IN compiled regular expression
 *
 * @return APR_SUCCESS
 */
static apr_status_t regex_cleanup(void *preg) {
  pcre_free(((regex_t *) preg)->re_pcre);
  return APR_SUCCESS;
}

