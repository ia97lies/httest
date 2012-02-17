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

/**
 * @file
 *
 * @Author christian liesch <liesch@gmx.ch>
 *
 * Implementation of the HTTP Test Tool util.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <config.h>
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_env.h>

#include "defines.h"
#include "util.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/


/************************************************************************
 * Forward declaration 
 ***********************************************************************/


/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * This function is taken from apr. The apr_tokenize_to_argv do remove
 * all leftover "\", but this breaks up my httest completly.
 *
 * @param pool IN Context from which pool allocations will occur.
 * @arg_str IN Input argument string for conversion to argv[].
 * @argv_out IN Output location. This is a pointer to an array
 *              of pointers to strings (ie. &(char *argv[]).
 *              This value will be allocated from the contexts
 *              pool and filled in with copies of the tokens
 *              found during parsing of the arg_str. 
 * @param with_quotes IN do not strip quotes from quoted string
 *
 * @return SUCCESS
 */
apr_status_t my_tokenize_to_argv(const char *arg_str, char ***argv_out,
                                 apr_pool_t *pool, int with_quotes)
{
    const char *cp;
    const char *ct;
    int isquoted, numargs = 0, argnum;

#define SKIP_WHITESPACE(cp) \
    for ( ; *cp == ' ' || *cp == '\t'; ) { \
        cp++; \
    };

#define CHECK_QUOTATION(cp,isquoted) \
    isquoted = 0; \
    if (*cp == '"') { \
        isquoted = 1; \
        cp++; \
    } \
    else if (*cp == '\'') { \
        isquoted = 2; \
        cp++; \
    }

/* DETERMINE_NEXTSTRING:
 * At exit, cp will point to one of the following:  NULL, SPACE, TAB or QUOTE.
 * NULL implies the argument string has been fully traversed.
 */
#define DETERMINE_NEXTSTRING(cp,isquoted) \
    for ( ; *cp != '\0'; cp++) { \
        if (   (*cp == '\\' && (*(cp+1) == ' ' || *(cp+1) == '\t' || \
                                *(cp+1) == '"' || *(cp+1) == '\''))) { \
            cp++; \
            continue; \
        } \
        if (   (!isquoted && (*cp == ' ' || *cp == '\t')) \
            || (isquoted == 1 && *cp == '"') \
            || (isquoted == 2 && *cp == '\'')                 ) { \
            break; \
        } \
    }
 
    cp = arg_str;
    SKIP_WHITESPACE(cp);
    ct = cp;

    /* This is ugly and expensive, but if anyone wants to figure a
     * way to support any number of args without counting and 
     * allocating, please go ahead and change the code.
     *
     * Must account for the trailing NULL arg.
     */
    numargs = 1;
    while (*ct != '\0') {
        CHECK_QUOTATION(ct, isquoted);
        DETERMINE_NEXTSTRING(ct, isquoted);
        if (*ct != '\0') {
            ct++;
        }
        numargs++;
        SKIP_WHITESPACE(ct);
    }
    *argv_out = apr_palloc(pool, numargs * sizeof(char*));

    /*  determine first argument */
    for (argnum = 0; argnum < (numargs-1); argnum++) {
        SKIP_WHITESPACE(cp);
        CHECK_QUOTATION(cp, isquoted);
        ct = cp;
        DETERMINE_NEXTSTRING(cp, isquoted);
        cp++;
        /* do not swallow quotes */
        if (isquoted && with_quotes) {
          (*argv_out)[argnum] = apr_palloc(pool, (cp+1) - (ct-1));
          apr_cpystrn((*argv_out)[argnum], ct-1, (cp+1) - (ct-1));
        }
        else {
          (*argv_out)[argnum] = apr_palloc(pool, cp - ct);
          apr_cpystrn((*argv_out)[argnum], ct, cp - ct);
        }
    }
    (*argv_out)[argnum] = NULL;

    return APR_SUCCESS;
}

/**
 * @deprecitated: should do everything with new my_get_args
 * get a string starting/ending with a char, unescape this char if found as an 
 * escape sequence.
 *
 * @param string IN <char><string with escaped <char>><char>
 * @param last OUT pointer to next char after cutted string
 *
 * @return <string with unescaped <char>>
 * @note: Example: "foo bar \"hallo velo\"" -> foo bar "hallo velo"
 */
char *my_unescape(char *string, char **last) {
  char *result;
  char enclose;
  apr_size_t i;
  apr_size_t j;
  apr_size_t len;

  if (!string) {
    return string;
  }
  
  len = strlen(string);
  
  enclose = string[0];
  result = string;
  for (i = 1, j = 0; i < len; i++, j++) {
    /* check if we have an escape char */
    if (string[i] == '\\') {
      /* lookahead */
      ++i;
      /* if lookahead is not \ or " store the \ too, else skip */
      if (string[i] != '\\' && string[i] != enclose) {
	result[j] = '\\';
	++j;
      }
    }
    /* break if we got the first char unescaped */
    else if (string[i] == enclose) {
      ++i;
      break;
    }
    /* store char in result */
    result[j] = string[i];
  }
  result[j] = 0;
  *last = &string[i]; 
  return result;
}

/**
 * Deep table copy
 *
 * @param p IN pool
 * @param orig IN orig table
 *
 * @return copy of orig
 */
apr_table_t *my_table_deep_copy(apr_pool_t *p, apr_table_t *orig) {
  apr_table_entry_t *e;
  apr_table_t *dest;
  int i;
  apr_size_t size;

  if (!orig) {
    dest = apr_table_make(p, 5);
    return dest;
  }

  size  = apr_table_elts(orig)->nelts;

  if (size < 5) {
    size = 5;
  }
  dest = apr_table_make(p, size);
  e = (apr_table_entry_t *) apr_table_elts(orig)->elts;
  for (i = 0; i < apr_table_elts(orig)->nelts; ++i) {
    apr_table_add(dest, e[i].key, e[i].val);
  }

  return dest;
}

/**
 * Swallow table copy
 *
 * @param p IN pool
 * @param orig IN orig table
 *
 * @return copy of orig
 */
apr_table_t *my_table_swallow_copy(apr_pool_t *p, apr_table_t *orig) {
  apr_table_entry_t *e;
  apr_table_t *dest;
  int i;
  apr_size_t size;
    
  if (!orig) {
    dest = apr_table_make(p, 5);
    return dest;
  }

  size  = apr_table_elts(orig)->nelts;

  if (size < 5) {
    size = 5;
  }
  dest = apr_table_make(p, size);
  e = (apr_table_entry_t *) apr_table_elts(orig)->elts;
  for (i = 0; i < apr_table_elts(orig)->nelts; ++i) {
    apr_table_addn(dest, apr_pstrdup(p, e[i].key), e[i].val);
  }

  return dest;
}

/**
 * get the status string
 *
 * @param p IN pool
 * @param rc IN status to print
 *
 * @return status string
 */
char *my_status_str(apr_pool_t * p, apr_status_t rc) {
  char *text = apr_pcalloc(p, 201);
  apr_strerror(rc, text, 200);
  return text;
}


/**
 * splits arguments into a table
 *
 * @param line IN string of params
 * @param params INOUT table to store params
 */
void my_get_args(char *line, store_t *params, apr_pool_t *pool) {
  int i; 
  char **argv;

  if (my_tokenize_to_argv(line, &argv, pool, 0) == APR_SUCCESS) {
    for (i = 0; argv[i] != NULL; i++) {
      /* store value by his index */
      store_set(params, apr_itoa(pool, i), argv[i]);
    }
  }
}

/**
 * display copyright information
 *
 * @param program name
 */
void copyright(const char *progname) {
  printf("%s " PACKAGE_VERSION "\n", progname);
  printf("\nCopyright (C) 2006 Free Software Foundation, Inc.\n"
         "This is free software; see the source for copying conditions.  There is NO\n"
	 "warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n");
  printf("\nWritten by Christian Liesch\n");
}

/**
 * filename
 *
 * @param path IN path to file
 *
 * @return last part of path
 */
const char *filename(apr_pool_t *pool, const char *path) {
  char *tmp;
  char *elem;
  char *last;
  
  char *old = NULL;

  tmp = apr_pstrdup(pool, path);
  elem = apr_strtok(tmp, "/", &last);
  while (elem) {
    old = elem;
    elem = apr_strtok(NULL, "/", &last);
  }

  return old;
} 

/**
 * 2 hex digit number to char borowed from apache sourc
 *
 * @param what IN hex to convert
 *
 * @return char
 */
char x2c(const char *what) {
  register char digit;

#if !APR_CHARSET_EBCDIC
  digit = ((what[0] >= 'A') ? ((what[0] & 0xdf) - 'A') + 10
	   : (what[0] - '0'));
  digit *= 16;
  digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10
	    : (what[1] - '0'));
#else /*APR_CHARSET_EBCDIC*/
  char xstr[5];
  xstr[0]='0';
  xstr[1]='x';
  xstr[2]=what[0];
  xstr[3]=what[1];
  xstr[4]='\0';
  digit = apr_xlate_conv_byte(ap_hdrs_from_ascii,
			      0xFF & strtol(xstr, NULL, 16));
#endif /*APR_CHARSET_EBCDIC*/
  return (digit);
}

