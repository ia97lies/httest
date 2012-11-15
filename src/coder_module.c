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
 * Implementation of the HTTP Test Tool coder module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <apr_strings.h>
#include <apr_base64.h>
#include <htt_core.h>
#include <htt_executable.h>
#include <htt_context.h>
#include <htt_string.h>
#include <htt_util.h>

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct url_escape_seq {
  char c;
  char *esc;
  apr_size_t len;
} url_escape_seq_t;


/**
 * Get index of url escape sequenze array 
 *
 * @param c IN char for lookup
 *
 * @return index of url escape sequenz array
 */
static int _get_url_escape_index(char c); 

/**
 * urlenc 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_urlenc_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * urldec 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_urldec_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * urldec 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_htmldec_function(htt_executable_t *executable, 
                                          htt_context_t *context, 
                                          apr_pool_t *ptmp, htt_map_t *params, 
                                          htt_stack_t *retvars, char *line); 

/**
 * b64enc 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_b64enc_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/**
 * b64dec 
 * @param executable IN executable
 * @param context IN running context
 * @param params IN parameters
 * @param retvars IN return variables
 * @param line IN unsplitted but resolved line
 * @param apr status
 */
static apr_status_t _cmd_b64dec_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line); 

/************************************************************************
 * Globals 
 ***********************************************************************/
static url_escape_seq_t url_escape_seq[] = {
  { '?', "%3F", 3 },
  { '\n', "%0D", 3 },
  { ' ', "+", 1 },
  { '/', "%2F", 3 },
  { ';', "%3B", 3 },
  { '%', "%25", 3 },
  { '=', "%3D", 3 },
  { '"', "%22", 3 },
  { '\'', "%2C", 3 },
  { '.', "%2E", 3 },
  { ':', "%3A", 3 },
  { '@', "%40", 3 },
  { '\\', "%5C", 3 },
  { '&', "%26", 3 },
  { '+', "%2B", 3 },
};

/************************************************************************
 * Public
 ***********************************************************************/
apr_status_t coder_module_init(htt_t *htt) {
  return APR_SUCCESS;
}

apr_status_t coder_module_command_register(htt_t *htt) {
  htt_add_command(htt, "urlenc", "in : out", "<url> <result>",
                  "Url encode <url> and store it into <result>",
                  htt_cmd_line_compile, _cmd_urlenc_function);

  htt_add_command(htt, "urldec", "in : out", "<encoded url> <result>",
                  "Url decode <encoded url> and store it into <result>",
                  htt_cmd_line_compile, _cmd_urldec_function);

  htt_add_command(htt, "htmldec", "in : out", "<encoded html> <result>",
                  "Url decode <encoded html> and store it into <result>",
                  htt_cmd_line_compile, _cmd_htmldec_function);

  htt_add_command(htt, "b64enc", "in : out", "<string> <result>",
                  "base 64 encode <string> and store it into <result>",
                  htt_cmd_line_compile, _cmd_b64enc_function);

  htt_add_command(htt, "b64dec", "in : out", "<string> <result>",
                  "base 64 decode <string> and store it into <result>",
                  htt_cmd_line_compile, _cmd_b64dec_function);

  return APR_SUCCESS;
}

/************************************************************************
 * Private
 ***********************************************************************/

static apr_status_t _cmd_urlenc_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  /* do this the old way, becaus argv tokenizer removes all "\" */
  const char *string;
  char *result;
  int i;
  int j;
  int k;
  apr_size_t len;

  htt_string_t *in = htt_map_get(params, "in");

  if (!in || !htt_isa_string(in)) {
    apr_status_t status = APR_EGENERAL;
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Nothing to encode");
    return status;
  }

  string = htt_string_get(in);
  len = strlen(string);
  /* allocate worste case -> every char enc with pattern %XX */
  result = apr_pcalloc(ptmp, 3 * len + 1);

  /** do the simple stuff */
  for (j = 0, i = 0; string[i]; i++) {
    k = _get_url_escape_index(string[i]);
    if (k != -1) {
      strncpy(&result[j], url_escape_seq[k].esc, url_escape_seq[k].len);
      j += url_escape_seq[k].len;
    }
    else {
      result[j++] = string[i];
    }
  }

  htt_stack_push(retvars, htt_string_new(ptmp, result));

  return APR_SUCCESS;

}

static apr_status_t _cmd_urldec_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  /* do this the old way, becaus argv tokenizer removes all "\" */
  const char *string;
  char c;
  int i;
  int j;
  apr_size_t len;
  char *inplace;

  htt_string_t *in = htt_map_get(params, "in");

  if (!in || !htt_isa_string(in)) {
    apr_status_t status = APR_EGENERAL;
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Nothing to decode");
    return status;
  }

  string = htt_string_get(in);
  inplace = apr_pstrdup(ptmp, string);
  len = strlen(string);
  for (i = 0, j = 0; i < len; i++, j++) {
    c = string[i];
    if (string[i] == '+') {
      c = 32;
    }
    else if (string[i] == '%') {
      if (i + 2 < len) {
        c = htt_util_x2c(&string[i + 1]);
	i += 2;
      }
    }
    else if (string[i] == '\\' && i + 1 < len && string[i + 1] == 'x') {
      if (i + 3 < len) {
        c = htt_util_x2c(&string[i + 2]);
	i += 3;
      }
    }
    inplace[j] = c;
  }
  inplace[j] = 0;

  htt_stack_push(retvars, htt_string_new(ptmp, string));

  return APR_SUCCESS;
}

static apr_status_t _cmd_htmldec_function(htt_executable_t *executable, 
                                          htt_context_t *context, 
                                          apr_pool_t *ptmp, htt_map_t *params, 
                                          htt_stack_t *retvars, char *line) {
  const char *string;
  char c;
  int i;
  int j;
  apr_size_t len;
  char *inplace;


  htt_string_t *in = htt_map_get(params, "in");

  if (!in || !htt_isa_string(in)) {
    apr_status_t status = APR_EGENERAL;
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Nothing to decode");
    return status;
  }

  string = htt_string_get(in);

  inplace = apr_pstrdup(ptmp, string);
  len = strlen(string);
  for (i = 0, j = 0; i < len; i++, j++) {
      c = string[i];
      if (string[i] == '&' && i + 2 < len && string[i + 1] == '#' && 
	  string[i + 2] == 'x') {
	/* hex */
      }
      else if (string[i] == '&' && i + 1 < len && string[i + 1] == '#') {
	/* decimal */
      }
      inplace[j] = c;
    }
  inplace[j] = 0;

  htt_stack_push(retvars, htt_string_new(ptmp, string));

  return APR_SUCCESS;
}

static apr_status_t _cmd_b64enc_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  const char *string;
  apr_size_t len;
  char *base64;

  htt_string_t *in = htt_map_get(params, "in");

  if (!in || !htt_isa_string(in)) {
    apr_status_t status = APR_EGENERAL;
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Nothing to decode");
    return status;
  }

  string = htt_string_get(in);

  len = apr_base64_encode_len(strlen(string));
  base64 = apr_pcalloc(ptmp, len + 1);
  apr_base64_encode(base64, string, strlen(string));
  
  htt_stack_push(retvars, htt_string_new(ptmp, base64));

  return APR_SUCCESS;
}

static apr_status_t _cmd_b64dec_function(htt_executable_t *executable, 
                                         htt_context_t *context, 
                                         apr_pool_t *ptmp, htt_map_t *params, 
                                         htt_stack_t *retvars, char *line) {
  const char *string;
  apr_size_t len;
  char *plain;

  htt_string_t *in = htt_map_get(params, "in");

  if (!in || !htt_isa_string(in)) {
    apr_status_t status = APR_EGENERAL;
    htt_log_error(htt_context_get_log(context), status, 
                  htt_executable_get_file(executable), 
                  htt_executable_get_line(executable), 
                  "Nothing to decode");
    return status;
  }

  string = htt_string_get(in);

  len = apr_base64_decode_len(string);
  plain = apr_pcalloc(ptmp, len + 1);
  apr_base64_decode(plain, string);
  
  htt_stack_push(retvars, htt_string_new(ptmp, plain));

  return APR_SUCCESS;
}

static int _get_url_escape_index(char c) {
  int i;
  for (i = 0; i < sizeof(url_escape_seq)/sizeof(url_escape_seq_t); i++) {
    if (url_escape_seq[i].c == c) {
      return i;
    }
  }
  return -1;
}

