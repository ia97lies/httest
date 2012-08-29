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
 *
 * REMARK
 * Original Copyright 1991 by Bob Stout as part of
 * the MicroFirm Function Library (MFL)
 * 
 * This subset* version is hereby donated to the public domain.
 */

/**
 * @file
 *
 * @Author christian liesch <liesch@gmx.ch>
 *
 * Implementation of the HTTP Test Tool math module 
 *
 * infix notation
 * !(4 + 5 * 8 * (4 + 1) / 5 < 6)
 *
 * stack interpreter postfix notation =>
 *
 * => result is 1
 *
 * EBNF Description
 * bexpression= bterm {or bterm};
 * bterm      = bfactor {and bfactor};
 * bfactor    = [not] condition;
 * condition  = expression ["==" | "!=" | ">" | ">=" | "<" | "<=" expression];
 * expression = term  {"+" term};
 * term       = factor {"*" factor};
 * factor     = constant | "(" bexpression ")";
 * constant   = digit {digit};
 * digit      = "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9";
 *
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

/* Use STACK from openssl to sort commands */
#include <openssl/ssl.h>

#include <apr.h>
#include <apr_lib.h>
#include <apr_strings.h>

#include "htt_eval.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
enum {
  MATH_NONE = 0,
  MATH_ADD,
  MATH_SUB,
  MATH_MUL,
  MATH_DIV,
  MATH_MOD,
  MATH_POWER,
  MATH_EQ,
  MATH_NE,
  MATH_BT,
  MATH_BE,
  MATH_LT,
  MATH_LE,
  MATH_PARENT_L,
  MATH_PARENT_R,
  MATH_NUM,
  MATH_EOF,
  MATH_NOT,
  MATH_AND,
  MATH_OR,
  MATH_ERR
} _token_e;

struct htt_eval_s {
  apr_pool_t *pool;
  STACK_OF(long) *stack;
  const char *line;
  apr_size_t i;
  apr_size_t len;
  int last_number;
  int cur_token;
};

static apr_status_t _parse_expression(htt_eval_t *hook);
static apr_status_t _parse_term(htt_eval_t *hook);
static apr_status_t _parse_factor(htt_eval_t *hook);

/************************************************************************
 * Globals 
 ***********************************************************************/

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * skip spaces
 * @param hook IN eval instance
 */
static void _skip_space(htt_eval_t *hook) {
  for (; hook->i < hook->len && hook->line[hook->i] == ' '; hook->i++);
}

/**
 * get next char and increase read pointer.
 * @param hook IN eval instance
 * @return char or \0 if end of line
 */
static char _next_char(htt_eval_t *hook) {
  if (hook->i < hook->len) {
    return hook->line[hook->i++];
  }
  else {
    return '\0';
  }
}

/**
 * look a head on char but do not increase read pointer.
 * @param hook IN eval instance
 * @return lookahead char or \0 if end of line
 */
static char _peek_char(htt_eval_t *hook) {
  if (hook->i < hook->len) {
    return hook->line[hook->i];
  }
  else {
    return '\0';
  }
}

/**
 * look a head on char but do not increase read pointer.
 * @param hook IN eval instance
 * @return lookahead char or \0 if end of line
 */
static char _lookahead(htt_eval_t *hook, int ahead) {
  if (hook->i+ahead < hook->len) {
    return hook->line[hook->i+ahead];
  }
  else {
    return '\0';
  }
}

/**
 * Get number from given possition
 * @param hook IN eval instance
 */
static void _get_number(htt_eval_t *hook) {
  const char *number;
  apr_size_t start = hook->i;
  while (apr_isdigit(_peek_char(hook))) _next_char(hook);
  number = apr_pstrndup(hook->pool, &hook->line[start], hook->i - start);
  hook->last_number = apr_atoi64(number);
}

/**
 * get next token from line
 * @param hook IN eval instance
 * @return token
 */
static int _get_next_token(htt_eval_t *hook) {
  char c;
  _skip_space(hook);
  while ((c = _peek_char(hook))) {
    switch (c) {
    case 'a':
      if (_lookahead(hook,1) == 'n' && _lookahead(hook,2) == 'd') {
	_next_char(hook);
	_next_char(hook);
	_next_char(hook);
        return MATH_AND;
      }
      else {
	return MATH_ERR;
      }
      break;
    case 'o':
      if (_lookahead(hook,1) == 'r') {
	_next_char(hook);
	_next_char(hook);
	_next_char(hook);
        return MATH_OR;
      }
      else {
	return MATH_ERR;
      }
      break;
    case 'n':
      if (_lookahead(hook,1) == 'o' && _lookahead(hook,2) == 't') {
	_next_char(hook);
	_next_char(hook);
	_next_char(hook);
        return MATH_NOT;
      }
      else {
	return MATH_ERR;
      }
      break;
    case '=':
      if (_lookahead(hook,1) == '=') {
	_next_char(hook);
	_next_char(hook);
	return MATH_EQ;
      }
      else {
	return MATH_ERR;
      }
      break;
    case '<': 
      if (_lookahead(hook,1) == '=') {
	_next_char(hook);
	_next_char(hook);
	return MATH_LE;
      }
      else {
	_next_char(hook);
	return MATH_LT;
      }
      break;
    case '>': 
      if (_lookahead(hook,1) == '=') {
	_next_char(hook);
	_next_char(hook);
	return MATH_BE;
      }
      else {
	_next_char(hook);
	return MATH_BT;
      }
      break;
    case '!': 
      _next_char(hook);
      if (_lookahead(hook,1) == '=') {
	_next_char(hook);
	return MATH_NE;
      }
      else {
	return MATH_ERR;
      }
      break;
    case '+': 
      _next_char(hook);
      return MATH_ADD;
      break;
    case '-': 
      _next_char(hook);
      return MATH_SUB;
      break;
    case '*': 
      _next_char(hook);
      return MATH_MUL;
      break;
    case '/': 
      _next_char(hook);
      return MATH_DIV;
      break;
    case '%': 
      _next_char(hook);
      return MATH_MOD;
      break;
    case '^': 
      _next_char(hook);
      return MATH_POWER;
      break;
    case '(': 
      _next_char(hook);
      return MATH_PARENT_L;
      break;
    case ')': 
      _next_char(hook);
      return MATH_PARENT_R;
      break;
    default:
      if (apr_isdigit(c)) {
	_get_number(hook);
	return MATH_NUM;
      }
      else {
      	return MATH_ERR;
      }
      break;
    }
  }
  return MATH_EOF;
}

/**
 * get next token from line and store it for peek.
 * @param hook IN math instance
 * @return token
 */
static int _get_token(htt_eval_t *hook) {
  hook->cur_token = _get_next_token(hook);
  return hook->cur_token;
}

/**
 * peek current token if any else get first token.
 * @param hook IN math instance
 * @return token
 */
static int _peek_token(htt_eval_t *hook) {
  if (hook->cur_token) {
    return hook->cur_token;
  }
  else {
    _get_token(hook);
    return hook->cur_token;
  }
}

/**
 * factor = constant | "(" expression ")";
 * @param hook IN math object
 * return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t _parse_factor(htt_eval_t *hook) {
  apr_status_t status;
  int token; 
  long *number;
  long sign = 1;

  token = _peek_token(hook);
  switch (token) {
  case MATH_ADD:
    /* skip this, positiv number are positve :) */
    _get_token(hook);
  case MATH_SUB:
    /* store sign */
    sign = -1;
    _get_token(hook);
  case MATH_NUM:
    number = apr_pcalloc(hook->pool, sizeof(*number));
    *number = hook->last_number * sign;
    SKM_sk_push(long, hook->stack, number);
    _get_token(hook);
    return APR_SUCCESS;
    break;
  case MATH_PARENT_L:
    token = _get_token(hook);
    status = _parse_expression(hook);
    token = _peek_token(hook);
    if (token != MATH_PARENT_R) {
      return APR_EINVAL;
    }
    token = _get_token(hook);
    return status;
    break;
  default:
    return APR_EINVAL;
    break;
  }
}
 
/**
 * term = factor { "*"|"/" factor }
 * @param hook IN math object
 * return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t _parse_term(htt_eval_t *hook) {
  int token; 
  apr_status_t status;
  long *right;
  long *left;
  long *result;
  
  if ((status = _parse_factor(hook)) != APR_SUCCESS) {
    return status;
  }

  token = _peek_token(hook);
  while (token != MATH_EOF) {
    if (token == MATH_MUL || token == MATH_DIV || token == MATH_POWER ||
	token == MATH_MOD) {
      _get_token(hook);
    }
    else {
      return APR_SUCCESS;
    }
   
    if ((status = _parse_factor(hook)) != APR_SUCCESS) {
      return status;
    }

    right = SKM_sk_pop(long, hook->stack);
    left = SKM_sk_pop(long, hook->stack);
    result = apr_pcalloc(hook->pool, sizeof(*result));
    switch (token) {
    case MATH_MUL:
      *result = *left * *right;
      break;
    case MATH_DIV:
      *result = *left / *right;
      break;
    case MATH_MOD:
      *result = *left % *right;
      break;
#ifdef LINUX
    case MATH_POWER:
      *result = pow(*left, *right);
      break;
#endif
    default:
      break;
    }
    SKM_sk_push(long, hook->stack, result);
 
    token = _peek_token(hook);
  }
  return APR_SUCCESS;
}

/**
 * expression = term { "+"|"-" term }
 * @param hook IN math object
 * return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t _parse_expression(htt_eval_t *hook) {
  int token; 
  apr_status_t status;
  long *right;
  long *left;
  long *result;
  
  if ((status = _parse_term(hook)) != APR_SUCCESS) {
    return status;
  }

  token = _peek_token(hook);
  while (token != MATH_EOF) {
    if (token == MATH_ADD || token == MATH_SUB) {
      _get_token(hook);
    }
    else {
      return APR_SUCCESS;
    }
    
    if ((status = _parse_term(hook)) != APR_SUCCESS) {
      return status;
    }

    right = SKM_sk_pop(long, hook->stack);
    left = SKM_sk_pop(long, hook->stack);
    result = apr_pcalloc(hook->pool, sizeof(*result));
    switch (token) {
    case MATH_ADD:
      *result = *left + *right;
      break;
    case MATH_SUB:
      *result = *left - *right;
      break;
    default:
      break;
    }
    SKM_sk_push(long, hook->stack, result);

    token = _peek_token(hook);
  }
  return APR_SUCCESS;
}

/**
 * condition    = expression ["==" | "!=" | ">" | ">=" | "<" | "<=" expression];
 * @param hook IN math object
 * return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t _parse_condition(htt_eval_t *hook) {
  int token; 
  apr_status_t status;
  long *right;
  long *left;
  long *result;
  
  if ((status = _parse_expression(hook)) != APR_SUCCESS) {
    return status;
  }

  token = _peek_token(hook);
  if (token != MATH_EOF) {
    if (token == MATH_EQ || token == MATH_NE || token == MATH_BT ||
	token == MATH_BE || token == MATH_LT || token == MATH_LE) {
      _get_token(hook);
    }
    else {
      return APR_SUCCESS;
    }
    
    if ((status = _parse_expression(hook)) != APR_SUCCESS) {
      return status;
    }

    right = SKM_sk_pop(long, hook->stack);
    left = SKM_sk_pop(long, hook->stack);
    result = apr_pcalloc(hook->pool, sizeof(*result));
    switch (token) {
    case MATH_EQ:
      *result = *left == *right;
      break;
    case MATH_NE:
      *result = *left != *right;
      break;
    case MATH_BT:
      *result = *left > *right;
      break;
    case MATH_BE:
      *result = *left >= *right;
      break;
    case MATH_LT:
      *result = *left < *right;
      break;
    case MATH_LE:
      *result = *left <= *right;
      break;
    default:
      break;
    }
    SKM_sk_push(long, hook->stack, result);
  }
  return APR_SUCCESS;
}

/**
 * Parse expression line
 * @param hook IN eval instance
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t _parse(htt_eval_t * hook, long *val) {
  long *result;
  apr_status_t status = _parse_condition(hook);
  result = SKM_sk_pop(long, hook->stack);
  if (result) {
    *val = *result;
  }
  else {
    status = APR_EINVAL;
  }
  return status;
}


/************************************************************************
 * public interface 
 ***********************************************************************/

htt_eval_t *htt_eval_new(apr_pool_t * pool) {
  apr_pool_t *mypool;
  apr_pool_create(&mypool, pool);
  htt_eval_t *hook = apr_pcalloc(mypool, sizeof(*hook));
  hook->pool = mypool; 
  hook->stack = SKM_sk_new_null(long);

  return hook;
}

apr_status_t htt_eval(htt_eval_t * hook, const char *line, long *val) {
  apr_status_t status;

  hook->line = line; 
  hook->len = strlen(line);
  hook->i = 0;
  hook->last_number = 0;
  hook->cur_token = 0;

  if ((status = _parse(hook, val)) != APR_SUCCESS) {
    return status;
  }
  /* get result from stack */
  return APR_SUCCESS;
}

void htt_eval_free(htt_eval_t *eval) {
  SKM_sk_free(long, eval->stack);
  apr_pool_destroy(eval->pool);
}

