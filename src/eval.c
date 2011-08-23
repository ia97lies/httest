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
 * equalit    = expression ["==" | "!=" | ">" | ">=" | "<" | "<=" expression];
 * expression = term  {"+" term};
 * term       = factor {"*" factor};
 * factor     = constant | "(" expression ")";
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

#include "eval.h"

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
  MATH_NOT,
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
  MATH_ERR
} math_token_e;

struct math_eval_s {
  apr_pool_t *pool;
  const char *delimiter;
  STACK_OF(int) *stack;
  const char *line;
  apr_size_t i;
  apr_size_t len;
  int last_number;
  int cur_token;
};

static apr_status_t math_parse_expression(math_eval_t *hook);
static apr_status_t math_parse_term(math_eval_t *hook);
static apr_status_t math_parse_factor(math_eval_t *hook);

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
static void math_skip_space(math_eval_t *hook) {
  for (; hook->i < hook->len && hook->line[hook->i] == ' '; hook->i++);
}

/**
 * get next char and increase read pointer.
 * @param hook IN eval instance
 * @return char or \0 if end of line
 */
static char math_next_char(math_eval_t *hook) {
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
static char math_peek_char(math_eval_t *hook) {
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
static char math_lookahead(math_eval_t *hook) {
  if (hook->i < hook->len) {
    return hook->line[hook->i+1];
  }
  else {
    return '\0';
  }
}

/**
 * Get number from given possition
 * @param hook IN eval instance
 */
static void math_get_number(math_eval_t *hook) {
  const char *number;
  apr_size_t start = hook->i;
  while (apr_isdigit(math_peek_char(hook))) math_next_char(hook);
  number = apr_pstrndup(hook->pool, &hook->line[start], hook->i - start);
  hook->last_number = apr_atoi64(number);
}

/**
 * get next token from line
 * @param hook IN eval instance
 * @return token
 */
static int math_get_next_token(math_eval_t *hook) {
  char c;
  math_skip_space(hook);
  while ((c = math_peek_char(hook))) {
    switch (c) {
    case '=':
      if (math_lookahead(hook) == '=') {
	math_next_char(hook);
	math_next_char(hook);
	return MATH_EQ;
      }
      else {
	return MATH_ERR;
      }
      break;
    case '<': 
      if (math_lookahead(hook) == '=') {
	math_next_char(hook);
	math_next_char(hook);
	return MATH_LE;
      }
      else {
	math_next_char(hook);
	return MATH_LT;
      }
      break;
    case '>': 
      if (math_lookahead(hook) == '=') {
	math_next_char(hook);
	math_next_char(hook);
	return MATH_BE;
      }
      else {
	math_next_char(hook);
	return MATH_BT;
      }
      break;
    case '!': 
      math_next_char(hook);
      if (math_lookahead(hook) == '=') {
	math_next_char(hook);
	return MATH_NE;
      }
      else {
	return MATH_NOT;
      }
      break;
    case '+': 
      math_next_char(hook);
      return MATH_ADD;
      break;
    case '-': 
      math_next_char(hook);
      return MATH_SUB;
      break;
    case '*': 
      math_next_char(hook);
      return MATH_MUL;
      break;
    case '/': 
      math_next_char(hook);
      return MATH_DIV;
      break;
    case '%': 
      math_next_char(hook);
      return MATH_MOD;
      break;
    case '^': 
      math_next_char(hook);
      return MATH_POWER;
      break;
    case '(': 
      math_next_char(hook);
      return MATH_PARENT_L;
      break;
    case ')': 
      math_next_char(hook);
      return MATH_PARENT_R;
      break;
    default:
      if (apr_isdigit(c)) {
	math_get_number(hook);
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
static int math_get_token(math_eval_t *hook) {
  hook->cur_token = math_get_next_token(hook);
  return hook->cur_token;
}

/**
 * peek current token if any else get first token.
 * @param hook IN math instance
 * @return token
 */
static int math_peek_token(math_eval_t *hook) {
  if (hook->cur_token) {
    return hook->cur_token;
  }
  else {
    math_get_token(hook);
    return hook->cur_token;
  }
}

/**
 * factor = constant | "(" expression ")";
 * @param hook IN math object
 * return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t math_parse_factor(math_eval_t *hook) {
  apr_status_t status;
  int token; 
  long *number;
  long sign = 1;

  token = math_peek_token(hook);
  switch (token) {
  case MATH_ADD:
    /* skip this, positiv number are positve :) */
    math_get_token(hook);
  case MATH_SUB:
    /* store sign */
    sign = -1;
    math_get_token(hook);
  case MATH_NUM:
    number = apr_pcalloc(hook->pool, sizeof(*number));
    *number = hook->last_number * sign;
    SKM_sk_push(long, hook->stack, number);
    math_get_token(hook);
    return APR_SUCCESS;
    break;
  case MATH_PARENT_L:
    token = math_get_token(hook);
    status = math_parse_expression(hook);
    token = math_peek_token(hook);
    if (token != MATH_PARENT_R) {
      return APR_EINVAL;
    }
    token = math_get_token(hook);
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
static apr_status_t math_parse_term(math_eval_t *hook) {
  int token; 
  apr_status_t status;
  long *right;
  long *left;
  long *result;
  
  if ((status = math_parse_factor(hook)) != APR_SUCCESS) {
    return status;
  }

  token = math_peek_token(hook);
  while (token != MATH_EOF) {
    if (token == MATH_MUL || token == MATH_DIV || token == MATH_POWER ||
	token == MATH_MOD) {
      math_get_token(hook);
    }
    else {
      return APR_SUCCESS;
    }
   
    if ((status = math_parse_factor(hook)) != APR_SUCCESS) {
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
    case MATH_POWER:
      *result = pow(*left, *right);
      break;
    default:
      break;
    }
    SKM_sk_push(long, hook->stack, result);
 
    token = math_peek_token(hook);
  }
  return APR_SUCCESS;
}

/**
 * expression = term { "+"|"-" term }
 * @param hook IN math object
 * return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t math_parse_expression(math_eval_t *hook) {
  int token; 
  apr_status_t status;
  long *right;
  long *left;
  long *result;
  
  if ((status = math_parse_term(hook)) != APR_SUCCESS) {
    return status;
  }

  token = math_peek_token(hook);
  while (token != MATH_EOF) {
    if (token == MATH_ADD || token == MATH_SUB) {
      math_get_token(hook);
    }
    else {
      return APR_SUCCESS;
    }
    
    if ((status = math_parse_term(hook)) != APR_SUCCESS) {
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

    token = math_peek_token(hook);
  }
  return APR_SUCCESS;
}

/**
 * equalit    = expression ["==" | "!=" | ">" | ">=" | "<" | "<=" expression];
 * @param hook IN math object
 * return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t math_parse_equalit(math_eval_t *hook) {
  int token; 
  apr_status_t status;
  long *right;
  long *left;
  long *result;
  
  if ((status = math_parse_expression(hook)) != APR_SUCCESS) {
    return status;
  }

  token = math_peek_token(hook);
  if (token != MATH_EOF) {
    if (token == MATH_EQ || token == MATH_NE || token == MATH_BT ||
	token == MATH_BE || token == MATH_LT || token == MATH_LE) {
      math_get_token(hook);
    }
    else {
      return APR_SUCCESS;
    }
    
    if ((status = math_parse_expression(hook)) != APR_SUCCESS) {
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
static apr_status_t math_parse(math_eval_t * hook, long *val) {
  long *result;
  apr_status_t status = math_parse_equalit(hook);
  result = SKM_sk_pop(long, hook->stack);
  *val = *result;
  return status;
}


/************************************************************************
 * public interface 
 ***********************************************************************/

/**
 * Create new instance of evaluator
 * @param pool IN pool
 * @return eval instance
 */
math_eval_t *math_eval_make(apr_pool_t * pool) {
  math_eval_t *hook = apr_pcalloc(pool, sizeof(*hook));
  hook->pool = pool; 
  hook->stack = SKM_sk_new_null(char);
  hook->delimiter = apr_pstrdup(pool, "+-*/=<>!()");

  return hook;
}

/**
 * Evaluate math expression 
 * @param hook IN eval instance
 * @param line IN line to parse
 * @param val OUT result
 * @return APR_SUCCESS or APR_EINVAL
 */
apr_status_t math_evaluate(math_eval_t * hook, const char *line, long *val) {
  apr_status_t status;

  hook->line = line; 
  hook->len = strlen(line);
  hook->i = 0;
  hook->last_number = 0;
  hook->cur_token = 0;

  if ((status = math_parse(hook, val)) != APR_SUCCESS) {
    return status;
  }
  /* get result from stack */
  return APR_SUCCESS;
}

