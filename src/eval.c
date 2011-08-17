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
 * boolexpr   = boolterm {"||" boolterm};
 * boolterm   = boolfactor {"&&" boolfactor};
 * boolfactor = equalit | expression | constant
 * equalit    = expression "==" | "!=" | ">" | ">=" | "<" | "<=" expression;
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
  MATH_ADD = 0,
  MATH_SUB,
  MATH_MUL,
  MATH_DIV,
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
  STACK_OF(char) *stack;
  const char *line;
  apr_size_t i;
  apr_size_t len;
  int last_number;
};

typedef struct math_elem_s math_elem_t;

typedef math_elem_t *(*math_op_f)(math_eval_t *hook, math_elem_t *left, 
                                  math_elem_t *right);

struct math_elem_s {
  int number;
  math_op_f op;
};


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
static char math_peek(math_eval_t *hook) {
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
  while (apr_isdigit(math_peek(hook))) math_next_char(hook);
  number = apr_pstrndup(hook->pool, &hook->line[start], hook->i - start);
  hook->last_number = apr_atoi64(number);
}

/**
 * get next token from line
 * @param hook IN eval instance
 * @return token
 */
static int math_get_token(math_eval_t *hook) {
  char c;
  math_skip_space(hook);
  while ((c = math_peek(hook))) {
    switch (c) {
    case '=':
      math_next_char(hook);
      if (math_lookahead(hook) == '=') {
	math_next_char(hook);
	return MATH_EQ;
      }
      else {
	return MATH_ERR;
      }
      break;
    case '<': 
      math_next_char(hook);
      if (math_lookahead(hook) == '=') {
	math_next_char(hook);
	return MATH_LE;
      }
      else {
	return MATH_LT;
      }
      break;
    case '>': 
      math_next_char(hook);
      if (math_lookahead(hook) == '=') {
	math_next_char(hook);
	return MATH_BE;
      }
      else {
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
 * execute stack
 * @param hook IN eval instance
 * @param val OUT result
 * @return APR_SUCCESS or APR_EINVAL 
 */
static apr_status_t math_execute(math_eval_t * hook, long *val) {
  math_elem_t *elem;
  math_elem_t *left = NULL;
  math_elem_t *right = NULL;

  elem = SKM_sk_pop(math_elem_t, hook->stack); 
  while (elem) {
    if (elem->op) {
      SKM_sk_push(math_elem_t, hook->stack, elem->op(hook, left, right));
      left = NULL;
      right = NULL;
    }
    else if (left == NULL) {
      left = elem;
    }
    else if (right == NULL) {
      right = elem;
    }
    elem = SKM_sk_pop(math_elem_t, hook->stack); 
  }
  if (left) {
    *val = left->number;
    return APR_SUCCESS;
  }
  else {
    return APR_EINVAL;
  }
}

/**
 * Parse expression line
 * @param hook IN eval instance
 * @return APR_SUCCESS or APR_EINVAL
 */
static apr_status_t math_parse(math_eval_t * hook) {
  int token;
  token = math_get_token(hook);
    fprintf(stderr, "\nXXX: %d", token);
    fflush(stderr);
  while (token != MATH_ERR && token != MATH_EOF) {
    token = math_get_token(hook);
    fprintf(stderr, "\nXXX: %d", token);
    fflush(stderr);
  }
  if (token == MATH_ERR) {
    return APR_EINVAL;
  }
  else {
    return APR_SUCCESS;
  }
}

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
apr_status_t math_evaluate(math_eval_t * hook, char *line, long *val) {
  apr_status_t status;

  hook->line = line; 
  hook->len = strlen(line);
  if ((status = math_parse(hook)) != APR_SUCCESS) {
    return status;
  }
  return math_execute(hook, val);
}

