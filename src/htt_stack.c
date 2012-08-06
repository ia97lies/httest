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
 * Interface of the htt stack.
 */

#include <apr_pools.h>
#include <apr_tables.h>
#include <apr_strings.h>
#include "htt_stack.h"

struct htt_stack_s {
  apr_pool_t *pool;
  apr_table_t *table;
  int sp;
};

htt_stack_t * htt_stack_new(apr_pool_t *pool) {
  htt_stack_t *stack = apr_pcalloc(pool, sizeof(*stack));
  stack->table = apr_table_make(pool, 10);
  stack->pool = pool;
  stack->sp = -1;
  return stack;
}

void htt_stack_push(htt_stack_t *stack, void *elem) {
  apr_table_addn(stack->table, apr_pstrdup(stack->pool, ""), elem);
  ++stack->sp;
}

void *htt_stack_pop(htt_stack_t *stack) {
  if (stack->sp < 0) {
    return NULL;
  }
  else {
    void *elem;
    apr_table_entry_t *e;
    e = (apr_table_entry_t *) apr_table_elts(stack->table)->elts;
    elem = e[stack->sp].val;
    --stack->sp;
    return elem;
  }
}

void *htt_stack_top(htt_stack_t *stack) {
  if (stack->sp < 0) {
    return NULL;
  }
  else {
    apr_table_entry_t *e;
    e = (apr_table_entry_t *) apr_table_elts(stack->table)->elts;
    return e[stack->sp].val;
  }
}

void *htt_stack_index(htt_stack_t *stack, int i) {
  if (i > stack->sp) {
    return NULL;
  }
  else {
    apr_table_entry_t *e;
    e = (apr_table_entry_t *) apr_table_elts(stack->table)->elts;
    return e[stack->sp - i].val;
  }
}

int htt_stack_elems(htt_stack_t *stack) {
  return stack->sp + 1;
}

