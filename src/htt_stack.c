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
#include <assert.h>
#include "htt_stack.h"

#define HTT_STACK_LIMIT 50

struct htt_stack_s {
  apr_pool_t *pool;
  void *table[HTT_STACK_LIMIT];
  int sp;
};

htt_stack_t * htt_stack_new(apr_pool_t *pool) {
  htt_stack_t *stack = apr_pcalloc(pool, sizeof(*stack));
  stack->pool = pool;
  stack->sp = -1;
  return stack;
}

void htt_stack_push(htt_stack_t *stack, void *elem) {
  ++stack->sp;
  assert(stack->sp < HTT_STACK_LIMIT);
  stack->table[stack->sp] = elem;
}

void *htt_stack_pop(htt_stack_t *stack) {
  if (stack->sp < 0) {
    return NULL;
  }
  else {
    void *elem = stack->table[stack->sp];
    --stack->sp;
    return elem;
  }
}

void *htt_stack_top(htt_stack_t *stack) {
  if (stack->sp < 0) {
    return NULL;
  }
  else {
    return stack->table[stack->sp];
  }
}

void *htt_stack_index(htt_stack_t *stack, int i) {
  if (i > stack->sp) {
    return NULL;
  }
  else {
    return stack->table[stack->sp - i];
  }
}

int htt_stack_elems(htt_stack_t *stack) {
  return stack->sp + 1;
}

