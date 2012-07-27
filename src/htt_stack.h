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

#ifndef HTT_STACK_H
#define HTT_STACK_H

typedef struct htt_stack_s htt_stack_t;

htt_stack_t * htt_stack_new(apr_pool_t *pool); 
void htt_stack_push(htt_stack_t *stack, void *elem);
void *htt_stack_pop(htt_stack_t *stack);
void *htt_stack_top(htt_stack_t *stack);
int htt_stack_elems(htt_stack_t *stack);

#endif
