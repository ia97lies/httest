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
 * Implementation of the HTTP Test Tool file reader.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif
#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>

#include "defines.h"
#include "file.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

struct bufreader_s {
  apr_status_t status;
  apr_pool_t *ppool;
  apr_pool_t *pool;
  apr_pool_t *next;
  apr_file_t *fp;
  apr_size_t i;
  apr_size_t len;
  char buf[BLOCK_MAX + 1];
};


/************************************************************************
 * Forward declaration 
 ***********************************************************************/

static apr_status_t bufreader_fill(bufreader_t * self); 
static void *my_realloc(bufreader_t *self, void *mem_old, 
                        apr_size_t size_old, apr_size_t size_new); 


/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * New bufreader object 
 *
 * @param self OUT bufreader object
 * @param fp IN an open file to read
 * @param p IN pool
 *
 * @return an apr status
 */
apr_status_t bufreader_new(bufreader_t ** self, apr_file_t * fp,
                           apr_pool_t * p) {
  apr_status_t status;
  apr_allocator_t *allocator;

  *self = apr_pcalloc(p, sizeof(bufreader_t));

  (*self)->fp = fp;
  allocator = apr_pool_allocator_get(p);
  apr_allocator_max_free_set(allocator, 1024*1024);
  (*self)->ppool = p;
  (*self)->status = APR_SUCCESS;
  apr_pool_create(&(*self)->pool, p);

  if ((status = bufreader_fill((*self))) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

/**
 * read line from file 
 *
 * @param self IN bufreader object
 * @param line OUT read line
 *
 * @return an apr status
 */
apr_status_t bufreader_read_line(bufreader_t * self, char **line) {
  apr_status_t status;
  char c;
  apr_size_t i;
  apr_size_t size;
  char *new_size_line;
  int leave_loop = 0;

  *line = NULL;
  size = 0;

  i = 0;
  c = 0;

  while (leave_loop == 0 && (status = apr_file_eof(self->fp)) != APR_EOF) {    
    if (i >= size) {
      new_size_line = my_realloc(self, *line, size, size + 512 + 1);
      size += 512;
      *line = new_size_line;
    }	
    if (self->i >= self->len) {
      if ((status = bufreader_fill(self)) != APR_SUCCESS) {
	goto error;
      }
    }

    c = self->buf[self->i];
    if (c == '\r' || c == '\n') {
      c='\0';
      leave_loop=1;
    }
    (*line)[i] = c;
    self->i++;
    i++;
  }
error:
  
  if (APR_STATUS_IS_EOF(status)) {
    if (i >= size) {
      new_size_line = my_realloc(self, *line, size, size + 512 + 1);
      size += 512;
      *line = new_size_line;
    }
    (*line)[i] = 0;
  }

  while (**line == ' ') {
    ++*line;
  }
  
  /* do not destroy returned line on next realloc */
  apr_pool_create(&self->pool, self->ppool);
  
  //if (apr_file_eof(self->fp) == APR_EOF) {
  //  return APR_EOF;
  //}
  //else {
  //  return APR_SUCCESS;
  //}
  return status;
}

/**
 * Read specifed block
 *
 * @param self IN bufreader object
 * @param block IN a block to fill up
 * @param length INOUT length of block, on return length of filled bytes
 *
 * @return APR_SUCCESS else APR error
 */
apr_status_t bufreader_read_block(bufreader_t * self, char *block,
                                  apr_size_t *length) {
  apr_status_t status;
  int i;
  int len = *length;

  status = APR_SUCCESS;

  (*length) = 0;

  i = 0;
  while (i < len) {
    if (self->i >= self->len) {
      if ((status = bufreader_fill(self)) != APR_SUCCESS) {
        break;
      }
    }

    block[i] = self->buf[self->i];
    ++i;
    ++self->i;
  }

  /* on eof we like to get the bytes recvieved so far */
  while (i < len && self->i < self->len) {
    block[i] = self->buf[self->i];
    ++i;
    ++self->i;
  }

  *length = i;

  return status;
}

/**
 * eof reader
 *
 * @param self IN bufreader object
 * @param buf OUT data 
 * @param len OUT data len
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t bufreader_read_eof(bufreader_t * self,
                                char **buf, apr_size_t *len) {
  char *read;
  apr_size_t block;
  apr_size_t alloc;
  apr_size_t i;

  apr_status_t status = APR_SUCCESS;

  *buf = NULL;
  (*len) = 0;

  i = 0;
  alloc = BLOCK_MAX;
  read = apr_pcalloc(self->pool, alloc);
  do {
    block = BLOCK_MAX;
    status = bufreader_read_block(self, &read[i], &block);
    i += block;
    if (i >= alloc) {
      alloc += BLOCK_MAX;
      read = my_realloc(self, read, alloc - BLOCK_MAX, alloc);
    }
  } while (status == APR_SUCCESS); 

  *buf = read;
  *len = i;

  if (status == APR_SUCCESS || status == APR_EOF) {
    return APR_SUCCESS;
  }
  else {
    return status;
  }
}

/**
 * Fill up buffer with data from file 
 *
 * @param self IN bufreader object
 *
 * @return an apr status
 */
static apr_status_t bufreader_fill(bufreader_t * self) {
  self->i = 0;
  self->len = BLOCK_MAX;

  if (self->status != APR_SUCCESS) {
    return self->status;
  }

  self->status = apr_file_read(self->fp, self->buf, &self->len);
  return self->status;
}

/**
 * realloc memory in pool
 *
 * @param p IN pool
 * @param mem_old IN old memory
 * @param size_old IN old memory size
 * @param size_new IN new memory size
 *
 * @return new memory
 */
static void *my_realloc(bufreader_t *self, void *mem_old, 
                        apr_size_t size_old, apr_size_t size_new) {
  void *mem_new;

  apr_pool_create(&self->next, self->ppool);
  mem_new = apr_palloc(self->next, size_new);
  if (mem_old != NULL) {
    memcpy(mem_new, mem_old, size_old < size_new ? size_old : size_new);
  }
  apr_pool_destroy(self->pool);
  self->pool = self->next;
  self->next = NULL;

  return mem_new;
}

