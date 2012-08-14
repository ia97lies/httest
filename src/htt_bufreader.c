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
#include <apr_buckets.h>

#include "htt_defines.h"
#include "htt_bufreader.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

struct htt_bufreader_s {
  apr_status_t status;
  apr_pool_t *pool;
  apr_file_t *fp;
  apr_size_t i;
  apr_size_t len;
  apr_bucket_alloc_t *alloc;
  apr_bucket_brigade *line;
  char *buf;
};


/************************************************************************
 * Forward declaration 
 ***********************************************************************/

/**
 * Fill up buffer with data from file 
 * @param self IN htt_bufreader object
 * @return an apr status
 */
static apr_status_t _bufreader_fill(htt_bufreader_t * self); 

/**
 * Check fp and read file
 * @param self IN htt_bufreader object
 * @return apr status
 */
static apr_status_t _file_read(htt_bufreader_t *self);

/**
 * Check end of file
 * @param self IN htt_bufreader object
 * @return APR_EOF if end of file
 */
static apr_status_t _file_eof(htt_bufreader_t *self);

/**
 * Create a plain bufreader
 * @param pool IN pool
 * @return bufreader
 */
static htt_bufreader_t *_bufreader_new(apr_pool_t * pool); 

/************************************************************************
 * Public
 ***********************************************************************/

htt_bufreader_t *htt_bufreader_file_new(apr_pool_t * pool, apr_file_t * fp) {
  htt_bufreader_t *bufreader = _bufreader_new(pool);
  bufreader->fp = fp;
  bufreader->buf = apr_pcalloc(bufreader->pool, HTT_BLOCK_MAX + 1); 
  bufreader->i = HTT_BLOCK_MAX;
  bufreader->len = HTT_BLOCK_MAX;

  return bufreader;
}

htt_bufreader_t *htt_bufreader_buf_new(apr_pool_t * pool, const char *buf, 
                                       apr_size_t len) { 
  htt_bufreader_t *bufreader = _bufreader_new(pool);
  bufreader->buf = apr_pcalloc(bufreader->pool, len);
  memcpy(bufreader->buf, buf, len);
  bufreader->len = len;
  return bufreader;
}

apr_status_t htt_bufreader_read_line(htt_bufreader_t * self, char **line) {
  char c;
  apr_size_t i;
  apr_status_t status = APR_SUCCESS;
  int leave_loop = 0;

  *line = NULL;

  i = 0;
  c = 0;
  while (leave_loop == 0 && (status = _file_eof(self)) != APR_EOF) {    
    if (self->i >= self->len) {
      if ((status = _bufreader_fill(self)) != APR_SUCCESS) {
        break;
      }
    }

    if (self->i < self->len) {
      c = self->buf[self->i];
      if (c == '\r' || c == '\n') {
	c='\0';
	leave_loop=1;
      }
      apr_brigade_putc(self->line, NULL, NULL, c);
      self->i++;
      i++;

    }
  }

  apr_brigade_pflatten(self->line, line, &i, self->pool);
  apr_brigade_cleanup(self->line);

  while (**line == ' ' || **line == '\t') {
    ++*line;
  }

  return status;
}

apr_status_t htt_bufreader_read_block(htt_bufreader_t * self, char *block,
                                  apr_size_t *length) {
  apr_status_t status;
  int i;
  int len = *length;

  status = APR_SUCCESS;

  (*length) = 0;

  i = 0;
  while (i < len) {
    if (self->i >= self->len) {
      if ((status = _bufreader_fill(self)) != APR_SUCCESS) {
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

apr_status_t htt_bufreader_read_eof(htt_bufreader_t * self,
                                char **buf, apr_size_t *len) {
  char *read;
  apr_size_t block;
  apr_bucket *b;
  apr_bucket_brigade *bb;

  apr_status_t status = APR_SUCCESS;

  *buf = NULL;
  (*len) = 0;

  bb = apr_brigade_create(self->pool, self->alloc);

  read = apr_pcalloc(self->pool, HTT_BLOCK_MAX);
  do {
    block = HTT_BLOCK_MAX;
    status = htt_bufreader_read_block(self, read, &block);
    b = apr_bucket_pool_create(read, block, self->pool, self->alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    read = apr_pcalloc(self->pool, HTT_BLOCK_MAX);
  } while (status == APR_SUCCESS); 

  apr_brigade_pflatten(bb, buf, len, self->pool);
  apr_brigade_destroy(bb);

  if (status == APR_SUCCESS || status == APR_EOF) {
    return APR_SUCCESS;
  }
  else {
    return status;
  }  
}


/************************************************************************
 * Private
 ***********************************************************************/

static htt_bufreader_t *_bufreader_new(apr_pool_t * pool) {
  apr_allocator_t *allocator;
  htt_bufreader_t *bufreader;
  apr_pool_t *bpool;

  apr_pool_create(&bpool, pool);
  bufreader = apr_pcalloc(bpool, sizeof(htt_bufreader_t));
  bufreader->pool = bpool;
  bufreader->alloc = apr_bucket_alloc_create(bufreader->pool);
  bufreader->line = apr_brigade_create(bufreader->pool, bufreader->alloc);
  allocator = apr_pool_allocator_get(bufreader->pool);
  apr_allocator_max_free_set(allocator, 1024*1024);
  bufreader->status = APR_SUCCESS;

  return bufreader;
}

static apr_status_t _bufreader_fill(htt_bufreader_t * self) {
  self->i = 0;

  if (self->status != APR_SUCCESS) {
    return self->status;
  }

  self->status = _file_read(self);
  return self->status;
}

static apr_status_t _file_read(htt_bufreader_t *self) {
  if (self->fp) {
    return apr_file_read(self->fp, self->buf, &self->len);
  }
  else {
    return APR_EOF;
  }
}

static apr_status_t _file_eof(htt_bufreader_t *self) {
  if (self->fp) {
    return apr_file_eof(self->fp);
  }
  else if (self->i >= self->len) {
    return APR_EOF;
  }
  else {
    return APR_SUCCESS;
  }
}

