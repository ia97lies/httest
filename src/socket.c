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
 * Implementation of the HTTP Test Tool socket.
 */

/************************************************************************
 * Includes
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <apr.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_buckets.h>

#include "defines.h"
#include "transport.h"
#include "socket.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

struct sockreader_s {
  apr_pool_t *pool;
  transport_t *transport;
  apr_size_t i;
  apr_size_t len;
  char *buf;
  char *swap;
  apr_bucket_alloc_t *alloc;
  apr_bucket_brigade *cache;
  apr_bucket_brigade *line;
  int options; 
};


/************************************************************************
 * Forward declaration 
 ***********************************************************************/

static apr_status_t sockreader_fill(sockreader_t * self); 
static char *my_strcasestr(const char *s1, const char *s2); 

/************************************************************************
 * Implementation 
 ***********************************************************************/

/**
 * Create a new sockreader object
 *
 * @param sockreader OUT new sockreader object
 * @param socket IN connected socket
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t sockreader_new(sockreader_t ** sockreader, transport_t *transport,
                            char *rest, apr_size_t len) {
  apr_status_t status;
  apr_allocator_t *allocator;
  apr_pool_t *pool;

  apr_pool_create(&pool, NULL);
  *sockreader = apr_pcalloc(pool, sizeof(sockreader_t));
  (*sockreader)->buf = apr_pcalloc(pool, BLOCK_MAX + 1);
  (*sockreader)->alloc = apr_bucket_alloc_create(pool);
  (*sockreader)->line = apr_brigade_create(pool, (*sockreader)->alloc);

  (*sockreader)->transport = transport;
  allocator = apr_pool_allocator_get(pool);
  apr_allocator_max_free_set(allocator, 1024*1024);
  (*sockreader)->pool = pool;

  if (len > BLOCK_MAX) {
    return APR_ENOMEM;
  }
  
  if (rest && len) {
    memcpy((*sockreader)->buf, rest, len);
    (*sockreader)->len = len;
  }
  else {
    if ((status = sockreader_fill((*sockreader))) != APR_SUCCESS) {
      return status;
    }
  }

  return APR_SUCCESS;
}

/**
 * Destroy sockreader
 * @param sockreader INOUT instance
 * @note: sockreader will be set to NULL
 */
void sockreader_destroy(sockreader_t **sockreader) {
  if ((*sockreader) != NULL) {
    apr_pool_destroy((*sockreader)->pool);
    *sockreader = NULL;
  }
}

/**
 * Set transport for upgrading facilities
 * @param sockreader IN sockreader instance
 * @param transport IN transport object
 */
void sockreader_set_transport(sockreader_t *sockreader, 
                              transport_t *transport) {
  sockreader->transport = transport;
}


/**
 * Set options
 *
 * @param self IN sockreader object
 * @param options IN SOCKREADER_OPTIONS_IGNORE_BODY to ignore recvd body 
 *                   SOCKREADER_OPTIONS_NONE delete options
 */
void sockreader_set_options(sockreader_t *self, int options) {
  self->options = options;
}

/**
 * Push back a line
 *
 * @param self IN sockreader object
 * @param buf IN buf to push back
 * @param len IN len to push back
 */
apr_status_t sockreader_push_back(sockreader_t * self, const char *buf, 
                                  apr_size_t len) {
  if (!self->cache) {
    self->cache = apr_brigade_create(self->pool, self->alloc);
  }

  apr_brigade_write(self->cache, NULL, NULL, buf, len);

  return APR_SUCCESS;
}

/**
 * Push back a line
 *
 * @param self IN sockreader object
 * @param line IN line to push back
 */
apr_status_t sockreader_push_line(sockreader_t * self, const char *line) {
  apr_status_t status;
  apr_size_t len = strlen(line);

  status = sockreader_push_back(self, line, len);
  if (status == APR_SUCCESS) {
    status = sockreader_push_back(self, "\r\n", 2);
  }
  return status;
}

/**
 * read line
 *
 * @param self IN sockreader object
 * @param line OUT read line
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t sockreader_read_line(sockreader_t * self, char **line) {
  char c;
  apr_size_t i;
  apr_status_t status = APR_SUCCESS;

  *line = NULL;

  i = 0;
  c = 0;
  apr_brigade_cleanup(self->line);
  while (c != '\n') {
    if (self->i >= self->len) {
      if ((status = sockreader_fill(self)) != APR_SUCCESS) {
        break;
      }
    }

    if (self->i < self->len) {
      c = self->buf[self->i];
      apr_brigade_putc(self->line, NULL, NULL, c);
      self->i++;
    }
  }

  apr_brigade_pflatten(self->line, line, &i, self->pool);
  apr_brigade_cleanup(self->line);

  if (i) {
    (*line)[i - 1] = 0;
  }
  if (i > 1 && (*line)[i - 2] == '\r') {
    (*line)[i - 2] = 0;
  }
  else {
    (*line)[i] = 0;
  }

  return status;
}

/**
 * Read specifed block
 *
 * @param self IN sockreader object
 * @param block IN a block to fill up
 * @param length INOUT length of block, on return length of filled bytes
 *
 * @return APR_SUCCESS else APR error
 */
apr_status_t sockreader_read_block(sockreader_t * self, char *block,
                                   apr_size_t *length) {
  apr_status_t status;
  int i;
  int min_len;
  apr_size_t len = *length;

  status = APR_SUCCESS;
  i = 0;
  if (block) {
    while (i < len) {
      if (self->i >= self->len) {
	if ((status = sockreader_fill(self)) != APR_SUCCESS) {
	  break;
	}
      }
      min_len = len - i < self->len - self->i ? len - i : self->len - self->i;
      memcpy(&block[i], &self->buf[self->i], min_len);
      i += min_len;
      self->i += min_len;
    }

    /* on eof we like to get the bytes recvieved so far */
    min_len = len - i < self->len - self->i ? len - i : self->len - self->i;
    memcpy(&block[i], &self->buf[self->i], min_len);
    i += min_len;
    self->i += min_len;
  }
  else {
    while (i < len) {
      if (self->i >= self->len) {
	if ((status = sockreader_fill(self)) != APR_SUCCESS) {
	  break;
	}
      }

      min_len = len - i < self->len - self->i ? len - i : self->len - self->i;
      i += min_len;
      self->i += min_len;
    }

    /* on eof we like to get the bytes recvieved so far */
    min_len = len - i < self->len - self->i ? len - i : self->len - self->i;
    i += min_len;
    self->i += min_len;
  }

  *length = i;

  return status;
}

/****
 * Http helper based on sockreader
 ****/
/**
 * content length reader 
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 * @param ct IN content length
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t content_length_reader(sockreader_t * self,
                                   char **buf, apr_size_t *ct, 
				   const char *val) {
  apr_status_t status = APR_SUCCESS;
  apr_size_t len = *ct;
  char *read;

  if ((apr_ssize_t)len < 0) {
    /** shall i read until close or just quit in this case? */
    *ct = 0;
    return status;
  }
  
  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    read = NULL;
  }
  else {
    read = apr_pcalloc(self->pool, len);
  }
  sockreader_read_block(self, read, &len);
  *buf = read;
  /* if we did not get the request length quit with data incomplete error */
  if (len != *ct) {
    status = APR_INCOMPLETE;
  }

  *ct = len;

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    *ct = 0;
  }

  return status;
}

/**
 * Transfer encoding reader (only chunked implemented) 
 *
 * @param sockreader IN sockreader object
 * @param bb OUT content buffer
 * @param val IN type of encoding 
 *
 * @return APR_SUCCESS else an APR error
 */
static apr_status_t transfer_enc_reader_bb(sockreader_t *self, 
                                           apr_bucket_brigade *bb, 
					   const char *val) {
  int chunk;
  char *end;
  char *line;
  char *read = NULL;
  apr_size_t chunk_cur;
  apr_size_t chunk_len;
  apr_bucket *b;
  apr_status_t status = APR_SUCCESS;

  chunk = 0;
  if (my_strcasestr(val, "chunked")) {
    while (1) {
      while (sockreader_read_line(self, &line) == APR_SUCCESS &&
             line[0] == 0);
      /* test if we got a chunk info */
      if (line[0] == 0) {
	/* break if not */
	break;
      }
      chunk = apr_strtoi64(line, &end, 16);
      if (chunk == 0) {
	break;
      }
      if (!(self->options & SOCKREADER_OPTIONS_IGNORE_BODY)) {
	read = apr_pcalloc(self->pool, chunk);
      }
      chunk_len = 0;
      while (chunk_len < chunk) {
	chunk_cur = chunk - chunk_len;
	if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
	  status = sockreader_read_block(self, NULL, &chunk_cur);
	}
	else {
	  status = sockreader_read_block(self, &read[chunk_len], 
	                                 &chunk_cur);
	}
	if (status != APR_SUCCESS && (status != APR_EOF || chunk_cur == 0)) {
	  break;
	}
	chunk_len += chunk_cur;
      }
      if (!(self->options & SOCKREADER_OPTIONS_IGNORE_BODY)) {
	b = apr_bucket_pool_create(read, chunk_len, self->pool, 
				   self->alloc);
	APR_BRIGADE_INSERT_TAIL(bb, b);
      }
      if (chunk != chunk_len) {
	status = APR_INCOMPLETE;
	break;
      }
    }
  }
  else {
    return APR_ENOTIMPL;
  }

  if (chunk != 0) {
    /* no null chunk termination */
    return APR_INCOMPLETE;
  }
  
  return status;
}

/**
 * Transfer encoding reader (only chunked implemented) 
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 * @param len OUT content len
 * @param val IN type of encoding 
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t transfer_enc_reader(sockreader_t * self,
                                 char **buf, apr_size_t *len, const char *val) {
  apr_bucket_brigade *bb;
  apr_status_t status = APR_SUCCESS;

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    bb = NULL;
  }
  else {
    bb = apr_brigade_create(self->pool, self->alloc);
  }

  status = transfer_enc_reader_bb(self, bb, val);

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    *buf = NULL;
    *len = 0;
  }
  else {
    apr_brigade_pflatten(bb, buf, len, self->pool);
    apr_brigade_destroy(bb);
  }

  /* if null chunk termination and eof this is also ok */
  if (status == APR_SUCCESS || status == APR_EOF) {
    return APR_SUCCESS;
  }
  else {
    return status;
  }
}

/**
 * Connection close reader 
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 * @param len OUT content len
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t eof_reader(sockreader_t * self, char **buf,
                        apr_size_t *len, const char *val) {
  char *read;
  apr_size_t block;
  apr_bucket *b;
  apr_bucket_brigade *bb;

  apr_status_t status = APR_SUCCESS;
  *buf = NULL;
  (*len) = 0;

  if (my_strcasestr(val, "upgrade")) {
    return APR_SUCCESS;
  }
  if (!my_strcasestr(val, "close")) {
    return APR_ENOTIMPL;
  }

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    bb = NULL;
  }
  else {
    bb = apr_brigade_create(self->pool, self->alloc);
  }

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    read = NULL;
  }
  else {
    read = apr_pcalloc(self->pool, BLOCK_MAX);
  }
  do {
    block = BLOCK_MAX;
    if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
      status = sockreader_read_block(self, NULL, &block);
    }
    else {
      status = sockreader_read_block(self, read, &block);
    }
    if (!self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
      b = apr_bucket_pool_create(read, block, self->pool, self->alloc);
      APR_BRIGADE_INSERT_TAIL(bb, b);
      read = apr_pcalloc(self->pool, BLOCK_MAX);
    }
  } while (status == APR_SUCCESS); 

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    *buf = NULL;
    *len = 0;
  }
  else {
    apr_brigade_pflatten(bb, buf, len, self->pool);
    apr_brigade_destroy(bb);
  }

  if (status == APR_SUCCESS || status == APR_EOF) {
    return APR_SUCCESS;
  }
  else {
    return status;
  }
}

/**
 * Encapsulated reader for ICAP messages
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t encapsulated_reader(sockreader_t * self, char **buf,
                                 apr_size_t *len, const char *enc_info,
				 const char *preview) {
  char *read;
  char *read2;
  char *last;
  char *cur;
  char *key;
  char *val;
  char *tmp;
  apr_status_t status;
  apr_size_t size;
  apr_size_t size2;
  
  tmp = apr_pstrdup(self->pool, enc_info);
  cur = apr_strtok(tmp, ",", &last);
  val = cur;
  while (cur) {
    val = cur;
    cur = apr_strtok(NULL, ", ", &last);
  }
 
  if (!val) {
    return APR_EINVAL;
  }

  key = apr_strtok(val, "=", &last);
  val = apr_strtok(NULL, "=", &last);

  if (!key || !val) {
    return APR_EINVAL;
  }
  
  size = apr_atoi64(val);

  if (size == 0) {
    return APR_SUCCESS;
  }
  
  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    read = NULL;
  }
  else {
    read = apr_pcalloc(self->pool, size);
  }
  sockreader_read_block(self, read, &size);

  if (strcasecmp(key, "null-body") != 0 && (!preview || strcasecmp(preview, "0") != 0)) {
    if ((status = transfer_enc_reader(self, &read2, &size2, "chunked")) 
	!= APR_SUCCESS) {
      return status;
    }
    if (!self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
      *buf = apr_pcalloc(self->pool, size + size2);
      memcpy(*buf, read, size);
      memcpy(&(*buf)[size], read2, size2);
      *len = size + size2;
    }
  }
  else {
    *len = size;
    *buf = read;
  }

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    *len = 0;
  }

  return APR_SUCCESS;
}

/**
 * fill up our buf of 8K
 *
 * @param self IN sockreader object
 *
 * @param APR_SUCCESS else an APR error
 */
static apr_status_t sockreader_fill(sockreader_t * self) {
  apr_status_t status;

  self->i = 0;
  self->len = 0;
  
  if (self->cache) {
    self->swap = self->buf;
    apr_brigade_pflatten(self->cache, &self->buf, &self->len, self->pool);
    self->cache = NULL;
    return APR_SUCCESS;
  }

  if (self->swap) {
    self->buf = self->swap;
    self->swap = NULL;
  }

  self->len = BLOCK_MAX;

  status = transport_read(self->transport, self->buf, &self->len);
  if (APR_STATUS_IS_EOF(status) && self->len > 0) {
    return APR_SUCCESS;
  }
  else {
    return status;
  }
}

/*
 * Similar to standard strstr() but we ignore case in this version.
 * Based on the strstr() implementation further below.
 * 
 * @param s1 IN string to lookin in
 * @param s2 IN string to look for
 *
 * @return pointer to found substring or NULL
 */
static char *my_strcasestr(const char *s1, const char *s2) {
  char *p1, *p2;
  if (*s2 == '\0') {
    /* an empty s2 */
    return((char *)s1);
  }
  while(1) {
    for ( ; (*s1 != '\0') && (apr_tolower(*s1) != apr_tolower(*s2)); s1++)
      ;
      if (*s1 == '\0') {
	return(NULL);
      }
      /* found first character of s2, see if the rest matches */
      p1 = (char *)s1;
      p2 = (char *)s2;
      for (++p1, ++p2; apr_tolower(*p1) == apr_tolower(*p2); ++p1, ++p2) {
	if (*p1 == '\0') {
	  /* both strings ended together */
	  return((char *)s1);
	}
      }
      if (*p2 == '\0') {
	/* second string ended, a match */
	break;
      }
      /* didn't find a match here, try starting at next character in s1 */
      s1++;
  }
  return((char *)s1);
}

