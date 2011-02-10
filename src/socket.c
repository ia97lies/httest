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
 * Implementation of the HTTP Test Tool socket.
 */

/************************************************************************
 * Includes
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/ssl.h>

#include <apr.h>
#include <apr_lib.h>
#include <apr_strings.h>
#include <apr_network_io.h>
#include <apr_buckets.h>

#include "defines.h"
#include "socket.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/

struct sockreader_s {
  apr_pool_t *ppool;
  apr_pool_t *pool;
  apr_pool_t *next;
  apr_socket_t *socket;
#ifdef USE_SSL
  SSL *ssl;
#endif
  apr_size_t i;
  apr_size_t len;
  char *buf;
  char *swap;
  apr_bucket_alloc_t *cache_alloc;
  apr_bucket_brigade *cache;
  int options; 
};


/************************************************************************
 * Forward declaration 
 ***********************************************************************/

static apr_status_t sockreader_fill(sockreader_t * self); 
static void *my_realloc(sockreader_t *sockreader, void *mem_old, 
                        apr_size_t size_old, apr_size_t size_new);
static char *my_strcasestr(const char *s1, const char *s2); 

/************************************************************************
 * Implementation 
 ***********************************************************************/

/**
 * Create a new sockreader object
 *
 * @param sockreader OUT new sockreader object
 * @param socket IN connected socket
 * @param p IN pool
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t sockreader_new(sockreader_t ** sockreader, apr_socket_t * socket,
#ifdef USE_SSL
                            SSL * ssl,
#endif
                            char *rest, apr_size_t len, apr_pool_t * p) {
  apr_status_t status;
  apr_allocator_t *allocator;

  *sockreader = apr_pcalloc(p, sizeof(sockreader_t));
  (*sockreader)->buf = apr_pcalloc(p, BLOCK_MAX + 1);
  (*sockreader)->cache_alloc = apr_bucket_alloc_create(p);

  (*sockreader)->socket = socket;
#ifdef USE_SSL
  (*sockreader)->ssl = ssl;
#endif
  allocator = apr_pool_allocator_get(p);
  apr_allocator_max_free_set(allocator, 1024*1024);
  (*sockreader)->ppool = p;
  apr_pool_create(&(*sockreader)->pool, p);

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
 * Get corresponding socket from sockreader
 *
 * @param self IN sockreader object
 *
 * @return socket
 */
apr_socket_t * sockreader_get_socket(sockreader_t *self) {
  if (!self) {
    return NULL;
  }
  return self->socket;
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
  apr_bucket *b;

  if (!self->cache) {
    self->cache = apr_brigade_create(self->ppool, self->cache_alloc);
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
  apr_status_t status;
  char c;
  apr_size_t i;
  apr_size_t size;
  char *new_size_line;

  *line = NULL;
  size = 0;

  i = 0;
  c = 0;
  while (c != '\n') {
    if (i >= size) {
      size += 512;
      new_size_line = apr_palloc(self->ppool, size + 1);
      if (*line != NULL) {
	memcpy(new_size_line, *line, size - 512);
      }
      *line = new_size_line;
    }
    if (self->i >= self->len) {
      if ((status = sockreader_fill(self)) != APR_SUCCESS) {
        return status;
      }
    }

    if (self->i < self->len) {
      c = self->buf[self->i];
      (*line)[i] = c;
      self->i++;
      i++;
    }
  }
  if (i) {
    (*line)[i - 1] = 0;
  }
  if (i > 1 && (*line)[i - 2] == '\r') {
    (*line)[i - 2] = 0;
  }
  else {
    (*line)[i] = 0;
  }

  return APR_SUCCESS;
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
  int len = *length;

  status = APR_SUCCESS;
  i = 0;
  if (block) {
    while (i < len) {
      if (self->i >= self->len) {
	if ((status = sockreader_fill(self)) != APR_SUCCESS) {
	  break;
	}
      }

      if (block) {
	block[i] = self->buf[self->i];
      }
      ++i;
      ++self->i;
    }

    /* on eof we like to get the bytes recvieved so far */
    while (i < len && self->i < self->len) {
      block[i] = self->buf[self->i];
      ++i;
      ++self->i;
    }
  }
  else {
    while (i < len) {
      if (len - i > self->len - self->i) {
	i += self->len - self->i;
	if ((status = sockreader_fill(self)) != APR_SUCCESS) {
	  break;
	}
      }
      else {
	i = len;
	self->i += len;
      }
    }
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
apr_status_t content_length_reader(sockreader_t * sockreader,
                                   char **buf, apr_size_t *ct, 
				   const char *val) {
  apr_status_t status = APR_SUCCESS;
  apr_ssize_t len = *ct;
  char *read;

  if (len < 0) {
    /** shall i read until close or just quit in this case? */
    *ct = 0;
    return status;
  }
  
  if (sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    read = NULL;
  }
  else {
    read = apr_pcalloc(sockreader->pool, len);
  }
  sockreader_read_block(sockreader, read, &len);
  *buf = read;
  /* if we did not get the request length quit with data incomplete error */
  if (len != *ct) {
    status = APR_INCOMPLETE;
  }

  *ct = len;

  if (sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    *ct = 0;
  }

  return status;
}

/**
 * Transfer encoding reader (only chunked implemented) 
 *
 * @param sockreader IN sockreader object
 * @param buf OUT content buffer
 * @param val IN type of encoding 
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t transfer_enc_reader(sockreader_t * sockreader,
                                 char **buf, apr_size_t *len, const char *val) {
  char *end;
  char *line;
  int chunk;
  char *read;
  apr_size_t cur_len;
  apr_size_t chunk_cur;
  apr_size_t chunk_len;

  apr_status_t status = APR_SUCCESS;

  *buf = NULL;
  (*len) = 0;
  if (sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    read = NULL;
  }
  else {
    read = apr_pcalloc(sockreader->pool, 1);
  }
  cur_len = 0;
  chunk = 0;
  if (my_strcasestr(val, "chunked")) {
    while (1) {
      while (sockreader_read_line(sockreader, &line) == APR_SUCCESS &&
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
      if (!sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
	read = my_realloc(sockreader, read, cur_len, cur_len + chunk);
      }
      chunk_len = 0;
      while (chunk_len < chunk) {
	chunk_cur = chunk - chunk_len;
	if (sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
	  status = sockreader_read_block(sockreader, NULL, &chunk_cur);
	}
	else {
	  status = sockreader_read_block(sockreader, &read[cur_len + chunk_len], &chunk_cur);
	}
	if (status != APR_SUCCESS && (status != APR_EOF || chunk_cur == 0)) {
	  break;
	}
	chunk_len += chunk_cur;
      }
      if (chunk != chunk_len) {
	status = APR_INCOMPLETE;
	break;
      }
      cur_len += chunk;
    }
  }
  else {
    return APR_ENOTIMPL;
  }

  if (chunk != 0) {
    /* no null chunk termination */
    status = APR_INCOMPLETE;
  }

  *buf = read;
  *len = cur_len;
  if (sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    *len = 0;
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
 *
 * @return APR_SUCCESS else an APR error
 */
apr_status_t eof_reader(sockreader_t * self, char **buf,
                        apr_size_t *len, const char *val) {
  char *read;
  apr_size_t block;
  apr_size_t alloc;
  apr_size_t i;

  apr_status_t status = APR_SUCCESS;
  *buf = NULL;
  (*len) = 0;

  if (!my_strcasestr(val, "close")) {
    return APR_ENOTIMPL;
  }

  i = 0;
  alloc = BLOCK_MAX;
  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    read = NULL;
  }
  else {
    read = apr_pcalloc(self->pool, alloc);
  }
  do {
    block = BLOCK_MAX;
    if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
      status = sockreader_read_block(self, NULL, &block);
    }
    else {
      status = sockreader_read_block(self, &read[i], &block);
    }
    i += block;
    if (!self->options & SOCKREADER_OPTIONS_IGNORE_BODY &&
	i >= alloc) {
      alloc += BLOCK_MAX;
      read = my_realloc(self, read, alloc - BLOCK_MAX, alloc);
    }
  } while (status == APR_SUCCESS); 

  *buf = read;
  *len = i;

  if (self->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    *len = 0;
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
apr_status_t encapsulated_reader(sockreader_t * sockreader, char **buf,
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
  
  tmp = apr_pstrdup(sockreader->ppool, enc_info);
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
  
  if (sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
    read = NULL;
  }
  else {
    read = apr_pcalloc(sockreader->pool, size);
  }
  sockreader_read_block(sockreader, read, &size);

  if (strcasecmp(key, "null-body") != 0 && (!preview || strcasecmp(preview, "0") != 0)) {
    if ((status = transfer_enc_reader(sockreader, &read2, &size2, "chunked")) 
	!= APR_SUCCESS) {
      return status;
    }
    if (!sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
      *buf = apr_pcalloc(sockreader->ppool, size + size2);
      memcpy(*buf, read, size);
      memcpy(&(*buf)[size], read2, size2);
      *len = size + size2;
    }
  }
  else {
    *len = size;
    *buf = read;
  }

  if (sockreader->options & SOCKREADER_OPTIONS_IGNORE_BODY) {
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

  if (!self->socket) {
    return APR_ENOSOCKET;
  }

  self->len = BLOCK_MAX;

#ifdef USE_SSL
  if (self->ssl) {
  tryagain:
    apr_sleep(1);
    status = SSL_read(self->ssl, self->buf, self->len);
    if (status <= 0) {
      int scode = SSL_get_error(self->ssl, status);

      if (scode == SSL_ERROR_ZERO_RETURN) {
	self->len = 0;
        return APR_EOF;
      }
      else if (scode != SSL_ERROR_WANT_WRITE && scode != SSL_ERROR_WANT_READ) {
	self->len = 0;
        return APR_ECONNABORTED;
      }
      else {
        goto tryagain;
      }
    }
    else {
      self->len = status;
      return APR_SUCCESS;
    }
  }
  else
#endif
  {
    status = apr_socket_recv(self->socket, self->buf, &self->len);
    if (APR_STATUS_IS_EOF(status) && self->len > 0) {
      return APR_SUCCESS;
    }
    else {
      return status;
    }
  }
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
static void *my_realloc(sockreader_t *sockreader, void *mem_old, 
                        apr_size_t size_old, apr_size_t size_new) {
  void *mem_new;

  apr_pool_create(&sockreader->next, sockreader->ppool);
  mem_new = apr_palloc(sockreader->next, size_new);
  if (mem_old != NULL) {
    memcpy(mem_new, mem_old, size_old < size_new ? size_old : size_new);
  }
  apr_pool_destroy(sockreader->pool);
  sockreader->pool = sockreader->next;
  sockreader->next = NULL;

  fflush(stderr);
  return mem_new;
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
    for ( ; (*s1 != '\0') && (apr_tolower(*s1) != apr_tolower(*s2)); s1++);
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

