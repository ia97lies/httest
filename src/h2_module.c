/**
 * Copyright 2010 Christian Liesch
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
 * @Author armin abfalterer <armin.abfalterer@united-security-providers.ch>
 *
 * Implementation of the HTTP Test Tool h2 module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/

#include <apr.h>
#include <apr_poll.h>
#include <apr_rmm.h>
#include <apr_strings.h>
#include <openssl/ssl.h>

#include "nghttp2/nghttp2.h"
#include "regex.h"
#include "module.h"
#include "ssl_module.h"
#include "body.h"
#include "h2_module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * h2_module = "h2_module";

enum { IO_NONE, WANT_READ, WANT_WRITE };

/* as defined in nghttp2_session.h */
#define NGHTTP2_INBOUND_BUFFER_LENGTH 16384

#define MAKE_NV3(NAME, VALUE, VALUELEN)                                        \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, VALUELEN,             \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

#define MAKE_NV4(NAME, NAMELEN, VALUE, VALUELEN)                               \
  { (uint8_t *)NAME, (uint8_t *)VALUE, NAMELEN, VALUELEN, NGHTTP2_NV_FLAG_NONE }

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

typedef struct h2_stream_s {
  int id;
  int closed;

  apr_pool_t *p;

  char *data;
  apr_size_t data_len;
  apr_ssize_t data_sent;

  char *data_in;
  apr_size_t data_in_len;
  apr_size_t data_in_read;
  apr_size_t data_in_expect;
  
  apr_table_t *headers_in;
  apr_table_t *headers_out;

  validation_t match;
  validation_t grep;
  validation_t expect;
} h2_stream_t;

typedef struct h2_sconf_s {
  SSL *ssl;
  int is_server;
  nghttp2_session *session;
  int want_io;
  char *authority;
} h2_sconf_t;

typedef struct h2_wconf_t {
  apr_hash_t *streams;
#define H2_STATE_CLOSED       0x00
#define H2_STATE_INIT         0x01
#define H2_STATE_NEGOTIATE    0x02
#define H2_STATE_ESTABLISHED  0x04
  int state;
  int settings;
  int pings;
  int goaways;
  int open_streams;
} h2_wconf_t;

/************************************************************************
 * Local 
 ***********************************************************************/

static h2_sconf_t *h2_get_socket_config(worker_t *worker) {
  h2_sconf_t *config;

  if (!worker || !worker->socket) {
    return NULL;
  }

  config = module_get_config(worker->socket->config, h2_module);
  if (config == NULL) {
    worker_log(worker, LOG_DEBUG,
               "create new sconf for socket %" APR_UINT64_T_HEX_FMT,
               worker->socket);
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->socket->config,
                      apr_pstrdup(worker->pbody, h2_module), config);
  }
  return config;
}

static h2_wconf_t *h2_get_worker_config(worker_t *worker) {
  h2_wconf_t *config;

  if (!worker) {
    return NULL;
  }

  config = module_get_config(worker->config, h2_module);
  if (config == NULL) {
    worker_log(worker, LOG_DEBUG, "create new wconf for worker %"APR_UINT64_T_HEX_FMT, worker);
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    config->streams = apr_hash_make(worker->pbody);
    module_set_config(worker->config, apr_pstrdup(worker->pbody, h2_module), config);
  }
  return config;
}

static int copy_table_entry(void *rec, const char *key, const char *val) {
 apr_table_t *t = rec;

 apr_table_addn(rec, key, val);
}

/************************************************************************
 * nghttp2 stuff 
 ***********************************************************************/
const char *h2_settings_array[] = {
  "NONE",
  "SETTINGS_HEADER_TABLE_SIZE",
  "SETTINGS_ENABLE_PUSH",
  "SETTINGS_MAX_CONCURRENT_STREAMS",
  "SETTINGS_INITIAL_WINDOW_SIZE",
  "SETTINGS_MAX_FRAME_SIZE",
  "SETTINGS_MAX_HEADER_LIST_SIZE",
  NULL
};

const char *h2_error_code_array[] = {
  "NGHTTP2_NO_ERROR",
  "NGHTTP2_PROTOCOL_ERROR",
  "NGHTTP2_INTERNAL_ERROR",
  "NGHTTP2_FLOW_CONTROL_ERROR",
  "NGHTTP2_SETTINGS_TIMEOUT",
  "NGHTTP2_STREAM_CLOSED",
  "NGHTTP2_FRAME_SIZE_ERROR",
  "NGHTTP2_REFUSED_STREAM",
  "NGHTTP2_CANCEL",
  "NGHTTP2_COMPRESSION_ERROR",
  "NGHTTP2_CONNECT_ERROR",
  "NGHTTP2_ENHANCE_YOUR_CALM",
  "NGHTTP2_INADEQUATE_SECURITY",
  "NGHTTP2_HTTP_1_1_REQUIRED"
};

static int32_t h2_get_id_of(const char *array[], const char *key) {
  int i; 
  if (key != NULL) {
    for (i = 0; i < 7; i++) {
      if (strcmp(key, array[i]) == 0) {
        return i;
      }
    }
  }
  return 0;
}

static const char *h2_get_name_of(const char *array[], int32_t id) {
  if (id > 0 && id < 7) {
    return array[id];
  }
  return "NOT_FOUND";
}

static const char *h2_get_settings_as_text(apr_pool_t *pool,
                                           nghttp2_settings_entry *settings,
                                           int size) {
  int i;
  char *result = "SETTINGS: ";
  for (i = 0; i < size; i++) {
    result =
        apr_psprintf(pool, "%s%s=%d, ", result,
                     h2_get_name_of(h2_settings_array, settings[i].settings_id),
                     settings[i].value);
  }
  return result;
}

static apr_status_t h2_open_session(worker_t *worker) {
  h2_sconf_t *sconf = h2_get_socket_config(worker);

  if (!sconf || !sconf->session) {
    worker_log(worker, LOG_ERR, "no open h2 session");
    return APR_EGENERAL;
  }

  return APR_SUCCESS;
}

static void ctl_poll(apr_pollfd_t *pollfd, h2_sconf_t *sconf) {
  pollfd->reqevents = 0;

  if (nghttp2_session_want_read(sconf->session) ||
      sconf->want_io == WANT_READ) {
    pollfd->reqevents |= APR_POLLIN;
  }

  if (nghttp2_session_want_write(sconf->session) ||
      sconf->want_io == WANT_WRITE) {
    pollfd->reqevents |= APR_POLLOUT;
  }
}

static apr_status_t poll(worker_t *worker) {
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_sconf_t *sconf = h2_get_socket_config(worker);
  apr_pollset_t *pollset;
  apr_pollfd_t pollfd;
  apr_status_t status;
  apr_pool_t *p;
  int loop = 1;
  int rv;

  apr_pool_create(&p, NULL);

  if ((status = apr_pollset_create(&pollset, 1, p, 0)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Can not create pollset %s(%d)",
               my_status_str(p, status), status);
    return status;
  }

  pollfd.p = p;
  pollfd.desc_type = APR_POLL_SOCKET;
  pollfd.reqevents = APR_POLLIN | APR_POLLOUT | APR_POLLHUP;
  pollfd.desc.s = worker->socket->socket;
  worker_log(worker, LOG_DEBUG,
             "poll worker: %" APR_UINT64_T_HEX_FMT
             " worker->socket: %" APR_UINT64_T_HEX_FMT
             " worker->socket->socket: %" APR_UINT64_T_HEX_FMT,
             worker, worker->socket, worker->socket->socket);

  ctl_poll(&pollfd, sconf);
  if ((status = apr_pollset_add(pollset, &pollfd)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Can not add pollfd to pollset: %s(%d)",
               my_status_str(p, status), status);
    return status;
  }

  while ((nghttp2_session_want_read(sconf->session) ||
          nghttp2_session_want_write(sconf->session)) && loop) {
    const apr_pollfd_t *result;
    apr_int32_t num;

    char *mode = apr_pstrcat(
        p, nghttp2_session_want_read(sconf->session) ? "r" : "-", "/",
        nghttp2_session_want_read(sconf->session) ? "w" : "", NULL);
    worker_log(worker, LOG_DEBUG, "next poll cycle: %s", mode);

    if ((status = apr_pollset_poll(pollset, worker->socktmo, &num, &result)) !=
        APR_SUCCESS) {
      if (APR_STATUS_IS_EINTR(status)) {
        continue;
      }
      worker_log(worker, LOG_ERR, "Can not poll on pollset: %s(%d)",
                 my_status_str(p, status), status);
      return status;
    }

    worker_log(worker, LOG_DEBUG, "poll tmo: %d, num: %d, events: %x",
               worker->socktmo, num, result[0].rtnevents);

    if (result[0].rtnevents & APR_POLLOUT) {
      worker_log(worker, LOG_DEBUG, "ready to send session data frames");
      if ((rv = nghttp2_session_send(sconf->session)) != 0) {
        worker_log(worker, LOG_DEBUG, "error on sending session data frame %d", rv);
        return APR_EGENERAL;
      }
    }

    if (result[0].rtnevents & APR_POLLIN) {
      worker_log(worker, LOG_DEBUG, "ready to receive session data frames");
      if ((rv = nghttp2_session_recv(sconf->session)) != 0) {
        worker_log(worker, LOG_DEBUG, "error on recieving session data frame %d", rv);
        return APR_EGENERAL;
      }
    }

    if (result[0].rtnevents & APR_POLLERR) {
      worker_log(worker, LOG_ERR, "Error on connection");
      return APR_EGENERAL;
    }

    if (result[0].rtnevents & APR_POLLHUP) {
      worker_log(worker, LOG_ERR, "Connection hangup");
      return APR_EGENERAL;
    }

    ctl_poll(&pollfd, sconf); 
    loop = (wconf->settings || wconf->open_streams || wconf->pings ||
            wconf->goaways);

    worker_log(worker, LOG_DEBUG, "end poll cycle");
  }

  apr_pollset_destroy(pollset);
  apr_pool_destroy(p);

  return APR_SUCCESS;
}

static ssize_t h2_send_callback(nghttp2_session *session, const uint8_t *data,
                                size_t length, int flags, void *user_data) {
  int rv;
  worker_t *worker = user_data;
  h2_sconf_t *sconf = h2_get_socket_config(worker);

  worker_log(worker, LOG_DEBUG,
             "h2_send_callback session: %" APR_UINT64_T_HEX_FMT
             ", length: %ld, flags: %d, user_data: %" APR_UINT64_T_HEX_FMT,
             session, length, flags, user_data);
  sconf->want_io = IO_NONE;

  rv = SSL_write(sconf->ssl, data, (int)length);
  if (rv <= 0) {
    int err = SSL_get_error(sconf->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      sconf->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      worker_log(worker, LOG_DEBUG, "want_io: %s",
                 err == SSL_ERROR_WANT_READ ? "read" : "write");
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      worker_log(worker, LOG_ERR, "Could not send %d", rv);
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }

  worker_log(worker, LOG_DEBUG, "send callback rv: %d", rv);
  return rv;
}

static ssize_t h2_recv_callback(nghttp2_session *session, uint8_t *buf,
                                size_t length, int flags, void *user_data) {
  worker_t *worker = user_data;
  h2_sconf_t *sconf = h2_get_socket_config(worker);
  int rv;

  worker_log(worker, LOG_DEBUG,
             "h2_recv_callback session: %" APR_UINT64_T_HEX_FMT
             ", length: %ld, flags: %d, user_data:%" APR_UINT64_T_HEX_FMT,
             session, length, flags, user_data);
  sconf->want_io = IO_NONE;
  rv = SSL_read(sconf->ssl, buf, (int)length);
  if (rv < 0) {
    int err = SSL_get_error(sconf->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      sconf->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      worker_log(worker, LOG_DEBUG, "want_io: %s",
                 err == SSL_ERROR_WANT_READ ? "read" : "write");
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      worker_log(worker, LOG_ERR, "Could not recv %d", rv);
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if (rv == 0) {
    rv = NGHTTP2_ERR_EOF;
  }

  worker_log(worker, LOG_DEBUG, "recv callback rv: %d", rv);
  return rv;
}

static int h2_on_frame_send_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  size_t i;
  apr_pool_t *p;
  worker_t *worker = user_data;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  apr_pool_create(&p, NULL);

  worker_log(worker, LOG_DEBUG, "> frame header stream %d, type: %d, flag: %d",
             frame->hd.stream_id, frame->hd.type, frame->hd.flags);

  switch (frame->hd.type) {
    case NGHTTP2_WINDOW_UPDATE:
      worker_log(worker, LOG_DEBUG, "> WINDOW_UPDATE");
      break;
    case NGHTTP2_HEADERS:
      worker_log(worker, LOG_DEBUG, "> HEADERS");
      if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
        const nghttp2_nv *nva = frame->headers.nva;
        for (i = 0; i < frame->headers.nvlen; ++i) {
          worker_log(worker, LOG_INFO, ">%d %s: %s", frame->hd.stream_id,
                     nva[i].name, nva[i].value);
        }
      }

    case NGHTTP2_DATA:
      worker_log(worker, LOG_DEBUG, "> DATA");
      break;
    case NGHTTP2_RST_STREAM:
      worker_log(worker, LOG_DEBUG, "> RST_STREAM");
      break;
    case NGHTTP2_GOAWAY: {
      const char *debug = apr_pmemdup(p, frame->goaway.opaque_data,
                                      frame->goaway.opaque_data_len);
      worker_log(worker, LOG_INFO, "> GOAWAY: %s %s",
                 h2_get_name_of(h2_error_code_array, frame->goaway.error_code),
                 debug);
      wconf->goaways++;
    } break;
    case NGHTTP2_SETTINGS:
      if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
        worker_log(worker, LOG_INFO, "> SETTINGS ACK");
      } else {
        worker_log(worker, LOG_INFO, "> SETTINGS: niv: %lu", frame->settings.niv);
      }
      break;
    case NGHTTP2_PING:
      if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
        char *opaque_data = apr_pcalloc(p, 9);
        memcpy(opaque_data, frame->ping.opaque_data, 8);
        worker_log(worker, LOG_INFO, "> PING ACK: %s", opaque_data);
      } else {
        worker_log(worker, LOG_INFO, "> PING");
      }
      break;
    default:
      worker_log(worker, LOG_INFO, "> UNKNOWN");
      break;
  }
  apr_pool_destroy(p);
  return 0;
}

static int h2_on_frame_recv_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  size_t i;
  apr_pool_t *p;
  worker_t *worker = user_data;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  apr_pool_create(&p, NULL);

  worker_log(worker, LOG_DEBUG, "< frame header type: %d, flag: %d",
             frame->hd.type, frame->hd.flags);

  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->hd.flags == NGHTTP2_FLAG_END_HEADERS) {
        worker_log(worker, LOG_DEBUG, "< END_HEADERS");
      }
      break;
    case NGHTTP2_DATA:
      if (frame->hd.flags == NGHTTP2_FLAG_END_STREAM) {
        worker_log(worker, LOG_DEBUG, "< END_STREAM");
      }
      else {
        worker_log(worker, LOG_DEBUG, "< DATA");
      }
      break;
    case NGHTTP2_WINDOW_UPDATE:
      worker_log(worker, LOG_INFO, "< WINDOW_UPDATE");
      break;
    case NGHTTP2_RST_STREAM:
      worker_log(worker, LOG_INFO, "< RST_STREAM");
      break;
    case NGHTTP2_GOAWAY: {
      const char *debug = apr_pmemdup(p, frame->goaway.opaque_data,
                                      frame->goaway.opaque_data_len);
      const char *goawayText = apr_psprintf(
          worker->pbody, "GOAWAY: %s \"%s\"",
          h2_get_name_of(h2_error_code_array, frame->goaway.error_code), debug);
      worker_log(worker, LOG_INFO, "< %s", goawayText);
    } break;
    case NGHTTP2_SETTINGS:
      if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
        const char *settingsText = apr_pstrdup(worker->pbody, "SETTINGS ACK");
        worker_log(worker, LOG_INFO, "< %s", settingsText);
        wconf->settings--;
      } else {
        const char *settingsText = h2_get_settings_as_text(
            worker->pbody, frame->settings.iv, frame->settings.niv);
        worker_log(worker, LOG_INFO, "< %s", settingsText);
      }
      break;
    case NGHTTP2_PING: {
      char *text = apr_pcalloc(p, 9);
      memcpy(text, frame->ping.opaque_data, 8);
      if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
        const char *pingText = apr_pstrcat(p, "PING ACK: ", text, NULL);
        worker_log(worker, LOG_INFO, "< %s", pingText);
        wconf->pings--;
      } else {
        const char *pingText = apr_pstrcat(p, "PING: ", text, NULL);
        worker_log(worker, LOG_INFO, "< %s", pingText);
      }
    } break;
    default:
      worker_log(worker, LOG_INFO, "< UNKNOWN");
  }
  apr_pool_destroy(p);
  return 0;
}

static int h2_on_begin_headers_callback(nghttp2_session *session,
                                        const nghttp2_frame *frame,
                                        void *user_data) {
  worker_t *worker = user_data;
  worker_log(worker, LOG_DEBUG, "< HEADERS");
  return 0;
}

static int h2_on_stream_close_callback(nghttp2_session *session,
                                       int32_t stream_id, uint32_t error_code,
                                       void *user_data) {
  worker_t *worker = user_data;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_stream_t *stream = apr_hash_get(
      wconf->streams, apr_itoa(worker->pbody, stream_id), APR_HASH_KEY_STRING);
  int rv;

  worker_log(worker, LOG_DEBUG, "stream %d closed", stream->id);
  stream->closed = 1;
  wconf->open_streams--;

  return 0;
}

static void h2_check_content_length(h2_stream_t *stream, const char *name,
                                    const char *val) {
  if (strcmp(name, "content-length") == 0) {
    stream->data_in_len = apr_atoi64(val);
  }
}

static int h2_check_response_header(worker_t *worker, const char *name) {
#define H2_RES_HEADER_DENY     0x1
#define H2_RES_HEADER_FILTER   0x2
  if (worker->headers_filter) {
    if (apr_table_get(worker->headers_filter, name)) {
      return H2_RES_HEADER_FILTER;
    }
  }
  if (worker->headers_allow) {
    if (!apr_table_get(worker->headers_allow, name)) {
      worker_log(worker, LOG_ERR, "%s header not allowed", name);
      return H2_RES_HEADER_DENY;
    }
  }
  return 0;
}

static int h2_on_header_callback(nghttp2_session *session,
                                 const nghttp2_frame *frame,
                                 const uint8_t *name, size_t namelen,
                                 const uint8_t *value, size_t valuelen,
                                 uint8_t flags, void *user_data) {
  worker_t *worker = user_data;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_stream_t *stream =
      apr_hash_get(wconf->streams, apr_itoa(worker->pbody, frame->hd.stream_id),
                   APR_HASH_KEY_STRING);

  switch (frame->hd.type) {
    case NGHTTP2_HEADERS: {
      int action = h2_check_response_header(worker, name);
      if (action & H2_RES_HEADER_DENY) {
        return NGHTTP2_ERR_CALLBACK_FAILURE; 
      }
      h2_check_content_length(stream, name, value);

      if (!(action & H2_RES_HEADER_FILTER)) {
        apr_table_set(stream->headers_in, name, value);
        worker_log(worker, LOG_INFO, "<%d %s: %s", stream->id, name, value);
      }

    } break;
  }

  return 0;
}

static int h2_on_data_chunk_recv_callback(nghttp2_session *session,
                                          uint8_t flags, int32_t stream_id,
                                          const uint8_t *data, size_t len,
                                          void *user_data) {
  worker_t *worker = user_data;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_stream_t *stream = apr_hash_get(
      wconf->streams, apr_itoa(worker->pbody, stream_id), APR_HASH_KEY_STRING);

  if (!stream->data_in) {
    stream->data_in = apr_palloc(stream->p, stream->data_in_len);
    stream->data_in_read = 0;
  }

  worker_log(worker, LOG_DEBUG, "read %d from stream %d", len, stream_id);

  if (stream->data_in_read + len > stream->data_in_len) {
    worker_log(worker, LOG_ERR, "Buffer to small (%d), stop receving",
               stream->data_in_len);

    return NGHTTP2_ERR_CALLBACK_FAILURE; 
  }

  memcpy(&stream->data_in[stream->data_in_read], data, len);
  stream->data_in_read += len;
  stream->data_in[stream->data_in_read] = 0;

  worker_log(worker, LOG_INFO, "<%d %s", stream_id, stream->data_in);

  return 0;
}

static void h2_setup_callbacks(nghttp2_session_callbacks *callbacks) {
  nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_callback);

  nghttp2_session_callbacks_set_recv_callback(callbacks, h2_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
                                                       h2_on_frame_send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       h2_on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                          h2_on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, h2_on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback(
      callbacks, h2_on_header_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, h2_on_data_chunk_recv_callback);
}


/************************************************************************
 * Optional Functions 
************************************************************************/

/************************************************************************
 * Commands
 ***********************************************************************/
apr_status_t block_H2_SESSION(worker_t *worker, worker_t *parent,
                              apr_pool_t *ptmp) {
  h2_wconf_t *wconf = h2_get_worker_config(parent);
  nghttp2_session_callbacks *callbacks;
  const char *data = store_get(worker->params, "ALL");
  const char *host = store_get(worker->params, "1");
  h2_sconf_t *sconf;
  int rv;

  wconf->state |= H2_STATE_INIT;
  rv = command_REQ(NULL, parent, (char *)data, parent->pbody);
  wconf->state |= H2_STATE_ESTABLISHED;

  if (rv != 0) {
    return APR_EGENERAL;
  }

  sconf = h2_get_socket_config(parent);
  sconf->ssl = ssl_get_session(parent);
  sconf->authority = apr_pstrdup(parent->pbody, host);
  /* hacky: see worker.c:command_CALL() */
  worker->socket = parent->socket;

  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 callbacks");
    return APR_EGENERAL;
  }
  h2_setup_callbacks(callbacks);

  if (!sconf->is_server) {
    worker_log(worker, LOG_DEBUG,
               "client nghttp2 install worker: %" APR_UINT64_T_HEX_FMT, parent);
    rv = nghttp2_session_client_new(&sconf->session, callbacks, parent);
  }
  else {
    worker_log(worker, LOG_DEBUG,
               "server nghttp2 install worker: %" APR_UINT64_T_HEX_FMT, parent);
    rv = nghttp2_session_server_new(&sconf->session, callbacks, parent);
  }
  nghttp2_session_callbacks_del(callbacks);
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 session");
    return APR_EGENERAL;
  }

  return rv;
}

apr_status_t block_H2_SETTINGS(worker_t *worker, worker_t *parent,
                               apr_pool_t *ptmp) {
  h2_sconf_t *sconf = h2_get_socket_config(parent);
  h2_wconf_t *wconf = h2_get_worker_config(parent);
  nghttp2_settings_entry settings[6];
  apr_status_t status;
  size_t cur = 0;
  const char *param;
  int i = 0;

  param  = store_get(worker->params, apr_itoa(ptmp, ++i));
  memset(&settings, 0, sizeof(settings));

  while (param && cur < 6) {
    char *setting = apr_pstrdup(parent->pbody, param);
    char *value;
    char *key = apr_strtok(setting, "=", &value);
    int32_t settings_id = h2_get_id_of(h2_settings_array, key);

    if (settings_id > 0) {
      settings[cur].settings_id = settings_id;
      settings[cur].value = apr_atoi64(value);
      cur++;
    } else {
      worker_log(worker, LOG_ERR, "Unknown h2 setting '%s'", key);
      return APR_EINVAL;
    }
    param = store_get(worker->params, apr_itoa(ptmp, ++i));
  }

  if (nghttp2_submit_settings(sconf->session, NGHTTP2_FLAG_NONE, settings,
                              cur) != 0) {
    worker_log(worker, LOG_ERR, "Invalid setting");
    return APR_EINVAL;
  }
  wconf->settings++;

  return APR_SUCCESS;
}

static ssize_t h2_data_read_callback(nghttp2_session *session,
                                     int32_t stream_id, uint8_t *buf,
                                     size_t length, uint32_t *data_flags,
                                     nghttp2_data_source *source,
                                     void *user_data) {
  worker_t *worker = user_data;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_stream_t *stream = apr_hash_get(
      wconf->streams, apr_itoa(worker->pbody, stream_id), APR_HASH_KEY_STRING);
  apr_size_t len=0, i;

  if (stream->data_len - stream->data_sent <= length) {
    len = stream->data_len - stream->data_sent;
    memcpy(buf, &stream->data[stream->data_sent], len);
  } else {
    len = length;
    memcpy(buf, &stream->data[stream->data_sent], length);
  }

  buf[len] = 0;
  stream->data_sent += len;
  worker_log(worker, LOG_INFO, ">%d %s", stream_id, buf);
  worker_log(worker, LOG_DEBUG, "send %d bytes", len);

  if (stream->data_len == stream->data_sent) {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  }

  return len;
}

h2_stream_t* h2_get_new_stream(worker_t *worker, int stream_id) {
  h2_stream_t *stream = apr_pcalloc(worker->pbody, sizeof(*stream));

  stream->id = stream_id;
  apr_pool_create(&stream->p, worker->pbody);

  /* TODO  allow to set buffer size */
  stream->data_in_len = NGHTTP2_INBOUND_BUFFER_LENGTH * 10;
  stream->headers_in = apr_table_make(stream->p, 20);
  stream->headers_out = apr_table_make(stream->p, 20);

  return stream;
}

apr_status_t block_H2_REQ(worker_t *worker, worker_t *parent,
                          apr_pool_t *ptmp) {
  h2_wconf_t *wconf = h2_get_worker_config(parent);
  h2_sconf_t *sconf = h2_get_socket_config(parent);
  const char *method = store_get(worker->params, "1");
  const char *path = store_get(worker->params, "2");
  apr_table_entry_t *e; 
  apr_status_t status;
  h2_stream_t *stream;
  int32_t stream_id;
  worker_t *body;
  int i=0, j, hdrn=0;
  apr_size_t data_len = 0;

  if ((status = h2_open_session(parent)) != APR_SUCCESS) {
    return status;
  }

  if ((status = worker_body(&body, parent)) != APR_SUCCESS) {
    return status;
  }

  stream_id = nghttp2_session_get_next_stream_id(sconf->session);
  worker_log(parent, LOG_DEBUG, "new stream %d", stream_id);

  stream = h2_get_new_stream(parent, stream_id);
  apr_hash_set(wconf->streams, apr_itoa(parent->pbody, stream_id),
               APR_HASH_KEY_STRING, stream);
  status = body->interpret(body, parent, NULL);

  /* copy expectations */
  stream->expect.headers = apr_table_make(parent->pbody, 10);
  stream->match.headers = apr_table_make(parent->pbody, 10);
  stream->match.body = apr_table_make(parent->pbody, 10);
  stream->expect.body = apr_table_make(parent->pbody, 10);
  apr_table_do(copy_table_entry, stream->expect.headers,
               parent->expect.headers, NULL);
  apr_table_do(copy_table_entry, stream->match.headers,
               parent->match.headers, NULL);
  apr_table_do(copy_table_entry, stream->match.body,
               parent->match.body, NULL);
  apr_table_do(copy_table_entry, stream->expect.body,
               parent->expect.body, NULL);
  apr_table_clear(parent->expect.headers);
  apr_table_clear(parent->match.headers);
  apr_table_clear(parent->match.body);
  apr_table_clear(parent->expect.body);
  
  /* copy headers */
  e = (apr_table_entry_t *)apr_table_elts(parent->cache)->elts;

  while (i < apr_table_elts(parent->cache)->nelts && *e[i].val) {
    char *name, *val;

    name = apr_strtok(e[i].val, ":", &val);
    if (*val && apr_isspace(*val)) {
      val++; 
    }
    apr_table_add(stream->headers_out, name, val);
    i++;
  }
  /* jump over empty line that separates headers from data */
  i++;

  if (i <= apr_table_elts(parent->cache)->nelts) {
    j = i;
    
    // T O D O
    /* calculate buffer size */
    for (i; i < apr_table_elts(parent->cache)->nelts; i++) {
      apr_size_t len;

      worker_get_line_length(worker, e[i], &len);
      data_len += len;
    }
    stream->data_len = data_len;
    stream->data = apr_pcalloc(parent->pbody, data_len);

    /* copy data */
    i = j;
    data_len = 0;
    for (i; i < apr_table_elts(parent->cache)->nelts; i++) {
      line_t line;
      line.info = e[i].key;
      line.buf = e[i].val;

      if (strstr(line.info, "resolve")) {
        int unresolved;
        line.buf = worker_replace_vars(worker, line.buf, &unresolved, parent->pbody);
      }
      if ((status = htt_run_line_flush(worker, &line)) != APR_SUCCESS) {
        return status;
      }
      if (strncasecmp(line.info, "NOCRLF:", 7) == 0) {
        line.len = apr_atoi64(&line.info[7]);
      } else if (strcasecmp(line.info, "NOCRLF") == 0) {
        line.len = strlen(line.buf);
      } else if (strcasecmp(line.info, "PLAIN") == 0) {
        /* add CRLF */
        line.buf = apr_pstrcat(parent->pbody, line.buf, "\r\n", NULL);
        line.len = strlen(line.buf);
      } else {
        line.len = strlen(line.buf);
      }

      memcpy(&stream->data[data_len], line.buf, line.len);
      data_len += line.len;
    }
  }
  apr_table_clear(parent->cache);

  nghttp2_nv hdrs[4 + apr_table_elts(stream->headers_out)->nelts];
  nghttp2_nv meth_nv = MAKE_NV3(":method", method, strlen(method)); 
  nghttp2_nv path_nv = MAKE_NV3(":path", path, strlen(path));
  nghttp2_nv scheme_nv = MAKE_NV3(":scheme", "https", 5);
  nghttp2_nv auth_nv = MAKE_NV3(":authority", sconf->authority, strlen(sconf->authority));
  hdrs[hdrn++] = meth_nv;
  hdrs[hdrn++] = path_nv;
  hdrs[hdrn++] = scheme_nv;
  hdrs[hdrn++] = auth_nv;

  e = (apr_table_entry_t *) apr_table_elts(stream->headers_out)->elts;
  for (i = 0; i < apr_table_elts(stream->headers_out)->nelts; i++) {
    nghttp2_nv hdr_nv =
        MAKE_NV4(e[i].key, strlen(e[i].key), e[i].val, strlen(e[i].val));
    hdrs[hdrn++] = hdr_nv;
  }

  nghttp2_data_provider data_prd;
  data_prd.read_callback = h2_data_read_callback;

  stream_id = nghttp2_submit_request(sconf->session, NULL, hdrs, hdrn,
                                     data_len ? &data_prd : NULL, parent);
  if (stream_id < 0) {
    worker_log(parent, LOG_ERR, "Could not submit request: %s",
               nghttp2_strerror(stream_id));
    return APR_EGENERAL;
  }
  wconf->open_streams++;

  worker_body_end(body, parent);
  return status;
}

apr_status_t block_H2_EXPECT(worker_t *worker, worker_t *parent,
                             apr_pool_t *ptmp) {
  h2_sconf_t *sconf = h2_get_socket_config(parent);
  h2_wconf_t *wconf = h2_get_worker_config(parent);

  const char *cat = store_get(worker->params, "1");
  const char *expect = store_get(worker->params, "2");

  int stream_id = nghttp2_session_get_next_stream_id(sconf->session);
  h2_stream_t *stream = apr_hash_get(
      wconf->streams, apr_itoa(worker->pbody, stream_id), APR_HASH_KEY_STRING);

  if (!stream) {
    worker_log(worker, LOG_ERR, "Invalid scope for command");
    return APR_EINVAL;
  }

  if (strcmp(cat, "bodysize") == 0) {
    stream->data_in_expect = apr_atoi64(expect);
  } else {
    worker_log(worker, LOG_ERR, "Invalid expectation");
    return APR_EINVAL;
  }

  return APR_SUCCESS;
}

apr_status_t block_H2_PING(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  h2_sconf_t *sconf = h2_get_socket_config(parent);
  h2_wconf_t *wconf = h2_get_worker_config(parent);
  const char *data = store_get(worker->params, "1");
  apr_status_t status;

  if ((status = h2_open_session(parent)) != APR_SUCCESS) {
    return status;
  }

  if (nghttp2_submit_ping(sconf->session, NGHTTP2_FLAG_NONE,
                          (const uint8_t *)data) != 0) {
    worker_log(worker, LOG_ERR, "Could not submit PING");
    return APR_EINVAL;
  }
  wconf->pings++;

  return APR_SUCCESS;
}

apr_status_t block_H2_GOAWAY(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  h2_sconf_t *sconf = h2_get_socket_config(parent);
  h2_wconf_t *wconf = h2_get_worker_config(parent);
  const char *error = store_get(worker->params, "1");
  const char *data = store_get(worker->params, "2");
  apr_status_t status;

  if ((status = h2_open_session(parent)) != APR_SUCCESS) {
    return status;
  }

  if (nghttp2_submit_goaway(
          sconf->session, NGHTTP2_FLAG_NONE,
          nghttp2_session_get_last_proc_stream_id(sconf->session),
          h2_get_id_of(h2_error_code_array, error), (void *)data,
          data ? strlen(data) : 0) != 0) {

    worker_log(worker, LOG_ERR, "Could not submit GOAWAY");
    return APR_EINVAL;
  }
  wconf->goaways++;

  return APR_SUCCESS;
}

apr_status_t block_H2_WAIT(worker_t *worker, worker_t *parent,
                           apr_pool_t *ptmp) {
  apr_status_t status;
  h2_sconf_t *sconf = h2_get_socket_config(parent); 
  h2_wconf_t *wconf = h2_get_worker_config(parent);
  apr_hash_index_t *hi;

  if ((status = h2_open_session(parent)) != APR_SUCCESS) {
    return status;
  }

  if ((status = poll(parent)) != APR_SUCCESS) {
    return status;
  }

  for (hi = apr_hash_first(worker->pbody, wconf->streams); hi; hi = apr_hash_next(hi)) {
    h2_stream_t *stream;
    apr_hash_this(hi, NULL, NULL, (void **)&stream);
    apr_table_entry_t *e;
    char *errmsg;
    apr_size_t data_len;
    int i;

    e = (apr_table_entry_t *)apr_table_elts(stream->headers_in)->elts;
    for (i = 0; i < apr_table_elts(stream->headers_in)->nelts; i++) {
      char *header = apr_pstrcat(worker->pbody, e[i].key, ": ", e[i].val, NULL);

      errmsg = apr_psprintf(worker->pbody, "EXPECT headers for stream %d", stream->id);
      worker_expect(parent, stream->expect.headers, header, strlen(header));
      errmsg = apr_psprintf(worker->pbody, "MATCH headers for stream %d", stream->id);
      worker_match(parent, stream->match.headers, header, strlen(header));
      /* worker_match(parent, stream->match.dot, data, strlen(data)); */
      /* worker_match(parent, stream->match.headers, data, strlen(data)); */
      /* worker_match(parent, stream->grep.dot, data, strlen(data)); */
      /* worker_match(parent, stream->grep.headers, data, strlen(data)); */
      /* worker_expect(parent, stream->expect.dot, data, strlen(data)); */
    }

    status = worker_assert_expect(worker, stream->expect.headers, errmsg, status);
    status = worker_assert_match(worker, stream->match.headers, errmsg, status);

    if (stream->data_in_expect && stream->data_in_read != stream->data_in_expect) {
      worker_log(worker, LOG_ERR,
                 "EXPECT bodysize for stream %d: read %d bytes", stream->id,
                 stream->data_in_read);
      return APR_EINVAL;
    }

    worker_match(parent, stream->match.body, stream->data_in,
                 stream->data_in_len);
    worker_expect(parent, stream->expect.body, stream->data_in,
                  stream->data_in_len);

    errmsg = apr_psprintf(worker->pbody, "EXPECT body for stream %d", stream->id);
    status = worker_assert_expect(worker, stream->expect.body, errmsg, status);
    errmsg = apr_psprintf(worker->pbody, "MATCH body for stream %d", stream->id);
    status = worker_assert_match(worker, stream->match.body, errmsg, status);

    apr_hash_set(wconf->streams, apr_itoa(parent->pbody, stream->id),
                 APR_HASH_KEY_STRING, NULL);
    apr_pool_destroy(stream->p);
  }

  return status;
}

/************************************************************************
 * Hooks
 ************************************************************************/
apr_status_t h2_hook_pre_close(worker_t *worker) {
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_sconf_t *sconf = h2_get_socket_config(worker); 
  apr_status_t status;
  int rv;

  /* if (!sconf || !sconf->session) { */
  /*   return APR_SUCCESS; */
  /* } */
  /*  */
  /* wconf->state = H2_STATE_CLOSED; */
  /* rv = nghttp2_submit_goaway( */
  /*     sconf->session, NGHTTP2_FLAG_NONE, */
  /*     nghttp2_session_get_last_proc_stream_id(sconf->session), NGHTTP2_NO_ERROR, */
  /*     (void *)"_CLOSE", strlen("_CLOSE")); */
  /*  */
  /* if (rv != 0) { */
  /*   worker_log(worker, LOG_ERR, "Could not send goaway frame: %d", rv); */
  /* } */
  /*  */
  /* wconf->goaways++; */
  /* return poll(worker); */

  return APR_SUCCESS;
}

static apr_status_t h2_hook_pre_connect(worker_t *worker) {
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  SSL_CTX *ssl_ctx = ssl_get_ctx(worker);

  if (wconf->state & H2_STATE_INIT) {
    worker_log(worker, LOG_DEBUG, "setting ALPN");
    /* TODO set h2 protocol in the alpn_select_cb callback */
    /* see SSL_CTX_set_alpn_select_cb */
    SSL_CTX_set_alpn_protos(ssl_ctx, (const unsigned char *)"\x02h2", 3);
    wconf->state |= H2_STATE_NEGOTIATE;
  } else {
    /* reset in case of mixed protocol usage */
    SSL_CTX_set_alpn_protos(ssl_ctx, 0, 0);
  }

  return APR_SUCCESS;
}

static apr_status_t h2_hook_close(worker_t *worker, char *info, char **new_info) {
  h2_sconf_t *sconf = h2_get_socket_config(worker);

  worker_log(worker, LOG_DEBUG, "h2_hook_close worker: %" APR_UINT64_T_HEX_FMT
                                ", info: %s, sconf: %" APR_UINT64_T_HEX_FMT,
             worker, info, sconf);
  nghttp2_session_del(sconf->session);
  sconf->session = NULL;
  sconf->ssl = NULL;

  return APR_SUCCESS;
}

static apr_status_t h2_hook_accept(worker_t *worker, char *data) {
  h2_sconf_t *sconfig = h2_get_socket_config(worker);
  sconfig->is_server = 1;

  return APR_SUCCESS;
}

/************************************************************************
 * Module 
 ***********************************************************************/
apr_status_t h2_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "H2", "_SESSION", "",
          "Build up a http2 session.",
          block_H2_SESSION)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "H2", "_SETTINGS", "<http/2 settings>",
          "Switch to http2 and exchange intial setting "
          "parameters for this connection.",
          block_H2_SETTINGS)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "H2", "_REQ", "<method> <url>",
          "Send a http2 request to peer.",
          block_H2_REQ)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "H2", "_EXPECT", "<category> <regex>",
          "Expectations TODO.",
          block_H2_EXPECT)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "H2", "_PING", "<8 byte>",
          "Send http2 ping.",
          block_H2_PING)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "H2", "_GOAWAY", "<error-code> <string>",
          "Send a http2 goaway to peer.",
          block_H2_GOAWAY)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "H2", "_WAIT", "",
          "Just receive and answer on HTTP/protocol.",
          block_H2_WAIT)) != APR_SUCCESS) {
    return status;
  }

  htt_hook_accept(h2_hook_accept, NULL, NULL, 0);
  htt_hook_pre_connect(h2_hook_pre_connect, NULL, NULL, 0);
  htt_hook_pre_close(h2_hook_pre_close, NULL, NULL, 0);
  htt_hook_close(h2_hook_close, NULL, NULL, 0);
  return APR_SUCCESS;
}


