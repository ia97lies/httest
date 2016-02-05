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
 *
 * Implementation of the HTTP Test Tool tcp module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/

#include <apr.h>
#include <apr_poll.h>
#include <apr_strings.h>
#include <openssl/ssl.h>

#include "nghttp2/nghttp2.h"
#include "regex.h"
#include "module.h"
#include "ssl_module.h"
#include "h2_module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
const char * h2_module = "h2_module";

enum { IO_NONE, WANT_READ, WANT_WRITE };

#define MAKE_NV(e, NAME, VALUE) \
    e.name = (uint8_t *) NAME; \
    e.value = (uint8_t *)VALUE; \
    e.namelen = sizeof(NAME) - 1; \
    e.valuelen = sizeof(VALUE) - 1; \
    e.flags = NGHTTP2_NV_FLAG_NONE;

#define MAKE_NV_CS(e, NAME, VALUE) \
    e.name = (uint8_t *) NAME; \
    e.value = (uint8_t *)VALUE; \
    e.namelen = sizeof(NAME) - 1; \
    e.valuelen = strlen(VALUE); \
    e.flags = NGHTTP2_NV_FLAG_NONE;

typedef struct h2_sconf_s {
  int h2_init;
  SSL *ssl;
  int is_server;
  nghttp2_session *session;
  int want_io;
} h2_sconf_t;

typedef struct h2_wconf_s {
#define H2_STATE_NONE           0
#define H2_STATE_SETTINGS       1
#define H2_STATE_PING           2
#define H2_STATE_GOAWAY         3
#define H2_STATE_HEADERS        4
#define H2_STATE_BODY           5
  int state;
} h2_wconf_t;

/************************************************************************
 * Local 
 ***********************************************************************/

/*****************************************************************************/
static h2_sconf_t *h2_get_socket_config(worker_t *worker) {
  h2_sconf_t *config;

  if (!worker || !worker->socket) {
    return NULL;
  }

  config = module_get_config(worker->socket->config, h2_module);
  if (config == NULL) {
    worker_log(worker, LOG_DEBUG, "create new sconf for socket %"APR_UINT64_T_HEX_FMT, worker->socket);
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->socket->config, apr_pstrdup(worker->pbody, h2_module), config);
  }
  return config;
}

/*****************************************************************************/
static h2_wconf_t *h2_get_worker_config(worker_t *worker) {
  h2_wconf_t *config;

  if (!worker) {
    return NULL;
  }

  config = module_get_config(worker->config, h2_module);
  if (config == NULL) {
    worker_log(worker, LOG_DEBUG, "create new wconf for worker %"APR_UINT64_T_HEX_FMT, worker);
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    module_set_config(worker->config, apr_pstrdup(worker->pbody, h2_module), config);
  }
  return config;
}

/*****************************************************************************/
static void executeMatchGrepExpectOnInput(worker_t *worker, const char *data) {
  worker_match(worker, worker->match.dot, data, strlen(data));
  worker_match(worker, worker->match.headers, data, strlen(data));
  worker_match(worker, worker->grep.dot, data, strlen(data));
  worker_match(worker, worker->grep.headers, data, strlen(data));
  worker_expect(worker, worker->expect.dot, data, strlen(data));
  worker_expect(worker, worker->expect.headers, data, strlen(data));
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

/*****************************************************************************/
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

/*****************************************************************************/
static const char *h2_get_name_of(const char *array[], int32_t id) {
  if (id > 0 && id < 7) {
    return array[id];
  }
  return "NOT_FOUND";
}

/*****************************************************************************/
static const char *h2_get_settings_as_text(apr_pool_t *pool, nghttp2_settings_entry *settings, int size) {
  int i;
  char *result = "SETTINGS: ";
  for (i = 0; i < size; i++) {
    result = apr_psprintf(pool, "%s%s=%d, ", result, h2_get_name_of(h2_settings_array, settings[i].settings_id), settings[i].value);
  }
  return result;
}

/*****************************************************************************/
static void ctl_poll(apr_pollfd_t *pollfd, h2_sconf_t *sconf) {
  pollfd->reqevents = 0;
  if (nghttp2_session_want_read(sconf->session) || sconf->want_io == WANT_READ) {
    pollfd->reqevents |= APR_POLLIN;
  }
  if (nghttp2_session_want_write(sconf->session) || sconf->want_io == WANT_WRITE) {
    pollfd->reqevents |= APR_POLLOUT;
  }
}

/*****************************************************************************/
static apr_status_t pollForData(worker_t *worker, int state)  {
  apr_pool_t *p;
  apr_pollset_t *pollset;
  apr_pollfd_t pollfd;
  apr_status_t status;
  int rv;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_sconf_t *sconf = h2_get_socket_config(worker);

  apr_pool_create(&p, NULL); 

  if ((status = apr_pollset_create(&pollset, 1, p, 0)) != APR_SUCCESS) {
    worker_log(worker, LOG_ERR, "Can not create pollset %s(%d)", my_status_str(p, status), status);
    return status;
  }

  pollfd.p = p;
  pollfd.desc_type = APR_POLL_SOCKET;
  pollfd.reqevents = APR_POLLIN | APR_POLLOUT;
  pollfd.desc.s = worker->socket->socket; 
  worker_log(worker, LOG_DEBUG, "pollForData worker: %"APR_UINT64_T_HEX_FMT" worker->socket: %"APR_UINT64_T_HEX_FMT" worker->socket->socket: %"APR_UINT64_T_HEX_FMT, worker, worker->socket, worker->socket->socket);
  while (wconf->state == state && 
      (nghttp2_session_want_read(sconf->session) ||
       nghttp2_session_want_write(sconf->session))) {
    apr_int32_t num;
    const apr_pollfd_t *result;
    worker_log(worker, LOG_DEBUG, "next poll cycle, state: %d\n", wconf->state);
    if ((status = apr_pollset_add(pollset, &pollfd)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Can not add pollfd to pollset %s(%d)", my_status_str(p, status), status);
      return status;
    };
    if ((status = apr_pollset_poll(pollset, worker->socktmo, &num, &result)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Can not poll on pollset %s(%d)", my_status_str(p, status), status);
      return status;
    }
    worker_log(worker, LOG_DEBUG, "poll tmo: %d, num: %d, events: %x", worker->socktmo, num, result[0].rtnevents);
    if (result[0].rtnevents & APR_POLLOUT) {
      worker_log(worker, LOG_DEBUG, "ready to send session data frames");
      if ((rv = nghttp2_session_send(sconf->session)) != 0) {
        worker_log(worker, LOG_ERR, "Could not send %d", rv);
        return APR_EGENERAL;
      }
    }
    if (result[0].rtnevents & APR_POLLIN) {
      worker_log(worker, LOG_DEBUG, "ready to receive session data frames");
      if ((rv = nghttp2_session_recv(sconf->session)) != 0) {
        worker_log(worker, LOG_ERR, "Could not recv %d", rv);
        return APR_EGENERAL;
      }
    }
    if ((status = apr_pollset_remove(pollset, &pollfd)) != APR_SUCCESS) {
      worker_log(worker, LOG_ERR, "Can not add pollfd to pollset %s(%d)", my_status_str(p, status), status);
      return status;
    };
    ctl_poll(&pollfd, sconf); 
    worker_log(worker, LOG_DEBUG, "end poll cycle, state: %d\n", wconf->state);
  }

  apr_pollset_destroy(pollset);

  apr_pool_destroy(p);
  return APR_SUCCESS;
}

/*****************************************************************************/
static ssize_t h2_send_callback(nghttp2_session *session, const uint8_t *data,
                                size_t length, int flags, void *user_data) {
  int rv;
  worker_t *worker = user_data;
  h2_sconf_t *sconf = h2_get_socket_config(worker);

  worker_log(worker, LOG_DEBUG, "h2_send_callback session: %"APR_UINT64_T_HEX_FMT
                            ", length: %ld, flags: %d, user_data:%"APR_UINT64_T_HEX_FMT, 
                session, length, flags, user_data);
  sconf->want_io = IO_NONE;
  rv = SSL_write(sconf->ssl, data, (int)length);
  if (rv <= 0) {
    int err = SSL_get_error(sconf->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      sconf->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  }
  worker_log(worker, LOG_DEBUG, "send callback rv: %d", rv);
  return rv;
}

/*****************************************************************************/
static ssize_t h2_recv_callback(nghttp2_session *session, uint8_t *buf,
                                size_t length, int flags, void *user_data) {
  int rv;
  worker_t *worker = user_data;
  h2_sconf_t *sconf = h2_get_socket_config(worker);

  worker_log(worker, LOG_DEBUG, "h2_recv_callback session: %"APR_UINT64_T_HEX_FMT
                            ", length: %ld, flags: %d, user_data:%"APR_UINT64_T_HEX_FMT, 
                session, length, flags, user_data);
  sconf->want_io = IO_NONE;
  rv = SSL_read(sconf->ssl, buf, (int)length);
  if (rv < 0) {
    int err = SSL_get_error(sconf->ssl, rv);
    if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
      sconf->want_io = (err == SSL_ERROR_WANT_READ ? WANT_READ : WANT_WRITE);
      rv = NGHTTP2_ERR_WOULDBLOCK;
    } else {
      rv = NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  } else if (rv == 0) {
    rv = NGHTTP2_ERR_EOF;
  }
  worker_log(worker, LOG_DEBUG, "recv callback rv: %d", rv);
  return rv;
}

/*****************************************************************************/
static int h2_on_frame_send_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  size_t i;
  apr_pool_t *p;
  worker_t *worker = user_data;
  apr_pool_create(&p, NULL);

  worker_log(worker, LOG_DEBUG, "> frame header type: %d, flag: %d", frame->hd.type, frame->hd.flags);
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
      const nghttp2_nv *nva = frame->headers.nva;
      worker_log(worker, LOG_INFO, "> HEADERS");
      for (i = 0; i < frame->headers.nvlen; ++i) {
        const char *name;
        const char *value;
        name = apr_pmemdup(p, nva[i].name, nva[i].namelen);
        value = apr_pmemdup(p, nva[i].value, nva[i].valuelen);
        worker_log(worker, LOG_INFO, "> %s: %s", name, value);
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    worker_log(worker, LOG_INFO, "> RST_STREAM");
    break;
  case NGHTTP2_GOAWAY:
    {
      const char *debug = apr_pmemdup(p, frame->goaway.opaque_data, frame->goaway.opaque_data_len);
      worker_log(worker, LOG_INFO, "> GOAWAY: %s %s", h2_get_name_of(h2_error_code_array, frame->goaway.error_code), debug);
    }
    break;
  case NGHTTP2_SETTINGS:
    if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
      worker_log(worker, LOG_INFO, "> SETTINGS ACK");
    }
    else {
      worker_log(worker, LOG_INFO, "> SETTINGS: niv: %lu", frame->settings.niv);
    }
  break;
    case NGHTTP2_PING:
      if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
        char *debug = apr_pcalloc(p, 9);
        memcpy(debug, frame->ping.opaque_data, 8);
        worker_log(worker, LOG_INFO, "> PING ACK: %s", debug);
      }
      else {
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

/*****************************************************************************/
static int h2_on_frame_recv_callback(nghttp2_session *session,
    const nghttp2_frame *frame,
    void *user_data) {
  size_t i;
  apr_pool_t *p;
  worker_t *worker = user_data;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  apr_pool_create(&p, NULL);

  worker_log(worker, LOG_DEBUG, "< frame header type: %d, flag: %d", frame->hd.type, frame->hd.flags);
  switch (frame->hd.type) {
    case NGHTTP2_HEADERS:
      if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
        const nghttp2_nv *nva = frame->headers.nva;
        worker_log(worker, LOG_INFO, "< HEADERS");
        for (i = 0; i < frame->headers.nvlen; ++i) {
          const char *name;
          const char *value;
          name = apr_pmemdup(p, nva[i].name, nva[i].namelen);
          value = apr_pmemdup(p, nva[i].value, nva[i].valuelen);
          worker_log(worker, LOG_INFO, "< %s: %s", name, value);
        }
      }
      break;
    case NGHTTP2_RST_STREAM:
      worker_log(worker, LOG_INFO, "< RST_STREAM");
      break;
    case NGHTTP2_GOAWAY:
      {
        const char *debug = apr_pmemdup(p, frame->goaway.opaque_data, frame->goaway.opaque_data_len);
        const char *goawayText = apr_psprintf(worker->pbody, "GOAWAY: %s \"%s\"", h2_get_name_of(h2_error_code_array, frame->goaway.error_code), debug);
        executeMatchGrepExpectOnInput(worker, goawayText);
		worker_log(worker, LOG_INFO, "< %s", goawayText);
        wconf->state = H2_STATE_NONE;
      }
      break;
    case NGHTTP2_SETTINGS:
      if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
        const char *settingsText = apr_pstrdup(worker->pbody, "SETTINGS ACK");
        executeMatchGrepExpectOnInput(worker, settingsText);
        worker_log(worker, LOG_INFO, "< %s", settingsText);
        wconf->state = H2_STATE_NONE;
      }
      else {
        const char *settingsText = h2_get_settings_as_text(worker->pbody, frame->settings.iv, frame->settings.niv);
        executeMatchGrepExpectOnInput(worker, settingsText);
        worker_log(worker, LOG_INFO, "< %s", settingsText);
      }
      break;
  case NGHTTP2_PING:
    {
      char *text = apr_pcalloc(p, 9);
      memcpy(text, frame->ping.opaque_data, 8);
      if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
        const char *pingText = apr_pstrcat(p, "PING ACK: ", text, NULL);
        executeMatchGrepExpectOnInput(worker, pingText);
        worker_log(worker, LOG_INFO, "< %s", pingText);
        wconf->state = H2_STATE_NONE;
      }
      else {
        const char *pingText = apr_pstrcat(p, "PING: ", text, NULL);
        executeMatchGrepExpectOnInput(worker, pingText);
        worker_log(worker, LOG_INFO, "< %s", pingText);
      }
    }
      break;
    default:
      worker_log(worker, LOG_INFO, "< (UNKNOWN)");
  }
  apr_pool_destroy(p);
  return 0;
}

/*****************************************************************************/
static int h2_on_begin_headers_callback(nghttp2_session *session,
      const nghttp2_frame *frame,
      void *user_data) {
  printf("Now headers will start\n");
  fflush(stdout);
  return 0;
}

/*****************************************************************************/
static int h2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                   uint32_t error_code,
                                   void *user_data) {
  int rv;
  worker_t *worker = user_data;
  rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

  worker_log(worker, LOG_INFO, "close callback %d", rv);
  if (rv != 0) {
    return rv;
  }
  return 0;
}

/*****************************************************************************/
static int h2_on_data_chunk_recv_callback(nghttp2_session *session,
                                          uint8_t flags, int32_t stream_id,
                                          const uint8_t *data, size_t len,
                                          void *user_data) {
    printf("[INFO] C <---------------------------- S (DATA chunk)\n"
           "%lu bytes\n",
           (unsigned long int)len);
    fwrite(data, 1, len, stdout);
    printf("\n");
  return 0;
}

/*****************************************************************************/
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

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, h2_on_data_chunk_recv_callback);
}


/************************************************************************
 * Hooks
 ************************************************************************/

/************************************************************************
 * Optional Functions 
************************************************************************/

/************************************************************************
 * Commands
 ***********************************************************************/
apr_status_t block_H2_NEW(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  int rv; 
  nghttp2_session_callbacks *callbacks;
  h2_sconf_t *sconf;

  sconf = h2_get_socket_config(parent); 
  sconf->h2_init = 0;
  sconf->ssl = ssl_get_session(parent);

  if (sconf->ssl == NULL) {
    worker_log(worker, LOG_ERR, "Only SSL is supported for HTTP/2.0");
    return APR_EINVAL;
  }

  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 callbacks");
    return APR_EGENERAL;
  }
  h2_setup_callbacks(callbacks);

  if (!sconf->is_server) {
    worker_log(worker, LOG_DEBUG, "client nghttp2 install worker: %"APR_UINT64_T_HEX_FMT, parent);
    rv = nghttp2_session_client_new(&sconf->session, callbacks, parent);
  }
  else {
    worker_log(worker, LOG_DEBUG, "server nghttp2 install worker: %"APR_UINT64_T_HEX_FMT, parent);
    rv = nghttp2_session_server_new(&sconf->session, callbacks, parent);
  }
  nghttp2_session_callbacks_del(callbacks);
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 session");
    return APR_EGENERAL;
  }

  sconf->h2_init = 1;

  return APR_SUCCESS;
}


/*****************************************************************************/
apr_status_t block_H2_SETTINGS(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  h2_sconf_t *sconf = h2_get_socket_config(parent); 

  if (sconf->h2_init == 0) {
    worker_log(parent, LOG_ERR, "h2 is not yet initialized, call _H2:NEW before any other call once.");
    return APR_EGENERAL;
  }
  else {
    nghttp2_settings_entry settings[6];
    int i = 0;
    size_t cur = 0;
    h2_wconf_t *wconf = h2_get_worker_config(parent);
    const char *param = store_get(worker->params, apr_itoa(ptmp, ++i));
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
      }
      else {
        worker_log(worker, LOG_ERR, "Unknown HTTP/2 setting '%s'", key);
        return APR_EINVAL;
      }
      param = store_get(worker->params, apr_itoa(ptmp, ++i));
    }

    if (nghttp2_submit_settings(sconf->session, NGHTTP2_FLAG_NONE, settings, cur) != 0) {
      worker_log(worker, LOG_ERR, "Invalid setting");
      return APR_EINVAL;
    }

    wconf->state = H2_STATE_SETTINGS;
    status = pollForData(parent, H2_STATE_SETTINGS); 

    return worker_assert(parent, status);
  }
}

/*****************************************************************************/
apr_status_t block_H2_PING(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  h2_sconf_t *sconf = h2_get_socket_config(parent); 

  if (sconf->h2_init == 0) {
    worker_log(parent, LOG_ERR, "h2 is not yet initialized, call _H2:NEW before any other call once.");
    return APR_EGENERAL;
  }
  else {
    h2_wconf_t *wconf = h2_get_worker_config(parent);
    const char *data = store_get(worker->params, "1");

    nghttp2_submit_ping(sconf->session, NGHTTP2_FLAG_NONE, (const uint8_t *)data);
    wconf->state = H2_STATE_PING;
    status = pollForData(parent, H2_STATE_PING); 
    return worker_assert(parent, status);
  }
}

/*****************************************************************************/
apr_status_t block_H2_GOAWAY(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  h2_sconf_t *sconf = h2_get_socket_config(parent); 

  if (sconf->h2_init == 0) {
    worker_log(parent, LOG_ERR, "h2 is not yet initialized, call _H2:NEW before any other call once.");
    return APR_EGENERAL;
  }
  else {
    h2_wconf_t *wconf = h2_get_worker_config(parent);
    const char *error = store_get(worker->params, "1");
    const char *data = store_get(worker->params, "2");

  nghttp2_submit_goaway(sconf->session, NGHTTP2_FLAG_NONE, nghttp2_session_get_last_proc_stream_id(sconf->session),
      h2_get_id_of(h2_error_code_array, error), (void *)data, data ? strlen(data) : 0);
    wconf->state = H2_STATE_GOAWAY;
    status = pollForData(parent, H2_STATE_GOAWAY); 
    return worker_assert(parent, status);
  }
}

/*****************************************************************************/
apr_status_t block_H2_WAIT(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  apr_status_t status;
  h2_sconf_t *sconf = h2_get_socket_config(parent); 

  if (sconf->h2_init == 0) {
    worker_log(parent, LOG_ERR, "h2 is not yet initialized, call _H2:NEW before any other call once.");
    return APR_EGENERAL;
  }
  else {
    h2_wconf_t *wconf = h2_get_worker_config(parent);

    wconf->state = H2_STATE_NONE;
    status = pollForData(parent, H2_STATE_NONE); 
    return worker_assert(parent, status);
  }
}

/*****************************************************************************/
apr_status_t h2_hook_pre_close(worker_t *worker) {
  int rv;
  apr_status_t status;
  h2_wconf_t *wconf = h2_get_worker_config(worker);
  h2_sconf_t *sconf = h2_get_socket_config(worker); 
  
  if (sconf->h2_init) {
    int i;
    /* due the description of the nghttp2 interface I should wait for 1 RTT and send goaway again */
    for (i = 0; i < 2; i++) {
      rv = nghttp2_submit_goaway(sconf->session, NGHTTP2_FLAG_NONE, nghttp2_session_get_last_proc_stream_id(sconf->session),
        NGHTTP2_NO_ERROR, (void *)"_CLOSE", strlen("_CLOSE"));
      if (rv != 0) {
        worker_log(worker, LOG_ERR, "Could not send goaway frame: %d", rv);
      }

      wconf->state = H2_STATE_NONE;
      status = pollForData(worker, H2_STATE_NONE); 
      apr_sleep(100000);
    }
  }

  return APR_SUCCESS;
}

/*****************************************************************************/
static apr_status_t h2_hook_close(worker_t *worker, char *info, char **new_info) {
  h2_sconf_t *sconf = h2_get_socket_config(worker); 
  worker_log(worker, LOG_DEBUG, "h2_hook_close worker: %"APR_UINT64_T_HEX_FMT", info: %s, sconf: %"APR_UINT64_T_HEX_FMT, worker, info, sconf);
  nghttp2_session_del(sconf->session);
  sconf->session = NULL;
  sconf->ssl = NULL;

  return APR_SUCCESS;
}

/*****************************************************************************/
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
  if ((status = module_command_new(global, "H2", "_NEW", "",
          "Build up a http2 session.",
          block_H2_NEW)) != APR_SUCCESS) {
    return status;
  }

  if ((status = module_command_new(global, "H2", "_SETTINGS", "<http/2 settings>",
          "Switch to http2 and exchange intial setting "
          "parameters for this connection.",
          block_H2_SETTINGS)) != APR_SUCCESS) {
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
  htt_hook_pre_close(h2_hook_pre_close, NULL, NULL, 0);
  htt_hook_close(h2_hook_close, NULL, NULL, 0);
  return APR_SUCCESS;
}


