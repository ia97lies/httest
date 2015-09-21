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
  SSL *ssl;
  int is_server;
  nghttp2_session *session;
  int want_io;
} h2_sconf_t;

typedef struct h2_transport_s {
  h2_sconf_t *sconf;
  apr_table_t *headers;
  /* need this for timeout settings */
  transport_t *h2_transport;
  apr_interval_time_t tmo;
#define H2_REQ_STATE_HEADERS        0
#define H2_REQ_STATE_BODY           1
  int req_state;
} h2_transport_t;

/************************************************************************
 * nghttp2 stuff 
 ***********************************************************************/
/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t h2_send_callback(nghttp2_session *session, const uint8_t *data,
                                size_t length, int flags, void *user_data) {
  h2_sconf_t *sconf;
  int rv;
  sconf = user_data;
  sconf->want_io = IO_NONE;
  ERR_clear_error();
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
  return rv;
}

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t h2_recv_callback(nghttp2_session *session, uint8_t *buf,
                                size_t length, int flags, void *user_data) {
  h2_sconf_t *sconf;
  int rv;
  sconf = user_data;
  sconf->want_io = IO_NONE;
  ERR_clear_error();
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
  return rv;
}

static int h2_on_frame_send_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  size_t i;
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (nghttp2_session_get_stream_user_data(session, frame->hd.stream_id)) {
      const nghttp2_nv *nva = frame->headers.nva;
      printf("[INFO] C ----------------------------> S (HEADERS)\n");
      for (i = 0; i < frame->headers.nvlen; ++i) {
        fwrite(nva[i].name, nva[i].namelen, 1, stdout);
        printf(": ");
        fwrite(nva[i].value, nva[i].valuelen, 1, stdout);
        printf("\n");
      }
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C ----------------------------> S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C ----------------------------> S (GOAWAY)\n");
    break;
  }
  return 0;
}

static int h2_on_frame_recv_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  size_t i;
  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat == NGHTTP2_HCAT_RESPONSE) {
      const nghttp2_nv *nva = frame->headers.nva;
        printf("[INFO] C <---------------------------- S (HEADERS)\n");
        for (i = 0; i < frame->headers.nvlen; ++i) {
          fwrite(nva[i].name, nva[i].namelen, 1, stdout);
          printf(": ");
          fwrite(nva[i].value, nva[i].valuelen, 1, stdout);
          printf("\n");
        }
    }
    break;
  case NGHTTP2_RST_STREAM:
    printf("[INFO] C <---------------------------- S (RST_STREAM)\n");
    break;
  case NGHTTP2_GOAWAY:
    printf("[INFO] C <---------------------------- S (GOAWAY)\n");
    break;
  }
  return 0;
}

/*
 * The implementation of nghttp2_on_stream_close_callback type. We use
 * this function to know the response is fully received. Since we just
 * fetch 1 resource in this program, after reception of the response,
 * we submit GOAWAY and close the session.
 */
static int h2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                       uint32_t error_code,
                                       void *user_data) {
    int rv;
    rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

    if (rv != 0) {
      return rv;
    }
  return 0;
}

#define MAX_OUTLEN 4096

/*
 * The implementation of nghttp2_on_data_chunk_recv_callback type. We
 * use this function to print the received response body.
 */
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

/*
 * Setup callback functions. nghttp2 API offers many callback
 * functions, but most of them are optional. The h2_send_callback is
 * always required. Since we use nghttp2_session_recv(), the
 * h2_recv_callback is also required.
 */
static void h2_setup_callbacks(nghttp2_session_callbacks *callbacks) {
  nghttp2_session_callbacks_set_send_callback(callbacks, h2_send_callback);

  nghttp2_session_callbacks_set_recv_callback(callbacks, h2_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback(callbacks,
                                                       h2_on_frame_send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks,
                                                       h2_on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, h2_on_stream_close_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, h2_on_data_chunk_recv_callback);
}

static apr_status_t exec_io(h2_sconf_t *sconf) { 
  if (nghttp2_session_recv(sconf->session) != 0) {
    return APR_EGENERAL;
  }

  if (nghttp2_session_send(sconf->session) != 0) {
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


/************************************************************************
 * Local 
 ***********************************************************************/

/**
 * GET ssl socket config from socket
 *
 * @param worker IN worker
 * @return socket config
 */
static h2_sconf_t *h2_get_socket_config(worker_t *worker) {
  h2_sconf_t *config;

  if (!worker || !worker->socket) {
    return NULL;
  }

  config = module_get_config(worker->socket->config, h2_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    config->ssl = ssl_get_session(worker);
    module_set_config(worker->socket->config, apr_pstrdup(worker->pbody, h2_module), config);
  }
  return config;
}

/**
 * Create h2 transport context
 * @param worker IN worker
 * @return h2 transport context
 */
static h2_transport_t *h2_get_transport(worker_t *worker, h2_sconf_t *sconf) {
  apr_interval_time_t tmo;
  h2_transport_t *h2_transport = apr_pcalloc(worker->pbody, sizeof(*h2_transport));
  h2_transport->sconf = sconf;
  h2_transport->h2_transport = worker->socket->transport;
  apr_socket_timeout_get(worker->socket->socket, &tmo);
  h2_transport->tmo = apr_time_as_msec(tmo);
  h2_transport->headers = apr_table_make(worker->pbody, 5);

  return h2_transport;
}

/**
 * Get os socket descriptor
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t h2_transport_os_desc_get(void *data, int *desc) {
  h2_transport_t *h2_transport = data;
  return APR_SUCCESS;
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t h2_transport_set_timeout(void *data, apr_interval_time_t t) {
  h2_transport_t *h2_transport = data;
  return APR_SUCCESS;
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t h2_transport_get_timeout(void *data, apr_interval_time_t *t) {
  h2_transport_t *h2_transport = data;
  return APR_SUCCESS;
}

/**
 * read from socket
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t h2_transport_read(void *data, char *buf, apr_size_t *size) {
  h2_transport_t *h2_transport = data;
  *size = 0;
  return APR_EOF;
}

/**
 * write to socket
 * @param data IN void pointer to socket
 * @param buf IN buffer
 * @param size INOUT buffer len
 * @return apr status
 */
static apr_status_t h2_transport_write(void *data, const char *buf, apr_size_t size) {
  h2_transport_t *h2_transport = data;

  if (h2_transport->req_state == H2_REQ_STATE_HEADERS)
    if (strlen(buf) > 0 && strcmp(buf, "\r\n") != 0) {
      apr_table_add(h2_transport->headers, "", buf);
    }
    else if (strlen(buf) == 0) {
      apr_pool_t *p; 
      char *line;
      char *method;
      char *path;
      char *last;
      apr_table_entry_t *e ;
      int n = apr_table_elts(h2_transport->headers)->nelts + 3;
      int i = 0;

      apr_pool_create(&p, NULL); 
      // TODO: send request now with h2_transport->headers :)
      nghttp2_nv nva[n];
      e = (apr_table_entry_t *) apr_table_elts(h2_transport->headers)->elts;
      // parse request line
      line = apr_pstrdup(p, e[0].val);
      method = apr_strtok(line, " ", &last);
      path = apr_strtok(NULL, " ", &last);

      MAKE_NV_CS(nva[0], ":method", method);
      MAKE_NV_CS(nva[1], ":path", path);
      MAKE_NV(nva[2], ":scheme", "https");
      MAKE_NV(nva[3], ":authority", "localhost:8080");
      /* TODO: do this later and cleaner
         for (i = 0; i < apr_table_elts(h2_transport->headers)->nelts; i++) {
         nva[3+i] = MAKE_NV_CS(":method", method);
         }
         */
      /* XXX this is just some hardcoded header to have one */
      MAKE_NV(nva[4], "user-agent", "nghttp2/" NGHTTP2_VERSION);
      /* TODO: store the id and implement many request on the same tcp in parallel!
       *       currently I have no clue how I should solve this syntactically :)
       */
      nghttp2_submit_request(h2_transport->sconf->session, NULL, nva, n, NULL, NULL);

      h2_transport->req_state = H2_REQ_STATE_BODY;
      apr_pool_destroy(p);
    }
    else {
    }

  return APR_SUCCESS;
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
/**
 * H2 V command
 *
 * @param worker IN command
 * @param worker IN thread data object
 * @param data IN Http2 version 
 *
 * @return APR_SUCCESS, APR_ENOTIMPL if wrong version or APR_EGENERAL on wrong parameters
 */
apr_status_t block_H2_SESSION(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  /* do this the old way, becaus argv tokenizer removes all "\" */
  int rv; 
  const char *version;
  const char *var;
  SSL *ssl;
  nghttp2_session_callbacks *callbacks;
  transport_t *transport;
  h2_transport_t *h2_transport;
  h2_sconf_t *sconf;

  version = store_get(worker->params, "1");

  if (!version) {
    worker_log(worker, LOG_ERR, "Version is missing");
    return APR_EGENERAL;
  }

  if (strcmp(version, "2.0") != 0) {
    worker_log(worker, LOG_ERR, "Only version 2.0 is supported");
    return APR_ENOTIMPL;
  }

  var = store_get(worker->params, "2");
  if (var) {
      worker_var_set(parent, var, version);
  }

  sconf = h2_get_socket_config(worker); 

  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 callbacks");
    APR_EGENERAL;
  }
  h2_setup_callbacks(callbacks);
  nghttp2_session_callbacks_del(callbacks);

  if (!sconf->is_server) {
      rv = nghttp2_session_client_new(&sconf->session, callbacks, sconf);
  }
  else {
      rv = nghttp2_session_server_new(&sconf->session, callbacks, sconf);
  }
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 session");
    APR_EGENERAL;
  }

  h2_transport = h2_get_transport(worker, sconf);
  transport = transport_new(h2_transport, worker->pbody, 
          h2_transport_os_desc_get, 
          h2_transport_set_timeout, 
          h2_transport_get_timeout, 
          h2_transport_read, 
          h2_transport_write);
  transport_register(worker->socket, transport);

  nghttp2_submit_settings(sconf->session, NGHTTP2_FLAG_NONE, NULL, 0);

  return APR_SUCCESS;
}

/**
 * do h2 server session
 *
 * @param worker IN
 *
 * @return APR_SUCCESS or apr error
 */
static apr_status_t h2_hook_accept(worker_t *worker, char *data) {
  apr_status_t status;
  h2_sconf_t *sconfig = h2_get_socket_config(worker);
  sconfig->is_server = 1;

  return APR_SUCCESS;
}


/************************************************************************
 * Module 
 ***********************************************************************/
apr_status_t h2_module_init(global_t *global) {
  apr_status_t status;

  if ((status = module_command_new(global, "H2", "_SESSION", "<Version>",
                               "Switch to http2 client and return version. "
                               "Currently only 2.0 is supported.",
                               block_H2_SESSION)) != APR_SUCCESS) {
    return status;
  }

  htt_hook_accept(h2_hook_accept, NULL, NULL, 0);
  return APR_SUCCESS;
}


