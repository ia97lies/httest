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
	worker_t *worker;
  h2_sconf_t *sconf;
  apr_table_t *headers;
  /* need this for timeout settings */
  transport_t *h2_transport;
  apr_interval_time_t tmo;
#define H2_STATE_NONE           0
#define H2_STATE_SETTINGS       1
#define H2_STATE_PING 					2
#define H2_STATE_HEADERS        3
#define H2_STATE_BODY           4
  int state;
} h2_transport_t;

/************************************************************************
 * nghttp2 stuff 
 ***********************************************************************/

/*
 * Check for the next poll
 * @param pollfd INOUT which is to prepare
 * @param sconf INOUT which state is to prepare
 */
static void ctl_poll(apr_pollfd_t *pollfd, h2_sconf_t *sconf) {
  pollfd->reqevents = 0;
  if (nghttp2_session_want_read(sconf->session) || sconf->want_io == WANT_READ) {
    pollfd->reqevents |= APR_POLLIN;
  }
  if (nghttp2_session_want_write(sconf->session) || sconf->want_io == WANT_WRITE) {
    pollfd->reqevents |= APR_POLLOUT;
  }
}

/*
 * Poll for data recv/send
 * @param h2_transport IN h2 transport struct
 * @param state IN the state we should poll
 */
static apr_status_t pollForData(h2_transport_t *h2_transport, int state)  {
	apr_pool_t *p;
	apr_pollset_t *pollset;
	apr_pollfd_t pollfd;
	apr_status_t status;
	int rv;
	worker_t *worker = h2_transport->worker;

	apr_pool_create(&p, NULL); 

	if ((status = apr_pollset_create(&pollset, 1, p, 0)) != APR_SUCCESS) {
		worker_log(worker, LOG_ERR, "Can not create pollset %s(%d)", my_status_str(p, status), status);
		return status;
	}

	pollfd.p = p;
	pollfd.desc_type = APR_POLL_SOCKET;
	pollfd.reqevents = APR_POLLIN | APR_POLLOUT;
	pollfd.desc.s = worker->socket->socket; 
	while (h2_transport->state == state && 
			(nghttp2_session_want_read(h2_transport->sconf->session) ||
			 nghttp2_session_want_write(h2_transport->sconf->session))) {
		apr_int32_t num;
		const apr_pollfd_t *result;
		worker_log(worker, LOG_DEBUG, "next poll cycle, state: %d\n", h2_transport->state);
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
			if ((rv = nghttp2_session_send(h2_transport->sconf->session)) != 0) {
				worker_log(worker, LOG_ERR, "Could not send %d", rv);
				return APR_EGENERAL;
			}
		}
		if (result[0].rtnevents & APR_POLLIN) {
			worker_log(worker, LOG_DEBUG, "ready to receive session data frames");
			if ((rv = nghttp2_session_recv(h2_transport->sconf->session)) != 0) {
				worker_log(worker, LOG_ERR, "Could not recv %d", rv);
				return APR_EGENERAL;
			}
		}
		if ((status = apr_pollset_remove(pollset, &pollfd)) != APR_SUCCESS) {
			worker_log(worker, LOG_ERR, "Can not add pollfd to pollset %s(%d)", my_status_str(p, status), status);
			return status;
		};
		ctl_poll(&pollfd, h2_transport->sconf); 
		worker_log(worker, LOG_DEBUG, "end poll cycle, state: %d\n", h2_transport->state);
	}

	apr_pollset_destroy(pollset);

	apr_pool_destroy(p);
	return APR_SUCCESS;
}

/*
 * The implementation of nghttp2_send_callback type. Here we write
 * |data| with size |length| to the network and return the number of
 * bytes actually written. See the documentation of
 * nghttp2_send_callback for the details.
 */
static ssize_t h2_send_callback(nghttp2_session *session, const uint8_t *data,
                                size_t length, int flags, void *user_data) {
  int rv;
  h2_transport_t *h2_transport = user_data;
	worker_t *worker = h2_transport->worker;
  h2_sconf_t *sconf = h2_transport->sconf;
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

/*
 * The implementation of nghttp2_recv_callback type. Here we read data
 * from the network and write them in |buf|. The capacity of |buf| is
 * |length| bytes. Returns the number of bytes stored in |buf|. See
 * the documentation of nghttp2_recv_callback for the details.
 */
static ssize_t h2_recv_callback(nghttp2_session *session, uint8_t *buf,
                                size_t length, int flags, void *user_data) {
  int rv;
  h2_transport_t *h2_transport = user_data;
	worker_t *worker = h2_transport->worker;
  h2_sconf_t *sconf = h2_transport->sconf;
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

static int h2_on_frame_send_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  size_t i;
  apr_pool_t *p;
  h2_transport_t *h2_transport = user_data;
  worker_t *worker = h2_transport->worker;
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
			worker_log(worker, LOG_INFO, "> GOAWAY: %s (%ld)", debug, frame->goaway.error_code);
		}
    break;
  case NGHTTP2_SETTINGS:
		if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
			worker_log(worker, LOG_INFO, "> SETTINGS ACK");
		}
		else {
			worker_log(worker, LOG_INFO, "> SETTINGS");
			worker_log(worker, LOG_INFO, "> SETTINGS: niv: %lu", frame->settings.niv);
		}
	break;
		case NGHTTP2_PING:
			if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
				worker_log(worker, LOG_INFO, "> PING ACK");
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

static int h2_on_frame_recv_callback(nghttp2_session *session,
		const nghttp2_frame *frame,
		void *user_data) {
	size_t i;
	apr_pool_t *p;
	h2_transport_t *h2_transport = user_data;
	worker_t *worker = h2_transport->worker;
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
				worker_log(worker, LOG_INFO, "< GOAWAY: %s (%ld)", debug, frame->goaway.error_code);
			}
			break;
		case NGHTTP2_SETTINGS:
			if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
				worker_log(worker, LOG_INFO, "< SETTINGS ACK");
				h2_transport->state = H2_STATE_NONE;
			}
			else {
				worker_log(worker, LOG_INFO, "< SETTINGS");
				worker_log(worker, LOG_INFO, "< SETTINGS: niv: %lu", frame->settings.niv);
			}
			break;
		case NGHTTP2_PING:
			if (frame->hd.flags == NGHTTP2_FLAG_ACK) {
				worker_log(worker, LOG_INFO, "< PING ACK");
				h2_transport->state = H2_STATE_NONE;
			}
			else {
				worker_log(worker, LOG_INFO, "< PING");
			}
			break;
		default:
			worker_log(worker, LOG_INFO, "< (UNKNOWN)");
	}
	apr_pool_destroy(p);
	return 0;
}

static int h2_on_begin_headers_callback(nghttp2_session *session,
			const nghttp2_frame *frame,
			void *user_data) {
  printf("Now headers will start\n");
  fflush(stdout);
  return 0;
}

static int h2_on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
		                               uint32_t error_code,
		                               void *user_data) {
	int rv;
	h2_transport_t *h2_transport = user_data;
	worker_t *worker = h2_transport->worker;
	rv = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);

	worker_log(worker, LOG_INFO, "close callback %d", rv);
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

  nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks,
                                                          h2_on_begin_headers_callback);
  nghttp2_session_callbacks_set_on_stream_close_callback(
      callbacks, h2_on_stream_close_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback(
      callbacks, h2_on_data_chunk_recv_callback);
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
	h2_transport->state = H2_STATE_SETTINGS;
	h2_transport->worker = worker;
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
  return APR_SUCCESS;
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t h2_transport_set_timeout(void *data, apr_interval_time_t t) {
  return APR_SUCCESS;
}

/**
 * Set timeout
 * @param data IN void pointer to socket
 * @param desc OUT os socket descriptor
 * @return apr status
 */
static apr_status_t h2_transport_get_timeout(void *data, apr_interval_time_t *t) {
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
 * H2 NEW command
 */
apr_status_t block_H2_NEW(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  /* do this the old way, becaus argv tokenizer removes all "\" */
  int rv; 
  nghttp2_session_callbacks *callbacks;
  transport_t *transport;
  h2_transport_t *h2_transport;
  h2_sconf_t *sconf;

  sconf = h2_get_socket_config(worker); 

	if (sconf->ssl == NULL) {
		worker_log(worker, LOG_ERR, "Only SSL is supported for HTTP/2.0");
		return APR_EINVAL;
	}

  h2_transport = h2_get_transport(worker, sconf);
  transport = transport_new(h2_transport, worker->pbody, 
          h2_transport_os_desc_get, 
          h2_transport_set_timeout, 
          h2_transport_get_timeout, 
          h2_transport_read, 
          h2_transport_write);
  transport_register(worker->socket, transport);

  rv = nghttp2_session_callbacks_new(&callbacks);
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 callbacks");
    return APR_EGENERAL;
  }
  h2_setup_callbacks(callbacks);

  if (!sconf->is_server) {
      rv = nghttp2_session_client_new(&sconf->session, callbacks, h2_transport);
  }
  else {
      rv = nghttp2_session_server_new(&sconf->session, callbacks, h2_transport);
  }
  if (rv != 0) {
    worker_log(worker, LOG_ERR, "Can not create http2 session");
    return APR_EGENERAL;
  }
	return APR_SUCCESS;
}


/**
 * H2 SETTINGS command
 */
apr_status_t block_H2_SETTINGS(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
	apr_status_t status;
	transport_t *transport = transport_get_current(worker->socket);
	h2_transport_t *h2_transport = transport_get_data(transport);
	h2_sconf_t *sconf = h2_get_socket_config(worker); 

	sconf = h2_get_socket_config(worker); 

	nghttp2_submit_settings(sconf->session, NGHTTP2_FLAG_NONE, NULL, 0);

	h2_transport->state = H2_STATE_SETTINGS;
	status = pollForData(h2_transport, H2_STATE_SETTINGS); 

	/* TODO: Belongs to close
	   nghttp2_session_callbacks_del(callbacks);
	   */
	return status;
}

/**
 * H2 PING command
 */
apr_status_t block_H2_PING(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
	apr_status_t status;
	transport_t *transport = transport_get_current(worker->socket);
	h2_transport_t *h2_transport = transport_get_data(transport);
	h2_sconf_t *sconf = h2_get_socket_config(worker); 

	nghttp2_submit_ping(sconf->session, NGHTTP2_FLAG_NONE, NULL);
	h2_transport->state = H2_STATE_PING;
	status = pollForData(h2_transport, H2_STATE_PING); 
	return status;
}

/**
 * H2 WAIT command
 */
apr_status_t block_H2_WAIT(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
	apr_status_t status;
	transport_t *transport = transport_get_current(worker->socket);
	h2_transport_t *h2_transport = transport_get_data(transport);

	h2_transport->state = H2_STATE_NONE;
	status = pollForData(h2_transport, H2_STATE_NONE); 
	return status;
}

/*
 * Do a graceful close
 */
apr_status_t h2_hook_pre_close(worker_t *worker) {
	int rv;
	apr_status_t status;
	transport_t *transport = transport_get_current(worker->socket);
	h2_transport_t *h2_transport = transport_get_data(transport);
	h2_sconf_t *sconf = h2_get_socket_config(worker); 

	rv = nghttp2_submit_goaway(sconf->session, NGHTTP2_FLAG_NONE, nghttp2_session_get_last_proc_stream_id(sconf->session),
			NGHTTP2_NO_ERROR, (void *)"_CLOSE", strlen("_CLOSE"));
  if (rv != 0) {
		worker_log(worker, LOG_ERR, "Could not send goaway frame: %d", rv);
	}

	h2_transport->state = H2_STATE_NONE;
	status = pollForData(h2_transport, H2_STATE_NONE); 
	apr_sleep(100000);
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

	if ((status = module_command_new(global, "H2", "_WAIT", "",
					"Just receive and answer on HTTP/protocol.",
					block_H2_WAIT)) != APR_SUCCESS) {
		return status;
	}

	htt_hook_accept(h2_hook_accept, NULL, NULL, 0);
	htt_hook_pre_close(h2_hook_pre_close, NULL, NULL, 0);
	return APR_SUCCESS;
}


