
#include "dso.h"
#include "stdio.h"

char *gbuf = NULL;

static void* foo_custom_handle() {
  if (!gbuf) {
    gbuf = malloc(10000);
  }
  return gbuf;
}

static apr_status_t foo_configure(void *custom, const char *buf) {
  return APR_SUCCESS;
}

static apr_status_t foo_read(void *custom, const char *buf, apr_size_t *len) {
  const char *str = "HTTP/1.1 200 OK\r\n\r\n";
  *len = strlen(str);
  memcpy(buf, str, *len);
  return APR_SUCCESS;
}

static apr_status_t foo_write(void *custom, const char *buf, apr_size_t len) {
  return APR_SUCCESS;
}

transport_dso_t foo_front = {
  foo_custom_handle, 
  foo_configure, 
  foo_read, 
  foo_write
};


