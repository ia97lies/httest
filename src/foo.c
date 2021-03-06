
#include "htt/dso.h"
#include "stdlib.h"
#include "stdio.h"
#include "string.h"

int i = 0;

const char *foo_test_val = NULL;

static void* foo_custom_handle() {
  return &i;
}

static apr_status_t foo_configure(void *custom, const char *buf) {
  return APR_SUCCESS;
}

static apr_status_t foo_read(void *custom, char *buf, apr_size_t *len) {
  const char *str = "HTTP/1.1 200 OK\r\n\r\n";
  *len = strlen(str);
  memcpy(buf, str, *len);
  return APR_SUCCESS;
}

static apr_status_t foo_read2(void *custom, char *buf, apr_size_t *len) {
  /*
  const char *str = "GET / HTTP/1.1\r\n\r\n";
  */
  char str[1024];
  ++i;
  sprintf(str, "GET /%d HTTP/1.1 \r\n\r\n", i);
  *len = strlen(str);
  memcpy(buf, str, *len);
  return APR_SUCCESS;
}

static apr_status_t foo_write(void *custom, const char *buf, apr_size_t len) {
  return APR_SUCCESS;
}

apr_status_t foo_set(const char *string) {
  foo_test_val = string;
  return APR_SUCCESS;
}

apr_status_t foo_test(const char *string) {
  if (foo_test_val && strcmp(string, foo_test_val) == 0) { 
    return APR_SUCCESS;
  }
  else {
    return APR_EINVAL;
  }
}

transport_dso_t foo_front = {
  foo_custom_handle, 
  foo_configure, 
  foo_read, 
  foo_write
};

transport_dso_t foo_back = {
  foo_custom_handle, 
  foo_configure, 
  foo_read2, 
  foo_write
};

