
#include "dso.h"
#include "stdio.h"

static void* foo_custom_handle() {
  fprintf(stdout, "Custom handle\n");
  fflush(stdout);
  return NULL;
}

static apr_status_t foo_configure(void *custom, const char *buf) {
  fprintf(stdout, "configure \"%s\"\n", buf);
  fflush(stdout);
  return APR_SUCCESS;
}

static apr_status_t foo_read(void *custom, const char *buf, apr_size_t *len) {
  fprintf(stdout, "read");
  fflush(stdout);
  return APR_SUCCESS;
}

static apr_status_t foo_write(void *custom, const char *buf, apr_size_t len) {
  fprintf(stdout, "write");
  fflush(stdout);
  return APR_SUCCESS;
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
  foo_read, 
  foo_write
};


