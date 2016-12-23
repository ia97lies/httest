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
 * Implementation of the HTTP Test Tool ssl.
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "defines.h"
#ifdef USE_SSL
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <openssl/ossl_typ.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>

/* don't move, needed exactly here on windows */
#include <module.h>

#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#include <apr.h>
#include <apr_strings.h>
#include <apr_file_io.h>
#include <apr_portable.h>
#include <apr_errno.h>
#include <apr_hash.h>

#if APR_HAVE_UNISTD_H
#include <unistd.h> /* for getpid() */
#endif

#ifndef RAND_MAX
#include <limits.h>
#define RAND_MAX INT_MAX
#endif

#include "ssl.h"


/************************************************************************
 * Definitions 
 ***********************************************************************/
#ifndef NUL
#define NUL '\0'
#endif

#define X509_REVOKED_get_serialNumber(xs) (xs->serialNumber)
#define strEQn(s1,s2,n)  (strncmp(s1,s2,n)     == 0)
#define strcEQ(s1,s2)    (strcasecmp(s1,s2)    == 0)
#define strcEQn(s1,s2,n) (strncasecmp(s1,s2,n) == 0)

#if OPENSSL_VERSION_NUMBER < 0x10100000

#define X509_get_signature_algorithm(xs) (xs->cert_info->signature->algorithm)
#define X509_get_key_algorithm(xs)       (xs->cert_info->key->algor->algorithm)
#define X509_NAME_ENTRY_get_data_ptr(xs) (xs->value->data)
#define X509_NAME_ENTRY_get_data_len(xs) (xs->value->length)

#else

static const ASN1_OBJECT *X509_get_signature_algorithm(const X509 *x)
{
	const X509_ALGOR *algor;
	const ASN1_OBJECT *paobj;

	algor = X509_get0_tbs_sigalg(x);
	X509_ALGOR_get0(&paobj, NULL, NULL, algor);
	return paobj;
}

static const ASN1_OBJECT *X509_get_key_algorithm(const X509 *x)
{
	X509_PUBKEY *pubkey;
	X509_ALGOR *algor;
	const ASN1_OBJECT *paobj;

	pubkey = X509_get_X509_PUBKEY(x);
	X509_PUBKEY_get0_param(NULL, NULL, NULL, &algor, pubkey);
	X509_ALGOR_get0(&paobj, NULL, NULL, algor);
	return paobj;
}

static inline const unsigned char *
X509_NAME_ENTRY_get_data_ptr(const X509_NAME_ENTRY *ne)
{
	ASN1_STRING *str;

	str = X509_NAME_ENTRY_get_data(ne);
	return ASN1_STRING_get0_data(str);
}

static inline int X509_NAME_ENTRY_get_data_len(const X509_NAME_ENTRY *ne)
{
	ASN1_STRING *str;

	str = X509_NAME_ENTRY_get_data(ne);
	return ASN1_STRING_length(str);
}

#endif

/************************************************************************
 * Forward declaration 
 ***********************************************************************/

static unsigned long ssl_util_thr_id(void);
static void ssl_util_thr_lock(int mode, int type, const char *file, int line); 
static int ssl_rand_choosenum(int l, int h); 
static apr_status_t ssl_util_thread_cleanup(void *data); 
static char *ssl_var_lookup_ssl_cert_dn(apr_pool_t *p, X509_NAME *xsname, const char *var);
static char *ssl_var_lookup_ssl_cert_valid(apr_pool_t *p, ASN1_UTCTIME *tm);
static char *ssl_var_lookup_ssl_cert_remain(apr_pool_t *p, ASN1_UTCTIME *tm);
static char *ssl_var_lookup_ssl_cert_serial(apr_pool_t *p, X509 *xs);
static char *ssl_var_lookup_ssl_cert_PEM(apr_pool_t *p, X509 *xs);

/************************************************************************
 * Implementation
 ***********************************************************************/

/**
 * To ensure thread-safetyness in OpenSSL - work in progress
 */
static apr_thread_mutex_t **lock_cs;
static int lock_num_locks;

/**
 * Thread setup (SSL call back)
 *
 * @param p IN pool
 */
void ssl_util_thread_setup(apr_pool_t * p) {
  int i;

  lock_num_locks = CRYPTO_num_locks();
  lock_cs = apr_palloc(p, lock_num_locks * sizeof(*lock_cs));

  for (i = 0; i < lock_num_locks; i++) {
    apr_thread_mutex_create(&(lock_cs[i]), APR_THREAD_MUTEX_DEFAULT, p);
  }

  CRYPTO_set_id_callback(ssl_util_thr_id);

  CRYPTO_set_locking_callback(ssl_util_thr_lock);

  apr_pool_cleanup_register(p, NULL, ssl_util_thread_cleanup,
                            apr_pool_cleanup_null);
}

/**
 * Do a seed
 */
void ssl_rand_seed(void) {
  int nDone = 0;
  int n, l;
  time_t t;
  pid_t pid;
  unsigned char stackdata[256];

  /*
   * seed in the current time (usually just 4 bytes)
   */
  t = time(NULL);
  l = sizeof(time_t);
  RAND_seed((unsigned char *) &t, l);
  nDone += l;

  /*
   * seed in the current process id (usually just 4 bytes)
   */
  pid = getpid();
  l = sizeof(pid_t);
  RAND_seed((unsigned char *) &pid, l);
  nDone += l;

  /*
   * seed in some current state of the run-time stack (128 bytes)
   */
  n = ssl_rand_choosenum(0, sizeof(stackdata) - 128 - 1);
  RAND_seed(stackdata + n, 128);
  nDone += 128;
}

/**
 * ssl handshake client site
 *
 * @param ssl IN ssl object
 * @param error OUT error text
 *
 * @return APR_EINVAL if no ssl context or
 *         APR_ECONNREFUSED if could not handshake or
 *         APR_SUCCESS
 */
apr_status_t ssl_handshake(SSL *ssl, char **error, apr_pool_t *pool) {
  apr_status_t status = APR_SUCCESS;
  int do_next = 1;

  *error = NULL;
  
  /* check first if we have a ssl context */
  if (!ssl) {
    *error = apr_pstrdup(pool, "No ssl context");
    return APR_EINVAL;
  }
  
  while (do_next) {
    int ret, ecode;

    apr_sleep(1);
    
    ret = SSL_do_handshake(ssl);
    ecode = SSL_get_error(ssl, ret);

    switch (ecode) {
    case SSL_ERROR_NONE:
      status = APR_SUCCESS;
      do_next = 0;
      break;
    case SSL_ERROR_WANT_READ:
      /* Try again */
      do_next = 1;
      break;
    case SSL_ERROR_WANT_WRITE:
      /* Try again */
      do_next = 1;
      break;
    case SSL_ERROR_WANT_CONNECT:
    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:
      {
	char *cascade_err = NULL;
	char buf[256];
	unsigned long l;
	while ((l = ERR_get_error()) != 0) {
	  ERR_error_string_n(l, buf, sizeof buf);
	  if (cascade_err) {
	    apr_pstrcat(pool, cascade_err, ";", buf, NULL);
	  }
	  else {
	    cascade_err = apr_pstrdup(pool, buf);
	  }
	}
	*error = apr_psprintf(pool, "Handshake failed: %s", cascade_err ? cascade_err : "<null>");
	status = APR_ECONNREFUSED;
	do_next = 0;
      }
      break;
    }
  }
  return status;
}

/**
 * ssl accept
 *
 * @param worker IN thread data object
 *
 * @return APR_SUCCESS
 */
apr_status_t ssl_accept(SSL *ssl, char **error, apr_pool_t *pool) {
  int rc;
  int err;

  *error = NULL;
  
  /* check first if we have a ssl context */
  if (!ssl) {
    *error = apr_pstrdup(pool, "No ssl context");
    return APR_EINVAL;
  }
  
tryagain:
  apr_sleep(1);
  if (SSL_is_init_finished(ssl)) {
    return APR_SUCCESS;
  }

  if ((rc = SSL_accept(ssl)) <= 0) {
    err = SSL_get_error(ssl, rc);

    if (err == SSL_ERROR_ZERO_RETURN) {
      *error = apr_pstrdup(pool, "SSL accept connection closed");
      return APR_ECONNABORTED;
    }
    else if (err == SSL_ERROR_WANT_READ) {
      *error = apr_pstrdup(pool, "SSL accept SSL_ERROR_WANT_READ.");
      goto tryagain;
    }
    else if (ERR_GET_LIB(ERR_peek_error()) == ERR_LIB_SSL &&
	     ERR_GET_REASON(ERR_peek_error()) == SSL_R_HTTP_REQUEST) {
      /*
       * The case where OpenSSL has recognized a HTTP request:
       * This means the client speaks plain HTTP on our HTTPS port.
       * ssl_io_filter_error will disable the ssl filters when it
       * sees this status code.
       */
      *error = apr_pstrdup(pool, "SSL accept client speaks plain HTTP");
      return APR_ENOTSOCK;
    }
    else if (err == SSL_ERROR_SYSCALL) {
       *error = apr_pstrdup(pool, 
                  "SSL accept interrupted by system "
                  "[Hint: Stop button pressed in browser?!]");
       return APR_ECONNABORTED;
    }
    else /* if (ssl_err == SSL_ERROR_SSL) */ {
	 /*
	  * Log SSL errors and any unexpected conditions.
          */
      *error = apr_psprintf(pool, "SSL library error %d in accept", err);
      return APR_ECONNABORTED;
    }
  }
 
  return APR_SUCCESS;
}

/**
 * This is a SSL lock call back
 *
 * @param mode IN lock mode
 * @param type IN lock type
 * @param file IN unused
 * @param line IN unused
 */
static void ssl_util_thr_lock(int mode, int type, const char *file, int line) {
  apr_status_t status;

  if (type < lock_num_locks) {
    if (mode & CRYPTO_LOCK) {
      if ((status = apr_thread_mutex_lock(lock_cs[type])) != APR_SUCCESS) {
	fprintf(stderr, "Fatal error could not lock");
	exit(status);
      }
    }
    else {
      if ((status = apr_thread_mutex_unlock(lock_cs[type])) != APR_SUCCESS) {
	fprintf(stderr, "Fatal error could not unlock");
	exit(status);
      }
    }
  }
}

/**
 * @return current thread id (SSL call back)
 */
static unsigned long ssl_util_thr_id(void) {
  /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread
   * id is a structure twice that big.  Use the TCB pointer instead as a
   * unique unsigned long.
   */
#ifdef __MVS__
  struct PSA {
    char unmapped[540];
    unsigned long PSATOLD;
  }  *psaptr = 0;

  return psaptr->PSATOLD;
#else
  return (unsigned long) apr_os_thread_current();
#endif
}

/**
 * Thread clean up function (SSL call back)
 *
 * @param data IN unused
 *
 * @return APR_SUCCESS
 */
static apr_status_t ssl_util_thread_cleanup(void *data) {
  CRYPTO_set_locking_callback(NULL);
  CRYPTO_set_id_callback(NULL);

  /* Let the registered mutex cleanups do their own thing
   */
  return APR_SUCCESS;
}

/**
 * Rand between low and high
 *
 * @param l IN bottom
 * @param h IN top value
 *
 * @return something between l and h
 */
static int ssl_rand_choosenum(int l, int h) {
  int i;
  char buf[50];

  srand((unsigned int) time(NULL));
  apr_snprintf(buf, sizeof(buf), "%.0f",
               (((double) (rand() % RAND_MAX) / RAND_MAX) * (h - l)));
  i = atoi(buf) + 1;
  if (i < l)
    i = l;
  if (i > h)
    i = h;
  return i;
}

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *try_load_engine(const char *engine, int debug) {
  ENGINE *e = ENGINE_by_id("dynamic");
  if (e) {
    if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
	|| !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
      ENGINE_free(e);
      e = NULL;
    }
  }
  return e;
}

ENGINE *setup_engine(BIO *err, const char *engine, int debug) {
  ENGINE *e = NULL;

  if (engine) {
    if(strcmp(engine, "auto") == 0) {
      BIO_printf(err,"enabling auto ENGINE support\n");
      ENGINE_register_all_complete();
      return NULL;
    }
    if((e = ENGINE_by_id(engine)) == NULL
	&& (e = try_load_engine(engine, debug)) == NULL) {
	    BIO_printf(err,"invalid engine \"%s\"\n", engine);
	    ERR_print_errors(err);
	    return NULL;
    }
    if (debug) {
      ENGINE_ctrl(e, ENGINE_CTRL_SET_LOGSTREAM,
		  0, err, 0);
    }
    if(!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
      BIO_printf(err,"can't use that engine\n");
      ERR_print_errors(err);
      ENGINE_free(e);
      return NULL;
    }

    BIO_printf(err,"engine \"%s\" set.\n", ENGINE_get_id(e));

    /* Free our "structural" reference. */
    ENGINE_free(e);
  }
  return e;
}

/**
 * Get ssl information from a X509 Cert
 *
 * @param p IN Pool
 * @param xs IN Cert
 * @param var IN Variable name
 *
 * @return Variable value
 */
char *ssl_var_lookup_ssl_cert(apr_pool_t *p, X509 *xs, const char *var) {
    char *result;
    X509_NAME *xsname;
    int nid;
    char *cp;

    result = NULL;

    if (strcEQ(var, "M_VERSION")) {
        result = apr_psprintf(p, "%lu", X509_get_version(xs)+1);
    }
    else if (strcEQ(var, "M_SERIAL")) {
        result = ssl_var_lookup_ssl_cert_serial(p, xs);
    }
    else if (strcEQ(var, "V_START")) {
        result = ssl_var_lookup_ssl_cert_valid(p, X509_get_notBefore(xs));
    }
    else if (strcEQ(var, "V_END")) {
        result = ssl_var_lookup_ssl_cert_valid(p, X509_get_notAfter(xs));
    }
    else if (strcEQ(var, "V_REMAIN")) {
        result = ssl_var_lookup_ssl_cert_remain(p, X509_get_notAfter(xs));
    }
    else if (strcEQ(var, "S_DN")) {
        xsname = X509_get_subject_name(xs);
        cp = X509_NAME_oneline(xsname, NULL, 0);
        result = apr_pstrdup(p, cp);
        OPENSSL_free(cp);
    }
    else if (strlen(var) > 5 && strcEQn(var, "S_DN_", 5)) {
        xsname = X509_get_subject_name(xs);
        result = ssl_var_lookup_ssl_cert_dn(p, xsname, var+5);
    }
    else if (strcEQ(var, "I_DN")) {
        xsname = X509_get_issuer_name(xs);
        cp = X509_NAME_oneline(xsname, NULL, 0);
        result = apr_pstrdup(p, cp);
        OPENSSL_free(cp);
    }
    else if (strlen(var) > 5 && strcEQn(var, "I_DN_", 5)) {
        xsname = X509_get_issuer_name(xs);
        result = ssl_var_lookup_ssl_cert_dn(p, xsname, var+5);
    }
    else if (strcEQ(var, "A_SIG")) {
        nid = OBJ_obj2nid((ASN1_OBJECT *)X509_get_signature_algorithm(xs));
        result = apr_pstrdup(p,
                             (nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(nid));
    }
    else if (strcEQ(var, "A_KEY")) {
        nid = OBJ_obj2nid((ASN1_OBJECT *)X509_get_key_algorithm(xs));
        result = apr_pstrdup(p,
                             (nid == NID_undef) ? "UNKNOWN" : OBJ_nid2ln(nid));
    }
    else if (strcEQ(var, "CERT")) {
        result = ssl_var_lookup_ssl_cert_PEM(p, xs);
    }

    result = apr_pstrdup(p, result);
    return result;
}

/* In this table, .extract is non-zero if RDNs using the NID should be
 * extracted to for the SSL_{CLIENT,SERVER}_{I,S}_DN_* environment
 * variables. */
static const struct {
    char *name;
    int   nid;
    int   extract;
} ssl_var_lookup_ssl_cert_dn_rec[] = {
    { "C",     NID_countryName,            1 },
    { "ST",    NID_stateOrProvinceName,    1 }, /* officially    (RFC2156) */
    { "SP",    NID_stateOrProvinceName,    0 }, /* compatibility (SSLeay)  */
    { "L",     NID_localityName,           1 },
    { "O",     NID_organizationName,       1 },
    { "OU",    NID_organizationalUnitName, 1 },
    { "CN",    NID_commonName,             1 },
    { "T",     NID_title,                  1 },
    { "I",     NID_initials,               1 },
    { "G",     NID_givenName,              1 },
    { "S",     NID_surname,                1 },
    { "D",     NID_description,            1 },
#ifdef NID_userId
    { "UID",   NID_x500UniqueIdentifier,   1 },
#endif
    { "Email", NID_pkcs9_emailAddress,     1 },
    { NULL,    0,                          0 }
};

static char *ssl_var_lookup_ssl_cert_dn(apr_pool_t *p, X509_NAME *xsname, const char *var)
{
    char *result, *ptr;
    X509_NAME_ENTRY *xsne;
    int i, j, n, idx = 0;
    apr_size_t varlen;

    /* if an _N suffix is used, find the Nth attribute of given name */
    ptr = strchr(var, '_');
    if (ptr != NULL && strspn(ptr + 1, "0123456789") == strlen(ptr + 1)) {
        idx = atoi(ptr + 1);
        varlen = ptr - var;
    } else {
        varlen = strlen(var);
    }

    result = NULL;

    for (i = 0; ssl_var_lookup_ssl_cert_dn_rec[i].name != NULL; i++) {
        if (strEQn(var, ssl_var_lookup_ssl_cert_dn_rec[i].name, varlen)
            && strlen(ssl_var_lookup_ssl_cert_dn_rec[i].name) == varlen) {
            for (j = 0; j < X509_NAME_entry_count(xsname); j++) {

                xsne = X509_NAME_get_entry(xsname, j);

                n =OBJ_obj2nid((ASN1_OBJECT *)X509_NAME_ENTRY_get_object(xsne));

                if (n == ssl_var_lookup_ssl_cert_dn_rec[i].nid && idx-- == 0) {
                    const unsigned char *data = X509_NAME_ENTRY_get_data_ptr(xsne);
                    /* cast needed from unsigned char to char */
                    result = apr_pstrmemdup(p, data,
                                            X509_NAME_ENTRY_get_data_len(xsne));
#if APR_CHARSET_EBCDIC
                    ap_xlate_proto_from_ascii(result, X509_NAME_ENTRY_get_data_len(xsne));
#endif /* APR_CHARSET_EBCDIC */
                    break;
                }
            }
            break;
        }
    }
    return result;
}

static char *ssl_var_lookup_ssl_cert_valid(apr_pool_t *p, ASN1_UTCTIME *tm)
{
    char *result;
    BIO* bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    ASN1_UTCTIME_print(bio, tm);
    n = BIO_pending(bio);
    result = apr_pcalloc(p, n+1);
    n = BIO_read(bio, result, n);
    result[n] = NUL;
    BIO_free(bio);
    return result;
}

#define DIGIT2NUM(x) (((x)[0] - '0') * 10 + (x)[1] - '0')

/* Return a string giving the number of days remaining until 'tm', or
 * "0" if this can't be determined. */
static char *ssl_var_lookup_ssl_cert_remain(apr_pool_t *p, ASN1_UTCTIME *tm)
{
    apr_time_t then, now = apr_time_now();
    apr_time_exp_t exp = {0};
    long diff;

    /* Fail if the time isn't a valid ASN.1 UTCTIME; RFC3280 mandates
     * that the seconds digits are present even though ASN.1
     * doesn't. */
    if (tm->length < 11 || !ASN1_UTCTIME_check(tm)) {
        return apr_pstrdup(p, "0");
    }

    exp.tm_year = DIGIT2NUM(tm->data);
    exp.tm_mon = DIGIT2NUM(tm->data + 2) - 1;
    exp.tm_mday = DIGIT2NUM(tm->data + 4) + 1;
    exp.tm_hour = DIGIT2NUM(tm->data + 6);
    exp.tm_min = DIGIT2NUM(tm->data + 8);
    exp.tm_sec = DIGIT2NUM(tm->data + 10);

    if (exp.tm_year <= 50) exp.tm_year += 100;

    if (apr_time_exp_gmt_get(&then, &exp) != APR_SUCCESS) {
        return apr_pstrdup(p, "0");
    }

    diff = (long)((apr_time_sec(then) - apr_time_sec(now)) / (60*60*24));

    return diff > 0 ? apr_ltoa(p, diff) : apr_pstrdup(p, "0");
}

static char *ssl_var_lookup_ssl_cert_serial(apr_pool_t *p, X509 *xs)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    i2a_ASN1_INTEGER(bio, X509_get_serialNumber(xs));
    n = BIO_pending(bio);
    result = apr_pcalloc(p, n+1);
    n = BIO_read(bio, result, n);
    result[n] = NUL;
    BIO_free(bio);
    return result;
}

static char *ssl_var_lookup_ssl_cert_PEM(apr_pool_t *p, X509 *xs)
{
    char *result;
    BIO *bio;
    int n;

    if ((bio = BIO_new(BIO_s_mem())) == NULL)
        return NULL;
    PEM_write_bio_X509(bio, xs);
    n = BIO_pending(bio);
    result = apr_pcalloc(p, n+1);
    n = BIO_read(bio, result, n);
    result[n] = NUL;
    BIO_free(bio);
    return result;
}

/* Add each RDN in 'xn' to the table 't' where the NID is present in
 * 'nids', using key prefix 'pfx'.  */
static void extract_dn(apr_table_t *t, apr_hash_t *nids, const char *pfx, 
                       X509_NAME *xn, apr_pool_t *p)
{
    X509_NAME_ENTRY *xsne;
    apr_hash_t *count;
    int i, nid;
  
    /* Hash of (int) NID -> (int *) counter to count each time an RDN
     * with the given NID has been seen. */
    count = apr_hash_make(p);

    /* For each RDN... */
    for (i = 0; i < X509_NAME_entry_count(xn); i++) {
         const char *tag;

         xsne = X509_NAME_get_entry(xn, i);

         /* Retrieve the nid, and check whether this is one of the nids
          * which are to be extracted. */
         nid = OBJ_obj2nid((ASN1_OBJECT *)X509_NAME_ENTRY_get_object(xsne));

         tag = apr_hash_get(nids, &nid, sizeof nid);
         if (tag) {
             const unsigned char *data = X509_NAME_ENTRY_get_data_ptr(xsne);
             const char *key;
             int *dup;
             char *value;

             /* Check whether a variable with this nid was already
              * been used; if so, use the foo_N=bar syntax. */
             dup = apr_hash_get(count, &nid, sizeof nid);
             if (dup) {
                 key = apr_psprintf(p, "%s%s_%d", pfx, tag, ++(*dup));
             }
             else {
                 /* Otherwise, use the plain foo=bar syntax. */
                 dup = apr_pcalloc(p, sizeof *dup);
                 apr_hash_set(count, &nid, sizeof nid, dup);
                 key = apr_pstrcat(p, pfx, tag, NULL);
             }
             
             /* cast needed from 'unsigned char *' to 'char *' */
             value = apr_pstrmemdup(p, data,
                                    X509_NAME_ENTRY_get_data_len(xsne));
#if APR_CHARSET_EBCDIC
             ap_xlate_proto_from_ascii(value, X509_NAME_ENTRY_get_data_len(xsne));
#endif /* APR_CHARSET_EBCDIC */
             apr_table_setn(t, key, value);
         }
    }
}

void modssl_var_extract_dns(apr_table_t *t, SSL *ssl, apr_pool_t *p)
{
    apr_hash_t *nids;
    unsigned n;
    X509 *xs;

    /* Build up a hash table of (int *)NID->(char *)short-name for all
     * the tags which are to be extracted: */
    nids = apr_hash_make(p);
    for (n = 0; ssl_var_lookup_ssl_cert_dn_rec[n].name; n++) {
        if (ssl_var_lookup_ssl_cert_dn_rec[n].extract) {
            apr_hash_set(nids, &ssl_var_lookup_ssl_cert_dn_rec[n].nid,
                         sizeof(ssl_var_lookup_ssl_cert_dn_rec[0].nid),
                         ssl_var_lookup_ssl_cert_dn_rec[n].name);
        }
    }
    
    /* Extract the server cert DNS -- note that the refcount does NOT
     * increase: */
    xs = SSL_get_certificate(ssl);
    if (xs) {
        extract_dn(t, nids, "SSL_SERVER_S_DN_", X509_get_subject_name(xs), p);
        extract_dn(t, nids, "SSL_SERVER_I_DN_", X509_get_issuer_name(xs), p);
    }
    
    /* Extract the client cert DNs -- note that the refcount DOES
     * increase: */
    xs = SSL_get_peer_certificate(ssl);
    if (xs) {
        extract_dn(t, nids, "SSL_CLIENT_S_DN_", X509_get_subject_name(xs), p);
        extract_dn(t, nids, "SSL_CLIENT_I_DN_", X509_get_issuer_name(xs), p);
        X509_free(xs);
    }
}

/**
 * verify callback for peer cert verification for debugging purpose
 * @param cur_ok IN current ok state
 * @param ctx IN X509 store context
 */
int debug_verify_callback(int cur_ok, X509_STORE_CTX *ctx) {
  char buf[256];
  X509 *err_cert;
  int err, depth;

  err_cert = X509_STORE_CTX_get_current_cert(ctx);
  err = X509_STORE_CTX_get_error(ctx);
  depth = X509_STORE_CTX_get_error_depth(ctx);

  X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);
  fprintf(stdout, "\nverify error:num=%d:%s:depth=%d:%s",
	  err, X509_verify_cert_error_string(err), depth, buf);
  return cur_ok;
}

/**
 * verify callback to skip peer cert verification, want always the peer cert
 * @param cur_ok IN current ok state
 * @param ctx IN X509 store context
 */
int skip_verify_callback(int cur_ok, X509_STORE_CTX *ctx) {
  X509 *err_cert = X509_STORE_CTX_get_current_cert(ctx);
  if (!err_cert) {
    return 0;
  }
  else {
    return 1;
  }
}

#endif

#endif
