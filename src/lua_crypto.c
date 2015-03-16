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
 *
 * --------------------------------------------------------------------------- 
 * This work is derived from the famos luacrypto library:
 *
 * The LuaCrypto library is designed and implemented by Keith Howe. The 
 * implementation is not derived from licensed software.
 *
 * Copyright © 2006 Keith Howe.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to 
 * deal in the Software without restriction, including without limitation the 
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or 
 * sell copies of the Software, and to permit persons to whom the Software is 
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all 
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING 
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 * ---------------------------------------------------------------------------
 */

/**
 * @file
 *
 * @Author christian liesch <liesch@gmx.ch>
 *
 * Interface of the HTTP Test Tool lua crypto extention.
 */


/************************************************************************
 * Includes
 ***********************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/dh.h>

#define LUA_COMPAT_MODULE
#include "lua.h"
#include "lauxlib.h"
#if ! defined (LUA_VERSION_NUM) || LUA_VERSION_NUM < 501
#include "compat-5.1.h"
#endif

#include "lua_crypto.h"
#include "module.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/

#define LUACRYPTO_PREFIX "LuaCrypto: "
#define LUACRYPTO_CORE "crypto"
#define LUACRYPTO_EVP "crypto.evp"
#define LUACRYPTO_HMAC "crypto.hmac"
#define LUACRYPTO_RAND "crypto.rand"
#define LUACRYPTO_BASE64 "crypto.base64"
#define LUACRYPTO_X509 "crypto.x509"
#define LUACRYPTO_X509NAME "crypto.x509name"
#define LUACRYPTO_ASN1TIME "crypto.asn1time"
#define LUACRYPTO_DH "crypto.dh"


/************************************************************************
 * Forward declaration 
 ***********************************************************************/

int luaopen_crypto(lua_State *L);


/************************************************************************
 * Implementation 
 ***********************************************************************/

static int crypto_error(lua_State *L) {
  char buf[120];
  unsigned long e = ERR_get_error();
  ERR_load_crypto_strings();
  lua_pushnil(L);
  lua_pushstring(L, ERR_error_string(e, buf));
  return 2;
}

/**
 * EVP Object
 */
static EVP_MD_CTX *evp_pget(lua_State *L, int i) {
  if (luaL_checkudata(L, i, LUACRYPTO_EVP) == NULL) {
    luaL_argerror(L, 1, "invalid object type");
  }
  return lua_touserdata(L, i);
}

static EVP_MD_CTX *evp_pnew(lua_State *L) {
  EVP_MD_CTX *c = lua_newuserdata(L, sizeof(EVP_MD_CTX));
  luaL_getmetatable(L, LUACRYPTO_EVP);
  lua_setmetatable(L, -2);
  return c;
}

static int evp_fnew(lua_State *L) {
  EVP_MD_CTX *c = NULL;
  const char *s = luaL_checkstring(L, 1);
  const EVP_MD *type = EVP_get_digestbyname(s);
  
  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }
  
  c = evp_pnew(L);
  EVP_MD_CTX_init(c);
  EVP_DigestInit_ex(c, type, NULL);
  
  return 1;
}

static int evp_clone(lua_State *L) {
  EVP_MD_CTX *c = evp_pget(L, 1);
  EVP_MD_CTX *d = evp_pnew(L);
  EVP_MD_CTX_init(d);
  EVP_MD_CTX_copy_ex(d, c);
  return 1;
}

static int evp_reset(lua_State *L) {
  EVP_MD_CTX *c = evp_pget(L, 1);
  const EVP_MD *t = EVP_MD_CTX_md(c);
  EVP_MD_CTX_cleanup(c);
  EVP_MD_CTX_init(c);
  EVP_DigestInit_ex(c, t, NULL);
  return 0;
}

static int evp_update(lua_State *L) {
  EVP_MD_CTX *c = evp_pget(L, 1);
  const char *s = luaL_checkstring(L, 2);
  
  EVP_DigestUpdate(c, s, strlen(s));
  
  lua_settop(L, 1);
  return 1;
}

static int evp_digest(lua_State *L) {
  EVP_MD_CTX *c = evp_pget(L, 1);
  EVP_MD_CTX *d = NULL;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int written = 0;
  unsigned int i;
  char *hex;
  
  if (lua_isstring(L, 2)) {  
    const char *s = luaL_checkstring(L, 2);
    EVP_DigestUpdate(c, s, strlen(s));
  }
  
  d = EVP_MD_CTX_create();
  EVP_MD_CTX_copy_ex(d, c);
  EVP_DigestFinal_ex(d, digest, &written);
  EVP_MD_CTX_destroy(d);
  
  if (lua_toboolean(L, 3)) {
    lua_pushlstring(L, (char *)digest, written);
  }
  else {
    hex = calloc(sizeof(char), written*2 + 1);
    for (i = 0; i < written; i++)
      sprintf(hex + 2*i, "%02x", digest[i]);
    lua_pushlstring(L, hex, written*2);
    free(hex);
  }
  
  return 1;
}

static int evp_tostring(lua_State *L) {
  EVP_MD_CTX *c = evp_pget(L, 1);
  char s[64];
  sprintf(s, "%s %p", LUACRYPTO_EVP, (void *)c);
  lua_pushstring(L, s);
  return 1;
}

static int evp_gc(lua_State *L) {
  EVP_MD_CTX *c = evp_pget(L, 1);
  EVP_MD_CTX_cleanup(c);
  return 1;
}

static int evp_fdigest(lua_State *L) {
  EVP_MD_CTX *c = NULL;
  const char *type_name = luaL_checkstring(L, 1);
  const char *s = luaL_checkstring(L, 2);
  const EVP_MD *type = EVP_get_digestbyname(type_name);
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int written = 0;
  unsigned int i;
  char *hex;
  
  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }
  
  c = EVP_MD_CTX_create();
  EVP_DigestInit_ex(c, type, NULL);
  EVP_DigestUpdate(c, s, strlen(s));
  EVP_DigestFinal_ex(c, digest, &written);
  
  if (lua_toboolean(L, 3)) {
    lua_pushlstring(L, (char *)digest, written);
  }
  else {
    hex = calloc(sizeof(char), written*2 + 1);
    for (i = 0; i < written; i++) {
      sprintf(hex + 2*i, "%02x", digest[i]);
    }
    lua_pushlstring(L, hex, written*2);
    free(hex);
  }
  
  return 1;
}

/**
 * HMAC Object
 */
static HMAC_CTX *hmac_pget(lua_State *L, int i) {
 if (luaL_checkudata(L, i, LUACRYPTO_HMAC) == NULL) {
    luaL_argerror(L, 1, "invalid object type");
 }
 return lua_touserdata(L, i);
}

static HMAC_CTX *hmac_pnew(lua_State *L) {
  HMAC_CTX *c = lua_newuserdata(L, sizeof(HMAC_CTX));
  luaL_getmetatable(L, LUACRYPTO_HMAC);
  lua_setmetatable(L, -2);
  return c;
}

static int hmac_fnew(lua_State *L) {
  HMAC_CTX *c = hmac_pnew(L);
  const char *s = luaL_checkstring(L, 1);
  const char *k = luaL_checkstring(L, 2);
  const EVP_MD *type = EVP_get_digestbyname(s);

  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }

  HMAC_CTX_init(c);
  HMAC_Init_ex(c, k, strlen(k), type, NULL);

  return 1;
}

static int hmac_clone(lua_State *L) {
 HMAC_CTX *c = hmac_pget(L, 1);
 HMAC_CTX *d = hmac_pnew(L);
 *d = *c;
 return 1;
}

static int hmac_reset(lua_State *L) {
  HMAC_CTX *c = hmac_pget(L, 1);
  HMAC_Init_ex(c, NULL, 0, NULL, NULL);
  return 0;
}

static int hmac_update(lua_State *L) {
  HMAC_CTX *c = hmac_pget(L, 1);
  const char *s = luaL_checkstring(L, 2);

  HMAC_Update(c, (unsigned char *)s, strlen(s));

  lua_settop(L, 1);
  return 1;
}

static int hmac_digest(lua_State *L) {
  HMAC_CTX *c = hmac_pget(L, 1);
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int written = 0;
  unsigned int i;
  char *hex;

  if (lua_isstring(L, 2))
  {
    const char *s = luaL_checkstring(L, 2);
    HMAC_Update(c, (unsigned char *)s, strlen(s));
  }

  HMAC_Final(c, digest, &written);

  if (lua_toboolean(L, 3)) {
    lua_pushlstring(L, (char *)digest, written);
  }
  else {
    hex = calloc(sizeof(char), written*2 + 1);
    for (i = 0; i < written; i++) {
      sprintf(hex + 2*i, "%02x", digest[i]);
    }
    lua_pushlstring(L, hex, written*2);
    free(hex);
  }

  return 1;
}

static int hmac_tostring(lua_State *L) {
  HMAC_CTX *c = hmac_pget(L, 1);
  char s[64];
  sprintf(s, "%s %p", LUACRYPTO_HMAC, (void *)c);
  lua_pushstring(L, s);
  return 1;
}

static int hmac_gc(lua_State *L) {
  HMAC_CTX *c = hmac_pget(L, 1);
  HMAC_CTX_cleanup(c);
  return 1;
}

static int hmac_fdigest(lua_State *L) {
  HMAC_CTX c;
  unsigned char digest[EVP_MAX_MD_SIZE];
  unsigned int written = 0;
  unsigned int i;
  char *hex;
  const char *t = luaL_checkstring(L, 1);
  const char *s = luaL_checkstring(L, 2);
  const char *k = luaL_checkstring(L, 3);
  const EVP_MD *type = EVP_get_digestbyname(t);

  if (type == NULL) {
    luaL_argerror(L, 1, "invalid digest type");
    return 0;
  }

  HMAC_CTX_init(&c);
  HMAC_Init_ex(&c, k, strlen(k), type, NULL);
  HMAC_Update(&c, (unsigned char *)s, strlen(s));
  HMAC_Final(&c, digest, &written);

  if (lua_toboolean(L, 4)) {
    lua_pushlstring(L, (char *)digest, written);
  }
  else {
    hex = calloc(sizeof(char), written*2 + 1);
    for (i = 0; i < written; i++) {
      sprintf(hex + 2*i, "%02x", digest[i]);
    }
    lua_pushlstring(L, hex, written*2);
    free(hex);
  }

  return 1;
}

/**
 * Random Object
 */
static int rand_do_bytes(lua_State *L, int (*bytes)(unsigned char *buf, int len)) {
  size_t count = luaL_checkint(L, 1);
  unsigned char tmp[256], *buf = tmp;
  if (count > sizeof tmp) {
    buf = malloc(count);
  }
  if (!buf) {
    return luaL_error(L, "out of memory");
  }
  else if (!bytes(buf, count)) {
    return crypto_error(L);
  }
  lua_pushlstring(L, (char *)buf, count);
  if (buf != tmp) {
    free(buf);
  }
  return 1;
}

static int rand_bytes(lua_State *L) {
  return rand_do_bytes(L, RAND_bytes);
}

static int rand_pseudo_bytes(lua_State *L) {
  return rand_do_bytes(L, RAND_pseudo_bytes);
}

static int rand_add(lua_State *L) {
  size_t num;
  const void *buf = luaL_checklstring(L, 1, &num);
  double entropy = luaL_optnumber(L, 2, num);
  RAND_add(buf, num, entropy);
  return 0;
}

static int rand_status(lua_State *L) {
  lua_pushboolean(L, RAND_status());
  return 1;
}

enum { WRITE_FILE_COUNT = 1024 };
static int rand_load(lua_State *L) {
  const char *name = luaL_optstring(L, 1, 0);
  char tmp[256];
  int n;
  if (!name && !(name = RAND_file_name(tmp, sizeof tmp))) {
    return crypto_error(L);
  }
  n = RAND_load_file(name, WRITE_FILE_COUNT);
  if (n == 0) {
    return crypto_error(L);
  }
  lua_pushnumber(L, n);
  return 1;
}

static int rand_write(lua_State *L) {
  const char *name = luaL_optstring(L, 1, 0);
  char tmp[256];
  int n;
  if (!name && !(name = RAND_file_name(tmp, sizeof tmp))) {
    return crypto_error(L);
  }
  n = RAND_write_file(name);
  if (n == 0) {
    return crypto_error(L);
  }
  lua_pushnumber(L, n);
  return 1;
}

static int rand_cleanup(lua_State *L) {
  RAND_cleanup();
  return 0;
}

/**
 * Base64
 */
static int b64_encode(lua_State *L) {
  if (lua_isstring(L, -1)) {
    apr_pool_t *pool;
    apr_size_t len;
    apr_size_t b64len;
    char *base64;

    const char *buffer = lua_tolstring(L, -1, &len);

    HT_POOL_CREATE(&pool);
    b64len = apr_base64_encode_len(len);
    base64 = apr_pcalloc(pool, b64len + 1);
    apr_base64_encode(base64, buffer, len);

    lua_pushstring(L, base64);
    apr_pool_destroy(pool);
    return 1;
  }
  else {
    luaL_error(L, "Expect a string parameter");
    return 1;
  }
}

static int b64_decode(lua_State *L) {
  if (lua_isstring(L, -1)) {
    apr_pool_t *pool;
    apr_size_t len;
    unsigned char *plain;

    const char *buffer = lua_tolstring(L, -1, &len);

    HT_POOL_CREATE(&pool);

    len = apr_base64_decode_len(buffer);
    plain = apr_pcalloc(pool, len);
    apr_base64_decode_binary(plain, buffer);

    lua_pushlstring(L, (char *)plain, len);
    apr_pool_destroy(pool);
    return 1;
  }
  else {
    luaL_error(L, "Expect a string parameter");
    return 1;
  }
}

/**
 * X509 Object
 */
static X509 *x509_pget(lua_State *L, int i) {
  if (luaL_checkudata(L, i, LUACRYPTO_X509) == NULL) {
    luaL_argerror(L, 1, "invalid object type");
  }
  return lua_touserdata(L, i);
}

static int x509_fnew(lua_State *L) {
  apr_size_t len;
  const char *data = luaL_checklstring(L, 1, &len);
  X509 *cert;
  BIO *mem;

  if (data == NULL) {
    luaL_argerror(L, 1, "PEM cert to load");
    return 0;
  }
  
  mem = BIO_new_mem_buf((void *)data, len);
  cert = PEM_read_bio_X509(mem, NULL, NULL, NULL);
  
  lua_pushlightuserdata(L, cert);
  luaL_getmetatable(L, LUACRYPTO_X509);
  lua_setmetatable(L, -2);

  return 1;
}

static int x509_fload(lua_State *L) {
  const char *filename = luaL_checkstring(L, 1);
  X509 *cert;
  BIO *file;

  if (filename == NULL) {
    luaL_argerror(L, 1, "path to x509 pem formated cert missing");
    return 0;
  }
 
  file = BIO_new_file(filename, "r");
  cert = PEM_read_bio_X509(file, NULL, NULL, NULL);
  
  lua_pushlightuserdata(L, cert);
  luaL_getmetatable(L, LUACRYPTO_X509);
  lua_setmetatable(L, -2);

  return 1;
}

static int x509_clone(lua_State *L) {
  X509 *cert = x509_pget(L, 1);
  X509 *copy = X509_dup(cert);

  lua_pushlightuserdata(L, copy);
  luaL_getmetatable(L, LUACRYPTO_X509);
  lua_setmetatable(L, -2);
  return 1;
}

static int x509_get_subject_name(lua_State *L) {
  X509 *cert = x509_pget(L, 1);
  X509_NAME *name = X509_get_subject_name(cert);

  lua_pushlightuserdata(L, name);
  luaL_getmetatable(L, LUACRYPTO_X509NAME);
  lua_setmetatable(L, -2);
  return 1;
}

static int x509_get_issuer_name(lua_State *L) {
  X509 *cert = x509_pget(L, 1);
  X509_NAME *name = X509_get_issuer_name(cert);

  lua_pushlightuserdata(L, name);
  luaL_getmetatable(L, LUACRYPTO_X509NAME);
  lua_setmetatable(L, -2);
  return 1;
}

static int x509_get_not_before(lua_State *L) {
  X509 *cert = x509_pget(L, 1);
  ASN1_TIME *time = X509_get_notBefore(cert);

  lua_pushlightuserdata(L, time);
  luaL_getmetatable(L, LUACRYPTO_ASN1TIME);
  lua_setmetatable(L, -2);
  return 1;
}

static int x509_get_not_after(lua_State *L) {
  X509 *cert = x509_pget(L, 1);
  ASN1_TIME *time = X509_get_notAfter(cert);

  lua_pushlightuserdata(L, time);
  luaL_getmetatable(L, LUACRYPTO_ASN1TIME);
  lua_setmetatable(L, -2);
  return 1;
}

static int x509_tostring(lua_State *L) {
  apr_pool_t *pool;
  X509 *cert = x509_pget(L, 1);
  char *s;
  HT_POOL_CREATE(&pool);
  s = apr_psprintf(pool, "X509 cert %p", cert);
  lua_pushstring(L, s);
  apr_pool_destroy(pool);
  return 1;
}

static int x509_gc(lua_State *L) {
  X509 *c = x509_pget(L, 1);
  X509_free(c);
  return 1;
}

/**
 * X509_NAME Object
 */
static X509_NAME *x509_name_pget(lua_State *L, int i) {
  if (luaL_checkudata(L, i, LUACRYPTO_X509NAME) == NULL) {
    luaL_argerror(L, 1, "invalid object type");
  }
  return lua_touserdata(L, i);
}

static int x509_name_clone(lua_State *L) {
  X509_NAME *name = x509_name_pget(L, 1);
  X509_NAME *copy = X509_NAME_dup(name);

  lua_pushlightuserdata(L, copy);
  luaL_getmetatable(L, LUACRYPTO_X509NAME);
  lua_setmetatable(L, -2);
  return 1;
}

static int x509_name_tostring(lua_State *L) {
  char *s;
  X509_NAME *name = x509_name_pget(L, 1);
  s = X509_NAME_oneline(name, NULL, 0);
  lua_pushstring(L, s);
  OPENSSL_free(s);
  return 1;
}

static int x509_name_toasn1(lua_State *L) {
  unsigned char *s = NULL;
  apr_size_t len;
  X509_NAME *name = x509_name_pget(L, 1);
  len = i2d_X509_NAME(name, &s);
  lua_pushlstring(L, (char *)s, len);
  OPENSSL_free(s);
  return 1;
}

static int x509_name_gc(lua_State *L) {
  X509_NAME *name = x509_name_pget(L, 1);
  X509_NAME_free(name);
  return 1;
}

/**
 * ASN1_TIME Object
 */
static ASN1_TIME *asn1_time_pget(lua_State *L, int i) {
  if (luaL_checkudata(L, i, LUACRYPTO_ASN1TIME) == NULL) {
    luaL_argerror(L, 1, "invalid object type");
  }
  return lua_touserdata(L, i);
}

static int asn1_time_fnew(lua_State *L) {
  ASN1_TIME *asn1time = M_ASN1_TIME_new(); 
  time_t t = time(NULL);
  ASN1_TIME_set(asn1time, t);
  lua_pushlightuserdata(L, asn1time);
  luaL_getmetatable(L, LUACRYPTO_ASN1TIME);
  lua_setmetatable(L, -2);

  return 1;
}

static int asn1_time_clone(lua_State *L) {
  ASN1_TIME *time = asn1_time_pget(L, 1);
  ASN1_TIME *copy = M_ASN1_TIME_dup(time);

  lua_pushlightuserdata(L, copy);
  luaL_getmetatable(L, LUACRYPTO_ASN1TIME);
  lua_setmetatable(L, -2);
  return 1;
}

static int asn1_time_tostring(lua_State *L) {
  char s[1024];
  BIO *mem;
  ASN1_TIME *time = asn1_time_pget(L, 1);
  mem = BIO_new_mem_buf((void *)s, 1024);
  ASN1_TIME_print(mem, time);
  lua_pushstring(L, s);
  return 1;
}

static int asn1_time_toasn1(lua_State *L) {
  unsigned char *s = NULL;
  apr_size_t len;
  ASN1_TIME *time = asn1_time_pget(L, 1);
  len = i2d_ASN1_TIME(time, &s);
  lua_pushlstring(L, (char *)s, len);
  OPENSSL_free(s);
  return 1;
}

static int asn1_time_gc(lua_State *L) {
  ASN1_TIME *time = asn1_time_pget(L, 1);
  M_ASN1_TIME_free(time);
  return 1;
}

/**
 * DH object
 */

static int dh_cb(int p, int n, BN_GENCB *cb) {
  char c='*';

  switch (p) {
  case 0:
    c='.';
    break;
  case 1:
    c='+';
    break;
  case 2:
    c='*';
    break;
  case 3:
    c='\n';
    break;
  }
  BIO_write(cb->arg,&c,1);
  (void)BIO_flush(cb->arg);
  return 1;
}

static DH *dh_pget(lua_State *L, int i) {
  if (luaL_checkudata(L, i, LUACRYPTO_DH) == NULL) {
    luaL_argerror(L, 1, "invalid object type");
  }
  return lua_touserdata(L, i);
}

static int dh_fnew(lua_State *L) {
  int generator = luaL_checknumber(L, 1);
  int num = luaL_checknumber(L, 2);
  DH *dh = DH_new();
  BIO *bio_err;
  BN_GENCB cb;
  if ((bio_err = BIO_new(BIO_s_file())) != NULL) {
    BIO_set_fp(bio_err,stderr,BIO_NOCLOSE|BIO_FP_TEXT);
  }
  BN_GENCB_set(&cb, dh_cb, bio_err);
  if (!DH_generate_parameters_ex(dh, num, generator, &cb)) {
    luaL_argerror(L, 1, "could not generate DH paramters");
    return 1;
  }
  DH_generate_key(dh);
  lua_pushlightuserdata(L, dh);
  luaL_getmetatable(L, LUACRYPTO_DH);
  lua_setmetatable(L, -2);

  return 1;
}

static int dh_clone(lua_State *L) {
  DH *dh = dh_pget(L, 1);
  DH *copy = DHparams_dup(dh);

  lua_pushlightuserdata(L, copy);
  luaL_getmetatable(L, LUACRYPTO_DH);
  lua_setmetatable(L, -2);
  return 1;
}

static int dh_tostring(lua_State *L) {
  char *s;
  apr_pool_t *pool;
  DH *dh = dh_pget(L, 1);
  HT_POOL_CREATE(&pool);
  s = apr_psprintf(pool, "DH %p", dh);
  lua_pushstring(L, s);
  apr_pool_destroy(pool);
  return 1;
}

static int dh_get_prime(lua_State *L) {
  apr_size_t len;
  unsigned char *s;
  apr_pool_t *pool;
  DH *dh = dh_pget(L, 1);
  HT_POOL_CREATE(&pool);
  s = apr_pcalloc(pool, BN_num_bytes(dh->p)); 
  len = BN_bn2bin(dh->p, s);
  lua_pushlstring(L, (char *)s, len);
  apr_pool_destroy(pool);
  return 1;
}

static int dh_get_priv_key(lua_State *L) {
  apr_size_t len;
  unsigned char *s;
  apr_pool_t *pool;
  DH *dh = dh_pget(L, 1);
  HT_POOL_CREATE(&pool);
  s = apr_pcalloc(pool, BN_num_bytes(dh->priv_key)); 
  len = BN_bn2bin(dh->priv_key, s);
  lua_pushlstring(L, (char *)s, len);
  apr_pool_destroy(pool);
  return 1;
}

static int dh_get_pub_key(lua_State *L) {
  apr_size_t len;
  unsigned char *s;
  apr_pool_t *pool;
  DH *dh = dh_pget(L, 1);
  HT_POOL_CREATE(&pool);
  s = apr_pcalloc(pool, BN_num_bytes(dh->pub_key)); 
  len = BN_bn2bin(dh->pub_key, s);
  lua_pushlstring(L, (char *)s, len);
  apr_pool_destroy(pool);
  return 1;
}

static int dh_gc(lua_State *L) {
  DH *dh = dh_pget(L, 1);
  DH_free(dh);
  return 1;
}

/**
 * Create a metatable and leave it on top of the stack.
 */
int luacrypto_createmeta (lua_State *L, const char *name, const luaL_Reg *methods) {
  if (!luaL_newmetatable (L, name)) {
    return 0;
  }
  
  /* define methods */
  luaL_openlib (L, NULL, methods, 0);
  
  /* define metamethods */
  lua_pushliteral (L, "__index");
  lua_pushvalue (L, -2);
  lua_settable (L, -3);

  lua_pushliteral (L, "__metatable");
  lua_pushliteral (L, LUACRYPTO_PREFIX"you're not allowed to get this metatable");
  lua_settable (L, -3);

  return 1;
}

/**
 * Create metatables for each class of object.
 */
static void create_metatables (lua_State *L) {
  struct luaL_Reg evp_functions[] = {
    { "digest", evp_fdigest },
    { "new", evp_fnew },
    {NULL, NULL},
  };

  struct luaL_Reg evp_methods[] = {
    { "__tostring", evp_tostring },
    { "__gc", evp_gc },
    { "clone", evp_clone },
    { "digest", evp_digest },
    { "reset", evp_reset },
    { "tostring", evp_tostring },
    { "update",	evp_update },
    {NULL, NULL},
  };

  struct luaL_Reg hmac_functions[] = {
    { "digest", hmac_fdigest },
    { "new", hmac_fnew },
    { NULL, NULL }
  };

  struct luaL_Reg hmac_methods[] = {
    { "__tostring", hmac_tostring },
    { "__gc", hmac_gc },
    { "clone", hmac_clone },
    { "digest", hmac_digest },
    { "reset", hmac_reset },
    { "tostring", hmac_tostring },
    { "update", hmac_update },
    { NULL, NULL }
  };
  struct luaL_Reg rand_functions[] = {
    { "bytes", rand_bytes },
    { "pseudo_bytes", rand_pseudo_bytes },
    { "add", rand_add },
    { "seed", rand_add },
    { "status", rand_status },
    { "load", rand_load },
    { "write", rand_write },
    { "cleanup", rand_cleanup },
    { NULL, NULL }
  };
  struct luaL_Reg b64_functions[] = {
    { "encode", b64_encode },
    { "decode", b64_decode },
    {NULL, NULL},
  };

  struct luaL_Reg x509_functions[] = {
    { "new", x509_fnew },
    { "load", x509_fload },
    {NULL, NULL},
  };

  struct luaL_Reg x509_methods[] = {
    { "__tostring", x509_tostring },
    { "__gc", x509_gc },
    { "clone", x509_clone },
    { "tostring", x509_tostring },
    { "get_subject_name", x509_get_subject_name }, 
    { "get_issuer_name", x509_get_issuer_name }, 
    { "get_not_before", x509_get_not_before }, 
    { "get_not_after", x509_get_not_after }, 
    {NULL, NULL},
  };

  struct luaL_Reg x509_name_methods[] = {
    { "__tostring", x509_name_tostring },
    { "__gc", x509_name_gc },
    { "clone", x509_name_clone },
    { "tostring", x509_name_tostring },
    { "toasn1", x509_name_toasn1 },
    {NULL, NULL},
  };

  struct luaL_Reg asn1_time_functions[] = {
    { "new", asn1_time_fnew },
    {NULL, NULL},
  };

  struct luaL_Reg asn1_time_methods[] = {
    { "__tostring", asn1_time_tostring },
    { "__gc", asn1_time_gc },
    { "clone", asn1_time_clone },
    { "tostring", asn1_time_tostring },
    { "toasn1", asn1_time_toasn1 },
    {NULL, NULL},
  };

  struct luaL_Reg dh_functions[] = {
    { "new", dh_fnew },
    {NULL, NULL},
  };

  struct luaL_Reg dh_methods[] = {
    { "__tostring", dh_tostring },
    { "__gc", dh_gc },
    { "clone", dh_clone },
    { "tostring", dh_tostring },
    { "get_prime", dh_get_prime },
    { "get_priv_key", dh_get_priv_key },
    { "get_pub_key", dh_get_pub_key },
    {NULL, NULL},
  };

  luaL_openlib (L, LUACRYPTO_EVP, evp_functions, 0);
  luacrypto_createmeta(L, LUACRYPTO_EVP, evp_methods);
  luaL_openlib (L, LUACRYPTO_HMAC, hmac_functions, 0);
  luacrypto_createmeta(L, LUACRYPTO_HMAC, hmac_methods);
  luaL_openlib (L, LUACRYPTO_RAND, rand_functions, 0);
  luaL_openlib (L, LUACRYPTO_BASE64, b64_functions, 0);
  luaL_openlib (L, LUACRYPTO_X509, x509_functions, 0);
  luacrypto_createmeta(L, LUACRYPTO_X509, x509_methods);
  luacrypto_createmeta(L, LUACRYPTO_X509NAME, x509_name_methods);
  luaL_openlib (L, LUACRYPTO_ASN1TIME, asn1_time_functions, 0);
  luacrypto_createmeta(L, LUACRYPTO_ASN1TIME, asn1_time_methods);
  luaL_openlib (L, LUACRYPTO_DH, dh_functions, 0);
  luacrypto_createmeta(L, LUACRYPTO_DH, dh_methods);
  lua_pop (L, 3);
}

/**
 * Creates the metatables for the objects and registers the
 * driver open method.
 * @param L IN Lua hook
 * @return 1
 */
int luaopen_crypto(lua_State *L) {
  struct luaL_Reg core[] = {
    {NULL, NULL},
  };
  OpenSSL_add_all_digests();
  create_metatables (L);
  luaL_openlib (L, LUACRYPTO_CORE, core, 0);
  return 1;
}
