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
 * Implementation of the HTTP Test NTLM.
 * based on this documentation: http://davenport.sourceforge.net/ntlm.html
 */

/* affects include files on Solaris */
#define BSD_COMP

/************************************************************************
 * Includes
 ***********************************************************************/
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if HAVE_STDLIB_H 
#include <stdlib.h>
#endif

#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/md4.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <apr.h>
#include <apr_strings.h>
#include <apr_getopt.h>
#include <apr_general.h>
#include <apr_lib.h>
#include <apr_portable.h>
#include <apr_base64.h>
#include <apr_env.h>
#include <apr_support.h>

#include "defines.h"
#include "util.h"

/************************************************************************
 * Defines 
 ***********************************************************************/
#define HTNTLM_NEGOTIATE_UNICODE               0x00000001 
#define HTNTLM_NEGOTIATE_OEM                   0x00000002
#define HTNTLM_REQUEST_TARGET                  0x00000004 
/* unknown 0x00000008 */
#define HTNTLM_NEGOTIATE_SIGN                  0x00000010
#define HTNTLM_NEGOTIATE_SEAL                  0x00000020 
#define HTNTLM_NEGOTIATE_DATAGRAM_STYLE        0x00000040 
#define HTNTLM_NEGOTIATE_LM_KEY                0x00000080 
#define HTNTLM_NEGOTIATE_NETWARE               0x00000100 
#define HTNTLM_NEGOTIATE_NTLM_KEY              0x00000200 
/* unknown 0x00000400 */
#define HTNTLM_NEGOTIATE_ANONYMOUS             0x00000800 
#define HTNTLM_NEGOTIATE_DOMAIN_SUPPLIED       0x00001000 
#define HTNTLM_NEGOTIATE_WORKSTATION_SUPPLIED  0x00002000 
#define HTNTLM_NEGOTIATE_LOCAL_CALL            0x00004000 
#define HTNTLM_NEGOTIATE_ALWAYS_SIGN           0x00008000 
#define HTNTLM_TARGET_TYPE_DOMAIN              0x00010000 
#define HTNTLM_TARGET_TYPE_SERVER              0x00020000 
#define HTNTLM_TARGET_TYPE_SHARE               0x00040000 
#define HTNTLM_NEGOTIATE_NTLM2_KEY             0x00080000 
#define HTNTLM_REQUEST_INIT_RESPONSE           0x00100000 
#define HTNTLM_REQUEST_ACCEPT_RESPONSE         0x00200000 
#define HTNTLM_REQUEST_NONNT_SESSION_KEY       0x00400000 
#define HTNTLM_NEGOTIATE_TARGET_INFO           0x00800000 
/* unknown 0x01000000 */
/* unknown 0x02000000 */
/* unknown 0x04000000 */
/* unknown 0x08000000 */
/* unknown 0x10000000 */
#define HTNTLM_NEGOTIATE_128                   0x20000000 
#define HTNTLM_NEGOTIATE_KEY_EXCHANGE          0x40000000
#define HTNTLM_NEGOTIATE_56                    0x80000000 

#define HTNTLM_STR_NEG_UNICODE               "neg-unicode" 
#define HTNTLM_STR_NEG_OEM                   "neg-oem"
#define HTNTLM_STR_REQ_TARGET                "req-target"
#define HTNTLM_STR_NEG_SIGN                  "neg-sign"
#define HTNTLM_STR_NEG_SEAL                  "neg-seal"
#define HTNTLM_STR_NEG_DATAGRAM_STYLE        "neg-datagram-style"
#define HTNTLM_STR_NEG_LM_KEY                "neg-lm-key"
#define HTNTLM_STR_NEG_NETWARE               "neg-netware"
#define HTNTLM_STR_NEG_NTLM_KEY              "neg-ntlm-key"
#define HTNTLM_STR_NEG_ANONYMOUS             "neg-anonymous"
#define HTNTLM_STR_NEG_DOMAIN_SUPP           "neg-domain-supp"
#define HTNTLM_STR_NEG_WORKSTATION_SUPP      "neg-workstation-supp"
#define HTNTLM_STR_NEG_LOCAL_CALL            "neg-local-call"
#define HTNTLM_STR_NEG_ALWAYS_SIGN           "neg-always_sign"
#define HTNTLM_STR_TARGET_TYPE_DOMAIN        "target-type-domain"
#define HTNTLM_STR_TARGET_TYPE_SERVER        "target-type-server"
#define HTNTLM_STR_TARGET_TYPE_SHARE         "target-type-share"
#define HTNTLM_STR_NEG_NTLM2_KEY             "neg-ntlm2-key"
#define HTNTLM_STR_REQ_INIT_RES              "req-init-res"
#define HTNTLM_STR_REQ_ACCEPT_RES            "req-accept-res"
#define HTNTLM_STR_REQ_NONNT_SESSION_KEY     "req-nonnt-session-key"
#define HTNTLM_STR_NEG_TARGET_INFO           "neg-target-info"
#define HTNTLM_STR_NEG_128                   "neg-128"
#define HTNTLM_STR_NEG_KEY_EXCHANGE          "neg-key-exchange"
#define HTNTLM_STR_NEG_56                    "neg-56"

#define HTNTLM_SUBBLK_SERVER_NAME 1
#define HTNTLM_SUBBLK_DOMAIN_NAME 2
#define HTNTLM_SUBBLK_DNS_SERVER 3
#define HTNTLM_SUBBLK_DNS_DOMAIN 4

#define HTNTLM_RESP_NONE 0x00
#define HTNTLM_RESP_LM 0x01
#define HTNTLM_RESP_NTLM 0x02
#define HTNTLM_RESP_LM2 0x04
#define HTNTLM_RESP_NTLM2 0x08
#define HTNTLM_RESP_NTLM2_SESS 0x10 

#define HTNTLM_STR_RESP_LM         "lm" 
#define HTNTLM_STR_RESP_NTLM       "ntlm" 
#define HTNTLM_STR_RESP_LM2        "lm2" 
#define HTNTLM_STR_RESP_NTLM2      "ntlm2" 
#define HTNTLM_STR_RESP_NTLM2_SESS "ntlm2-session" 

#ifdef WIN32
#define FMT_LLX "%I64x"
#else
#define FMT_LLX "%"APR_UINT64_T_HEX_FMT
#endif

/************************************************************************
 * Structurs
 ***********************************************************************/
typedef struct htntlm_flags_map_s {
  int flag;
  char *name;
} htntlm_flags_map_t;

typedef struct htntlm_os_s {
  int major;
  int minor; 
  int maint;
} htntlm_os_t;

typedef struct htntlm_hash_s {
  unsigned char *hash;
  uint16_t len;
} htntlm_hash_t;

typedef struct htntlm_s {
  apr_pool_t *pool;
#define HTNTLM_FUNC_FLAGS_NONE 0
#define HTNTLM_FUNC_FLAGS_UNICODE 1
#define HTNTLM_FUNC_FLAGS_DEBUG 2
  int func_flags;
  apr_file_t *out;
  char *exception;
  uint32_t type;
  const char *domain;
  const char *workstation;
  const char *server;
  htntlm_os_t os;
  const char *target;
  const char *dns_domain;
  const char *dns_server;
  const char *user;
  const char *password;
  uint64_t challenge;
  uint64_t client_challenge;
  uint64_t context;
  const char *session_key;
  htntlm_hash_t lm;
  htntlm_hash_t ntlm;
  const char *target_info;
  uint32_t flags;
  uint32_t resp;
} htntlm_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
char *lm_magic = "KGS!@#$%";

htntlm_flags_map_t flags_map[] = {
  { HTNTLM_NEGOTIATE_UNICODE, HTNTLM_STR_NEG_UNICODE },
  { HTNTLM_NEGOTIATE_OEM, HTNTLM_STR_NEG_OEM },
  { HTNTLM_REQUEST_TARGET, HTNTLM_STR_REQ_TARGET },
  { HTNTLM_NEGOTIATE_SIGN, HTNTLM_STR_NEG_SIGN },
  { HTNTLM_NEGOTIATE_SEAL, HTNTLM_STR_NEG_SEAL },
  { HTNTLM_NEGOTIATE_DATAGRAM_STYLE, HTNTLM_STR_NEG_DATAGRAM_STYLE },
  { HTNTLM_NEGOTIATE_LM_KEY, HTNTLM_STR_NEG_LM_KEY },
  { HTNTLM_NEGOTIATE_NETWARE, HTNTLM_STR_NEG_NETWARE },
  { HTNTLM_NEGOTIATE_NTLM_KEY, HTNTLM_STR_NEG_NTLM_KEY },
  { HTNTLM_NEGOTIATE_ANONYMOUS, HTNTLM_STR_NEG_ANONYMOUS },
  { HTNTLM_NEGOTIATE_DOMAIN_SUPPLIED, HTNTLM_STR_NEG_DOMAIN_SUPP },
  { HTNTLM_NEGOTIATE_WORKSTATION_SUPPLIED, HTNTLM_STR_NEG_WORKSTATION_SUPP },
  { HTNTLM_NEGOTIATE_LOCAL_CALL, HTNTLM_STR_NEG_LOCAL_CALL },
  { HTNTLM_NEGOTIATE_ALWAYS_SIGN, HTNTLM_STR_NEG_ALWAYS_SIGN },
  { HTNTLM_TARGET_TYPE_DOMAIN, HTNTLM_STR_TARGET_TYPE_DOMAIN },
  { HTNTLM_TARGET_TYPE_SERVER, HTNTLM_STR_TARGET_TYPE_SERVER },
  { HTNTLM_TARGET_TYPE_SHARE, HTNTLM_STR_TARGET_TYPE_SHARE },
  { HTNTLM_NEGOTIATE_NTLM2_KEY, HTNTLM_STR_NEG_NTLM2_KEY },
  { HTNTLM_REQUEST_INIT_RESPONSE, HTNTLM_STR_REQ_INIT_RES },
  { HTNTLM_REQUEST_ACCEPT_RESPONSE, HTNTLM_STR_REQ_ACCEPT_RES },
  { HTNTLM_REQUEST_NONNT_SESSION_KEY, HTNTLM_STR_REQ_NONNT_SESSION_KEY },
  { HTNTLM_NEGOTIATE_TARGET_INFO, HTNTLM_STR_NEG_TARGET_INFO },
  { HTNTLM_NEGOTIATE_128, HTNTLM_STR_NEG_128 },
  { HTNTLM_NEGOTIATE_KEY_EXCHANGE, HTNTLM_STR_NEG_KEY_EXCHANGE },
  { HTNTLM_NEGOTIATE_56, HTNTLM_STR_NEG_56 },
  { 0, NULL }
};

htntlm_flags_map_t resp_flags_map[] = {
  { HTNTLM_RESP_LM, HTNTLM_STR_RESP_LM },
  { HTNTLM_RESP_NTLM, HTNTLM_STR_RESP_NTLM },
  { HTNTLM_RESP_LM2, HTNTLM_STR_RESP_LM2 },
  { HTNTLM_RESP_NTLM2, HTNTLM_STR_RESP_NTLM2 },
  { HTNTLM_RESP_NTLM2_SESS, HTNTLM_STR_RESP_NTLM2_SESS },
  { 0, NULL }
};

apr_getopt_option_t options[] = {
  { "version", 'v', 0, "Print version number and exit" },
  { "help", 'h', 0, "Display usage information (this message)" },
  { "read", 'r', 1, "read a NTLM base64 encoded message" },
  { "write", 'w', 0, "write a NTLM base64 encoded message" },
  { "info", 'i', 0, "print in a readable manner" },
  { "debug", 'd', 0, "print debug information" },
  { "type", 't', 1, "NTLM message type 1, 2 or 3" },
  { "domain", 'D', 1, "Domain name" },
  { "workstation", 'W', 1, "Workstation name" },
  { "server", 'E', 1, "Workstation name" },
  { "os-version", 'O', 1, "OS Version major.minor.build" },
  { "target", 'T', 1, "Target name" },
  { "dns-domain", 'N', 1, "DNS domain name" },
  { "dns-server", 'S', 1, "DNS server name" },
  { "target-info", 'a', 1, "Target info as provided in NTLM type 2 message base64 encoded, need for NTLMv2" },
  { "user", 'U', 1, "User name" },
  { "password", 'P', 1, "password" },
  { "challenge", 'C', 1, "Challenge in hex notation" },
  { "client-challenge", 'c', 1, "Client challenge in hex notation, default is a random" },
  { "context", 'X', 1, "Context in hex notation" },
  { "session-key", 'K', 1, "Session Key" },
  { "response", 'R', 1, "response type space separated: lm ntlm lm2 ntlm2 ntlm2-session" },
  { "unicode", 'u', 0, "transmit user, workstation, ... as unicode strings" },
  { "flags", 'f', 1, "Space separated NTLM flags\n"
    HTNTLM_STR_NEG_UNICODE":\n"
    "  Indicates that Unicode strings are\n"
    "  supported for use in security buffer\n"
    "  data.\n"
    HTNTLM_STR_NEG_OEM":\n"
    "  Indicates that OEM strings are supported\n"
    "  for use in security buffer data.\n"
    HTNTLM_STR_REQ_TARGET":\n"
    "  Requests that the server's authentication\n"
    "  realm be included in the Type 2 message.\n"
    HTNTLM_STR_NEG_SIGN":\n"
    "  Specifies that authenticated communication\n"
    "  between the client and server should carry\n"
    "  a digital signature (message integrity).\n"
    HTNTLM_STR_NEG_SEAL":\n"
    "  Specifies that authenticated communication\n"
    "  between the client and server should be\n"
    "  encrypted (message confidentiality).\n" 
    HTNTLM_STR_NEG_DATAGRAM_STYLE":\n"
    "  Indicates that datagram authentication is\n"
    "  being used.\n"
    HTNTLM_STR_NEG_LM_KEY":\n"
    "  Indicates that the Lan Manager Session Key\n"
    "  should be used for signing and sealing\n"
    "  authenticated communications.\n"
    HTNTLM_STR_NEG_NETWARE":\n"
    "  This flag's usage has not been identified.\n"
    HTNTLM_STR_NEG_NTLM_KEY":\n"
    "  Indicates that NTLM authentication is\n"
    "  being used.\n"
    HTNTLM_STR_NEG_ANONYMOUS":\n"
    "  Sent by the client in the Type 3 message\n"
    "  to indicate that an anonymous context has\n"
    "  been established. This also affects the\n"
    "  response fields.\n"
    HTNTLM_STR_NEG_DOMAIN_SUPP":\n"
    "  Sent by the client in the Type 1 message\n"
    "  to indicate that the name of the domain in\n"
    "  which the client workstation has\n"
    "  membership is included in the message.\n"
    "  This is used by the server to determine\n"
    "  whether the client is eligible for local\n"
    "  authentication.\n"
    HTNTLM_STR_NEG_WORKSTATION_SUPP":\n"
    "  Sent by the client in the Type 1 message\n"
    "  to indicate that the client workstation's\n"
    "  name is included in the message. This is\n"
    "  used by the server to determine whether\n"
    "  the client is eligible for local\n"
    "  authentication.\n"
    HTNTLM_STR_NEG_LOCAL_CALL":\n"
    "  Sent by the server to indicate that the\n"
    "  server and client are on the same machine.\n"
    "  Implies that the client may use the\n"
    "  established local credentials for\n"
    "  authentication instead of calculating a\n"
    "  response to the challenge.\n"
    HTNTLM_STR_NEG_ALWAYS_SIGN":\n"
    "  Indicates that authenticated\n"
    "  communication between the client and\n"
    "  server should be signed with a \"dummy\"\n"
    "  signature. \n"
    HTNTLM_STR_TARGET_TYPE_DOMAIN":\n"
    "  Sent by the server in the Type 2 message\n"
    "  to indicate that the target authentication\n"
    "  realm is a domain. \n"
    HTNTLM_STR_TARGET_TYPE_SERVER":\n"
    "  Sent by the server in the Type 2 message\n"
    "  to indicate that the target authentication\n"
    "  realm is a server. \n"
    HTNTLM_STR_TARGET_TYPE_SHARE":\n"
    "  Sent by the server in the Type 2 message\n"
    "  to indicate that the target\n"
    "  authentication realm is a share.\n"
    "  Presumably, this is for share-level\n"
    "  authentication. Usage is unclear.\n"
    HTNTLM_STR_NEG_NTLM2_KEY":\n"
    "  Indicates that the NTLM2 signing and\n"
    "  sealing scheme should be used for\n"
    "  protecting authenticated communications.\n"
    "  Note that this refers to a particular\n"
    "  session security scheme, and is not\n"
    "  related to the use of NTLMv2\n"
    "  authentication. This flag can, however,\n"
    "  have an effect on the response\n"
    "  calculations\n"
    HTNTLM_STR_REQ_INIT_RES":\n"
    "  This flag's usage has not been identified\n"
    HTNTLM_STR_REQ_ACCEPT_RES":\n"
    "  This flag's usage has not been identified\n"
    HTNTLM_STR_REQ_NONNT_SESSION_KEY":\n"
    "  This flag's usage has not been identified\n"
    HTNTLM_STR_NEG_TARGET_INFO":\n"
    "  Sent by the server in the Type 2 message\n"
    "  to indicate that it is including a Target\n"
    "  Information block in the message. The\n"
    "  Target Information block is used in the\n"
    "  calculation of the NTLMv2 response.\n"
    HTNTLM_STR_NEG_128":\n"
    "  Indicates that 128-bit encryption is\n"
    "  supported.\n"
    HTNTLM_STR_NEG_KEY_EXCHANGE":\n"
    "  Indicates that the client will provide an\n"
    "  encrypted master key in the\n"
    "  \"Session Key\" field of the Type 3\n"
    "  message.\n"
    HTNTLM_STR_NEG_56":\n"
    "  Indicates that 56-bit encryption is\n"
    "  supported.\n"
  },
  { NULL, 0, 0, NULL }
};

/************************************************************************
 * Private 
 ***********************************************************************/

/**
 * Dump memory
 *
 * @param hook IN htntlm hook
 * @param mem IN memory to dump
 * @param len IN no bytes to dump
 */
void dump_mem(htntlm_t *hook, const unsigned char *mem, apr_size_t len) {
  int i;

  for (i = 0; i < len; i++) {
    apr_file_printf(hook->out, "%02x", mem[i]);
  }
}

/**
 * Copy src as a unicode string to dst
 *
 * @param pool IN pool
 * @param dst OUT unicode string
 * @param src IN null terminated string
 *
 * @return len of dst without null termination
 *
 * @note: do also null terminate
 */
static apr_size_t to_unicode(apr_pool_t *pool, char **dst, const char *src) {
  apr_size_t len;
  int i;

  if (!src) {
    src = apr_pstrdup(pool, "");
  }

  len = strlen(src);

  if (dst) {
    (*dst) = apr_pcalloc(pool, 2 * len + 2);
    for (i = 0; i < len; i++) {
      (*dst)[2 * i] = src[i];
      (*dst)[2 * i + 1] = 0;
    }
  }

  return 2 * len;
}

/**
 * From unicode to 8-bit chars (info loss ist possible).
 *
 * @param pool IN pool
 * @param dst OUT 8-bit chars string null-terminated
 * @param src IN unicode string
 * @param len IN unicode string len
 *
 * @return dst string len
 */
static char *from_unicode(apr_pool_t *pool, const char *src, apr_size_t len) {
  int i, j;
  char *dst; 

  dst = apr_pcalloc(pool, len / 2 + 1);
  for (i = 0, j = 0; i < len; i += 2, j++) {
    dst[j] = src[i];
  }
  dst[j] = 0;
  
  return dst;
}

/**
 * to unicode if requested 
 *
 * @param hook IN htntlm hook
 * @param dst OUT unicode or oem
 * @param src IN oem string
 */
static apr_size_t handle_unicode(htntlm_t *hook, char **dst, const char *src) {
  if (hook->func_flags & HTNTLM_FUNC_FLAGS_UNICODE) {
    return to_unicode(hook->pool, dst, src);
  }
  else {
    if (dst) {
      *dst = apr_pstrdup(hook->pool, src);
    }
    return strlen(src);
  }
}

/**
 * to oem if unicoded string
 *
 * @param hook IN htntlm hook
 * @param dst OUT unicode or oem
 * @param src IN oem string
 */
static char *handle_oem(htntlm_t *hook, const char *src, apr_size_t len) {
  char *dst; 

  if (hook->func_flags & HTNTLM_FUNC_FLAGS_UNICODE) {
    return from_unicode(hook->pool, src, len);
  }
  else {
    dst = apr_pcalloc(hook->pool, len + 1);
    memcpy(dst, src, len);
    return dst;
  }
}

static void usage_format_desc(apr_pool_t *pool, const char *desc) {
  char *last;
  char *val;
  char *copy;
 
  if (desc == NULL) {
    return;
  }

  copy = apr_pstrdup(pool, desc);

  val = apr_strtok(copy, "\n", &last);
  fprintf(stdout, "%s", val);
  val = apr_strtok(NULL, "\n", &last);
  while (val) {
    fprintf(stdout, "\n                      %s", val);
    val = apr_strtok(NULL, "\n", &last);
  }
}

/** 
 * display usage information
 *
 * @progname IN name of the programm
 */
static void usage(apr_pool_t *pool, const char *progname) {
  int i = 0;
  fprintf(stdout, "%s is used to read, generate and inspect NTLM messages.\n", progname);

  fprintf(stdout, "\nUsage: %s [OPTIONS]", progname);
  fprintf(stdout, "\nOptions:");
  while (options[i].optch) {
    if (options[i].optch <= 255) {
      fprintf(stdout, "\n  -%c --%-15s", options[i].optch, options[i].name);
      usage_format_desc(pool, options[i].description);
    }
    else {
      fprintf(stdout, "\n     --%-15s", options[i].name);
    }
    i++;
  }
  fprintf(stdout, "\n");
  exit(EINVAL);
}

/**
 * Copy to uppercase string
 *
 * @param pool IN pool
 * @param str IN string to copy
 *
 * @return upper case string
 */
static char * str_copy_to_upper(apr_pool_t *pool, const char *str) {
  int i = 0;
  char *tmp = apr_pstrdup(pool, str);
  
  while (tmp[i]) {
    tmp[i] = apr_toupper(tmp[i]);
    ++i;
  }

  return tmp;
}

/**
 * Copy n to uppercase string an null pad if strlen(str) is smaller than n
 *
 * @param pool IN pool
 * @param str IN string to copy
 * @param n IN resulting string length null pad if required
 *
 * @return upper case string
 */
static unsigned char * strn_copy_to_upper(apr_pool_t *pool, const char *str, apr_size_t n) {
  int i = 0;
  unsigned char *tmp = apr_pcalloc(pool, n + 1);
  
  while (str && str[i] && i < n) {
    tmp[i] = apr_toupper(str[i]);
    ++i;
  }

  return tmp;
}

/**
 * create a DES key
 *
 * @param src IN 7 bytes for des key
 */
static DES_key_schedule *create_des_key(htntlm_t *hook, unsigned char *src) {
  DES_cblock key;
  DES_key_schedule *key_sched = apr_pcalloc(hook->pool, sizeof(*key_sched));

  key[0] = src[0];
  key[1] = ((src[0] << 7) & 0xff) | (src[1] >> 1);
  key[2] = ((src[1] << 6) & 0xff) | (src[2] >> 2);
  key[3] = ((src[2] << 5) & 0xff) | (src[3] >> 3);
  key[4] = ((src[3] << 4) & 0xff) | (src[4] >> 4);
  key[5] = ((src[4] << 3) & 0xff) | (src[5] >> 5);
  key[6] = ((src[5] << 2) & 0xff) | (src[6] >> 6);
  key[7] = (src[6] << 1) & 0xff;

  DES_set_odd_parity(&key);
  DES_set_key(&key, key_sched);
  return key_sched;
}

/** 
 * create a 24 byte hash with the 21 byte key (DES)
 *
 * @param hook IN htntlm hook
 * @param key IN 21 byte key
 *
 * @return 24 byte hash
 */
static unsigned char *get_hash(htntlm_t *hook, unsigned char *key24, DES_cblock *data) {
  DES_key_schedule *key_sched;
  unsigned char *hash = apr_pcalloc(hook->pool, 24);
  
  /* check if there is a challenge, else error */
  
  key_sched = create_des_key(hook, key24);
  DES_ecb_encrypt(data, (DES_cblock *)hash, key_sched, DES_ENCRYPT);
  key_sched = create_des_key(hook, &key24[7]);
  DES_ecb_encrypt(data, (DES_cblock *)&hash[8], key_sched, DES_ENCRYPT);
  key_sched = create_des_key(hook, &key24[14]);
  DES_ecb_encrypt(data, (DES_cblock *)&hash[16], key_sched, DES_ENCRYPT);

  return hash;
}

/**
 * Create lm hash out of the values stored in hook
 *
 * @param hook IN htntlm hook
 *
 * @return lm hash (24 bytes)
 */
static unsigned char * get_lm_hash(htntlm_t *hook) {
  unsigned char *passwd;
  DES_key_schedule *key_sched;
  unsigned char lmbuffer[21];
  uint64_t chl = hton64(hook->challenge);

  passwd = strn_copy_to_upper(hook->pool, hook->password, 14);

  memset(lmbuffer, 0, 21); 
  key_sched = create_des_key(hook, passwd);
  DES_ecb_encrypt((DES_cblock *)lm_magic, (DES_cblock *)lmbuffer, key_sched, DES_ENCRYPT);
  key_sched = create_des_key(hook, &passwd[7]);
  DES_ecb_encrypt((DES_cblock *)lm_magic, (DES_cblock *)&lmbuffer[8], key_sched, DES_ENCRYPT);
  memset(passwd, 0, 14);
  
  return get_hash(hook, lmbuffer, (DES_cblock *)&chl);
}

/**
 * Create ntlm hash out of the values stored in hook
 *
 * @param hook IN htntlm hook
 *
 * @return ntlm hash (24 bytes)
 */
static unsigned char * get_ntlm_hash(htntlm_t *hook) {
  MD4_CTX MD4;
  unsigned char ntlmbuffer[21];
  char *passwd; 
  apr_size_t len;
  uint64_t chl = hton64(hook->challenge);

  /* transform to unicode password */
  len = to_unicode(hook->pool, &passwd, hook->password);

  MD4_Init(&MD4);
  MD4_Update(&MD4, passwd, len);
  MD4_Final(ntlmbuffer, &MD4);

  memset(&ntlmbuffer[16], 0, 5);

  return get_hash(hook, ntlmbuffer, (DES_cblock *)&chl);
}

/**
 * Create lm2 hash out of the values stored in hook
 *
 * @param hook IN htntlm hook
 *
 * @return lmv2 hash
 */
static unsigned char * get_lm2_hash(htntlm_t *hook, uint16_t *hash_len) {
  unsigned char ntlm_hash[16];
  unsigned char ntlm2_hash[16];
  unsigned char *lm2_hash;
  const EVP_MD *md5 = EVP_md5();
  MD4_CTX MD4;
  char *passwd; 
  apr_size_t len;
  char *uuser;
  apr_size_t uuser_len;
  char *udomain;
  apr_size_t udomain_len;
  unsigned char *buf;
  HMAC_CTX hmac;
  unsigned char challenges[16];
  uint64_t chl = hton64(hook->challenge);

  /* 1. get ntlm hash */
  len = to_unicode(hook->pool, &passwd, hook->password);
  MD4_Init(&MD4);
  MD4_Update(&MD4, passwd, len);
  MD4_Final(ntlm_hash, &MD4);

  /* 2. concatonate unicoded username with unicoded domain or server name */
  uuser_len = to_unicode(hook->pool, &uuser, hook->user);
  if (hook->domain) {
    udomain_len = to_unicode(hook->pool, &udomain, hook->domain);
  }
  else {
    udomain_len = to_unicode(hook->pool, &udomain, hook->server);
  }
  buf = apr_pcalloc(hook->pool, uuser_len + udomain_len);
  memcpy(buf, uuser, uuser_len);
  memcpy(&buf[uuser_len], udomain, udomain_len);

  HMAC_CTX_init(&hmac);
  HMAC_Init_ex(&hmac, ntlm_hash, 16, md5, NULL);
  HMAC_Update(&hmac, buf, uuser_len + udomain_len);
  len = 16;
  HMAC_Final(&hmac, ntlm2_hash, &len);

  /* 3. client challenge */

  /* 4. concat challenge wiht client challenge and hmac with key ntlm2_hash */
  lm2_hash = apr_pcalloc(hook->pool, 24);
  memcpy(challenges, &chl, 8);
  memcpy(&challenges[8], &hook->client_challenge, 8);

  HMAC_CTX_init(&hmac);
  HMAC_Init_ex(&hmac, ntlm2_hash, 16, md5, NULL);
  HMAC_Update(&hmac, challenges, 16);
  len = 16;
  HMAC_Final(&hmac, lm2_hash, &len);

  memcpy(&lm2_hash[16], &hook->client_challenge, 8);

  *hash_len = 24;
  return lm2_hash;
}

/**
 * Create ntlm2 hash out of the values stored in hook
 *
 * @param hook IN htntlm hook
 *
 * @return ntlmv2 hash
 */
static unsigned char * get_ntlm2_hash(htntlm_t *hook, uint16_t *hash_len) {
  char *uuser;
  char *udomain;
  unsigned char *part;
  apr_size_t uuser_len;
  apr_size_t udomain_len;
  const EVP_MD *md5 = EVP_md5();
  HMAC_CTX hmac;
  unsigned char ntlm_hash[16];
  unsigned char ntlm2_hash[16];
  unsigned char blob_hash[16];
  apr_size_t len;
  unsigned char *blob;
  unsigned char *buf;
  unsigned char *target_info = NULL;
  apr_size_t ti_len = 0;
  MD4_CTX MD4;
  char *passwd; 
  uint64_t chl = hton64(hook->challenge);
    
  if (hook->target_info) {
    int b64len = apr_base64_decode_len(hook->target_info);
    target_info = apr_pcalloc(hook->pool, b64len);
    ti_len = apr_base64_decode_binary(target_info, hook->target_info);
  }

  /* 1. get ntlm hash */
  len = to_unicode(hook->pool, &passwd, hook->password);

  MD4_Init(&MD4);
  MD4_Update(&MD4, passwd, len);
  MD4_Final(ntlm_hash, &MD4);

  /* 2. concat unicoded username and domain name and do a hmac md5 with ntlm_hash as key*/
  uuser_len = to_unicode(hook->pool, &uuser, hook->user);
  udomain_len = to_unicode(hook->pool, &udomain, hook->domain);
  part = apr_pcalloc(hook->pool, uuser_len + udomain_len);
  memcpy(part, uuser, uuser_len);
  memcpy(&part[uuser_len], udomain, udomain_len);
  
  HMAC_CTX_init(&hmac);
  HMAC_Init_ex(&hmac, ntlm_hash, 16, md5, NULL);
  HMAC_Update(&hmac, part, uuser_len + udomain_len);
  len = 16;
  HMAC_Final(&hmac, ntlm2_hash, &len);

  /* 3. blob */
  blob = apr_pcalloc(hook->pool, 28 + ti_len + 4);
  *((uint32_t *)&blob[0]) = hton32(0x00000101);
  *((uint32_t *)&blob[4]) = hton32(0x00000000);
#if defined(WIN32)
  *((uint64_t *)&blob[8]) = hton64((apr_time_sec(apr_time_now()) + 
    (unsigned __int64)11644473600) * (unsigned __int64)10000000);
#else
  *((uint64_t *)&blob[8]) = hton64((apr_time_sec(apr_time_now()) + 
    11644473600LLU) * 10000000LLU);
#endif
  if (hook->client_challenge) {
    memcpy(&blob[16], &hook->client_challenge, 8);
  }
  if (target_info) {
    memcpy(&blob[28], target_info, ti_len);
  }

  /* 4. catonate challenge to blob and do a hmac md5 with ntlm2_hash as key */
  buf = apr_pcalloc(hook->pool, 16 + 28 + ti_len + 4);
  if (chl) {
    memcpy(buf, &chl, 8);
  }
  memcpy(&buf[8], blob, 28 + ti_len + 4);

  HMAC_CTX_init(&hmac);
  HMAC_Init_ex(&hmac, ntlm2_hash, 16, md5, NULL);
  HMAC_Update(&hmac, buf, 8 + 28 + ti_len + 4);
  len = 16;
  HMAC_Final(&hmac, blob_hash, &len);

  /* 5. this value concat with the blob */
  memcpy(buf, blob_hash, 16);
  memcpy(&buf[16], blob, 28 + ti_len + 4);
  
  *hash_len = 16 + 28 + ti_len + 4;

  return buf;
}

/**
 * Create ntlm2 session out of the values stored in hook
 *
 * @param hook IN htntlm hook
 *
 * @return ntlm2 session
 */
static unsigned char * get_ntlm2_sess(htntlm_t *hook, uint16_t *hash_len) {
  char challenges[16];
  unsigned char ntlm2_hash[16];
  unsigned char ntlm_hash[21];
  MD4_CTX MD4;
  MD5_CTX MD5;
  char *passwd; 
  apr_size_t len;
  uint64_t chl = hton64(hook->challenge);

  /* 3. challenge and client challenge */
  memcpy(challenges, &chl, 8);
  memcpy(&challenges[8], &hook->client_challenge, 8);

  /* 4. md5 of challenges */
  MD5_Init(&MD5);
  MD5_Update(&MD5, challenges, 16);
  MD5_Final(ntlm2_hash, &MD5);
  
  /* 6. get ntlm hash */
  len = to_unicode(hook->pool, &passwd, hook->password);
  MD4_Init(&MD4);
  MD4_Update(&MD4, passwd, len);
  MD4_Final(ntlm_hash, &MD4);

  /* 7. ntlm has is null padded up to 21 bytes */ 
  memset(&ntlm_hash[16], 0, 5);
  
  *hash_len = 24;
  return get_hash(hook, ntlm_hash, (DES_cblock *)ntlm2_hash);
}

/**
 * Print ntlm message in a readable manner
 *
 * @param hook IN htntlm hook
 */
static void print_info(htntlm_t *hook) {
  int i = 0;

  if (hook->type == 0) {
    apr_file_printf(hook->out, "message-type: undef\n");
  }
  else if (hook->type > 0 && hook->type <= 3) {
    apr_file_printf(hook->out, "message-type: %d\n", hook->type);
  }
  else {
    apr_file_printf(hook->out, "message-type: malformed\n");
  }
  
  if (hook->flags) {
    apr_file_printf(hook->out, "flags: ");
    while (flags_map[i].name) {   
      if (hook->flags & flags_map[i].flag) {
	apr_file_printf(hook->out, "%s ", flags_map[i].name);
      }
      ++i;
    }
    apr_file_printf(hook->out, "\n");
  }

  if (hook->domain) {
    apr_file_printf(hook->out, "domain: %s\n", hook->domain);
  }

  if (hook->workstation) {
    apr_file_printf(hook->out, "workstation: %s\n", hook->workstation);
  }

  if (hook->target) {
    apr_file_printf(hook->out, "target: %s\n", hook->target);
  }

  if (hook->server) {
    apr_file_printf(hook->out, "server: %s\n", hook->server);
  }

  if (hook->dns_domain) {
    apr_file_printf(hook->out, "DNS domain: %s\n", hook->dns_domain);
  }

  if (hook->dns_server) {
    apr_file_printf(hook->out, "DNS server: %s\n", hook->dns_server);
  }

  if (hook->user) {
    apr_file_printf(hook->out, "user: %s\n", hook->user);
  }

  if (hook->challenge) {
    apr_file_printf(hook->out, "challenge: " FMT_LLX "\n", hook->challenge);
  }

  if (hook->client_challenge) {
    apr_file_printf(hook->out, "client challenge: " FMT_LLX "\n", 
	            hook->client_challenge);
  }
  
  if (hook->context) {
    apr_file_printf(hook->out, "context: " FMT_LLX "\n", hook->context);
  }

  if (hook->target_info) {
    apr_file_printf(hook->out, "target info: %s\n", hook->target_info);
  }
  
  if (hook->lm.hash) {
    apr_file_printf(hook->out, "lm hash: ");
    for (i = 0; i < hook->lm.len; i++) {
      apr_file_printf(hook->out, "%02x", hook->lm.hash[i]);
    }
    apr_file_printf(hook->out, "\n");
  }

  if (hook->ntlm.hash) {
    apr_file_printf(hook->out, "ntlm hash: ");
    for (i = 0; i < hook->ntlm.len; i++) {
      apr_file_printf(hook->out, "%02x", hook->ntlm.hash[i]);
    }
    apr_file_printf(hook->out, "\n");
  }
}

/**
 * Print ntlm message type 1 as a base64 string
 *
 * @param hook IN htntlm hook
 */
static void write_type1_msg(htntlm_t *hook) {
  unsigned char *msg;
  char *b64msg;
  int len;
  int b64len;
  uint16_t len16;
  uint32_t offset = 0;
  char *tmp;

  /* callculate len */
  if (hook->domain || hook->workstation) {
    len = 32;
  }
  else {
    len = 16;
  }
  
  if (hook->domain) {
    /* never unicode allways oem in a type 1 message */
    len += strlen(hook->domain);
  }
  if (hook->workstation) {
    /* never unicode allways oem in a type 1 message */
    len += strlen(hook->workstation);
  }

  /* allocate message */
  msg = apr_pcalloc(hook->pool, len);
  /* start string */
  strcpy((char *)msg, "NTLMSSP");
  /* type */
  *((uint32_t *)&msg[8]) = hton32(hook->type);
  /* flags */
  *((uint32_t *)&msg[12]) = hton32(hook->flags);
  /* optional domain */
  if (hook->domain) {
    /* never unicode allways oem in a type 1 message */
    tmp = apr_pstrdup(hook->pool, hook->domain);
    len16 = strlen(hook->domain);
    *((uint16_t *)&msg[16]) = hton16(len16);
    *((uint16_t *)&msg[18]) = hton16(len16);
    *((uint32_t *)&msg[20]) = hton32(32 + offset);
    memcpy(&msg[32 + offset], tmp, len16);
    offset = len16;
  }
  /* optional workstation */
  if (hook->workstation) {
    /* never unicode allways oem in a type 1 message */
    tmp = apr_pstrdup(hook->pool, hook->workstation);
    len16 = strlen(hook->workstation);
    *((uint16_t *)&msg[24]) = hton16(len16);
    *((uint16_t *)&msg[26]) = hton16(len16);
    *((uint32_t *)&msg[28]) = hton32(32 + offset);
    memcpy(&msg[32 + offset], tmp, len16);
  }
  
  b64len = apr_base64_encode_len(len);
  b64msg = apr_pcalloc(hook->pool, b64len);
  apr_base64_encode_binary(b64msg, msg, len);
  apr_file_printf(hook->out, "%s", b64msg);
}

/**
 * Print ntlm message type 2 as a base64 string
 *
 * @param hook IN htntlm hook
 */
static void write_type2_msg(htntlm_t *hook) {
  unsigned char *msg;
  char *b64msg;
  int len;
  int b64len;
  uint16_t len16;
  uint32_t offset = 0;
  uint16_t tlen16;
  char *tmp;

  /* callculate len */
  len = 48;
  tlen16 = 0;
  if (hook->target) {
    tlen16 += handle_unicode(hook, NULL, hook->target);
  }
  if (hook->domain) {
    tlen16 += 4 + to_unicode(hook->pool, NULL, hook->domain);
  }
  if (hook->server) {
    tlen16 += 4 + to_unicode(hook->pool, NULL, hook->server);
  }
  if (hook->dns_domain) {
    tlen16 += 4 + to_unicode(hook->pool, NULL, hook->dns_domain);
  }
  if (hook->dns_server) {
    tlen16 += 4 + strlen(hook->dns_server);
    tlen16 += 4 + to_unicode(hook->pool, NULL, hook->dns_server);
  }
  if (tlen16) {
    /* target info termination */
    tlen16 += 4;
  }
 
  len += tlen16;

  /* allocate message initialize with zeros*/
  msg = apr_pcalloc(hook->pool, len);
  /* start string */
  strcpy((char *)msg, "NTLMSSP");
  /* type */
  *((uint32_t *)&msg[8]) = hton32(hook->type);
  /* target */
  if (hook->target) {
    len16 = handle_unicode(hook, &tmp, hook->target);
    *((uint16_t *)&msg[12]) = hton16(len16);
    *((uint16_t *)&msg[14]) = hton16(len16);
    *((uint32_t *)&msg[16]) = hton32(48 + offset);
    memcpy(&msg[48 + offset], tmp, len16);
    offset = len16;
  }
  /* flags */
  *((uint32_t *)&msg[20]) = hton32(hook->flags);
  /* challenge */
  if (hook->challenge) {
    *((uint64_t *)&msg[24]) = hton64(hook->challenge);
  }
  /* context */
  if (hook->context) {
    *((uint64_t *)&msg[32]) = hton64(hook->context);
  }
  if (tlen16) {
    /* target info security buffer */
    *((uint16_t *)&msg[40]) = hton16(tlen16);
    *((uint16_t *)&msg[42]) = hton16(tlen16);
    *((uint32_t *)&msg[44]) = hton32(48 + offset);
    /* target info */
    if (hook->domain) {
      len16 = to_unicode(hook->pool, &tmp, hook->domain);
      *((uint16_t *)&msg[48 + offset]) = hton16(HTNTLM_SUBBLK_DOMAIN_NAME);
      *((uint16_t *)&msg[50 + offset]) = hton16(len16);
      memcpy(&msg[52 + offset], tmp, len16);
      offset += 4  + len16;
    }
    if (hook->server) {
      len16 = to_unicode(hook->pool, &tmp, hook->server);
      *((uint16_t *)&msg[48 + offset]) = hton16(HTNTLM_SUBBLK_SERVER_NAME);
      *((uint16_t *)&msg[50 + offset]) = hton16(len16);
      memcpy(&msg[52 + offset], tmp, len16);
      offset += 4  + len16;
    }
    if (hook->dns_domain) {
      len16 = to_unicode(hook->pool, &tmp, hook->dns_domain);
      *((uint16_t *)&msg[48 + offset]) = hton16(HTNTLM_SUBBLK_DNS_DOMAIN);
      *((uint16_t *)&msg[50 + offset]) = hton16(len16);
      memcpy(&msg[52 + offset], tmp, len16);
      offset += 4  + len16;
    }
    if (hook->dns_server) {
      len16 = to_unicode(hook->pool, &tmp, hook->dns_server);
      *((uint16_t *)&msg[48 + offset]) = hton16(HTNTLM_SUBBLK_DNS_SERVER);
      *((uint16_t *)&msg[50 + offset]) = hton16(len16);
      memcpy(&msg[52 + offset], tmp, len16);
      offset += 4  + len16;
    }
    if (tlen16) {
      *((uint16_t *)&msg[48 + offset]) = 0;
      *((uint16_t *)&msg[50 + offset]) = 0;
    }
    offset = tlen16;
  }
  /* base64 */
  b64len = apr_base64_encode_len(len);
  b64msg = apr_pcalloc(hook->pool, b64len);
  apr_base64_encode_binary(b64msg, msg, len);
  apr_file_printf(hook->out, "%s", b64msg);
}

/**
 * Print ntlm message type 3 as a base64 string
 *
 * @param hook IN htntlm hook
 */
static void write_type3_msg(htntlm_t *hook) {
  unsigned char *msg;
  char *b64msg;
  int len;
  int b64len;
  uint16_t len16;
  uint32_t offset = 0;
  char *tmp;

  /* callucalte len */
  len = 64;

  /* lm/lmv2 response len */
  if (hook->lm.len) {
    len += hook->lm.len;
  }
  /* ntlm/ntlmv2 response len */
  if (hook->ntlm.len) {
    len += hook->ntlm.len;
  }

  if (hook->domain) {
    len += handle_unicode(hook, NULL, hook->domain);
  }
  if (hook->user) {
    len += handle_unicode(hook, NULL, hook->user);
  }
  if (hook->workstation) {
    len += handle_unicode(hook, NULL, hook->workstation);
  }
  if (hook->session_key) {
    len += strlen(hook->session_key);
  }

  /* allocate message initialize with zeros*/
  msg = apr_pcalloc(hook->pool, len);
  /* start string */
  strcpy((char *)msg, "NTLMSSP");
  /* type */
  *((uint32_t *)&msg[8]) = hton32(hook->type);

  /* lm/lmv2 response */
  if (hook->lm.len) {
    len16 = hook->lm.len;
    *((uint16_t *)&msg[12]) = hton16(len16);
    *((uint16_t *)&msg[14]) = hton16(len16);
    *((uint32_t *)&msg[16]) = hton32(64 + offset);
    memcpy(&msg[64 + offset], hook->lm.hash, len16);
    offset += len16;
  }
  /* ntlm/ntlmv2 response */
  if (hook->ntlm.len) {
    len16 = hook->ntlm.len;
    *((uint16_t *)&msg[20]) = hton16(len16);
    *((uint16_t *)&msg[22]) = hton16(len16);
    *((uint32_t *)&msg[24]) = hton32(64 + offset);
    memcpy(&msg[64 + offset], hook->ntlm.hash, len16);
    offset += len16;
  }
  /* domain */
  if (hook->domain) {
    len16 = handle_unicode(hook, &tmp, hook->domain);
    *((uint16_t *)&msg[28]) = hton16(len16);
    *((uint16_t *)&msg[30]) = hton16(len16);
    *((uint32_t *)&msg[32]) = hton32(64 + offset);
    memcpy(&msg[64 + offset], tmp, len16);
    offset += len16;
  }
  /* user */
  if (hook->user) {
    len16 = handle_unicode(hook, &tmp, hook->user);
    *((uint16_t *)&msg[36]) = hton16(len16);
    *((uint16_t *)&msg[38]) = hton16(len16);
    *((uint32_t *)&msg[40]) = hton32(64 + offset);
    memcpy(&msg[64 + offset], tmp, len16);
    offset += len16;
  }
  /* workstation */
  if (hook->workstation) {
    len16 = handle_unicode(hook, &tmp, hook->workstation);
    *((uint16_t *)&msg[44]) = hton16(len16);
    *((uint16_t *)&msg[46]) = hton16(len16);
    *((uint32_t *)&msg[48]) = hton32(64 + offset);
    memcpy(&msg[64 + offset], tmp, len16);
    offset += len16;
  }
  /* session key */
  if (hook->session_key) {
    len16 = strlen(hook->session_key);
    *((uint16_t *)&msg[52]) = hton16(len16);
    *((uint16_t *)&msg[54]) = hton16(len16);
    *((uint32_t *)&msg[56]) = hton32(64 + offset);
    memcpy(&msg[64 + offset], hook->session_key, len16);
    offset += len16;
  }
  /* flags */
  *((uint32_t *)&msg[60]) = hton32(hook->flags);

  /* base64 */
  b64len = apr_base64_encode_len(len);
  b64msg = apr_pcalloc(hook->pool, b64len);
  apr_base64_encode_binary(b64msg, msg, len);
  apr_file_printf(hook->out, "%s", b64msg);
}

/**
 * Write ntlm message type 1,2,3 as a base64 string
 *
 * @param hook IN htntlm hook
 */
static void write_message(htntlm_t *hook) {
  switch (hook->type) {
  case 1:
    write_type1_msg(hook);
    break;
  case 2:
    write_type2_msg(hook);
    break;
  case 3:
    write_type3_msg(hook);
    break;
  default:
    break;
  }
}

/**
 * Read type 1 NTLM message
 *
 * @param hook IN htntlm hook
 * @param message IN NTLM message
 */
static void read_type1_msg(htntlm_t *hook, unsigned char *msg, int msg_len) {
  int len;
  int alloc;
  int offset;

  hook->flags = ntoh32(*((uint32_t *)&msg[12]));
  
  /* test if optional domain is there */
  if (msg_len < 24) {
    return;
  }
  /* domain */
  len = ntoh16(*((uint16_t *)&msg[16]));
  alloc = ntoh16(*((uint16_t *)&msg[18]));
  offset = ntoh32(*((uint32_t *)&msg[20]));
  if (len) {
    hook->domain = apr_pstrndup(hook->pool, (char *)&msg[offset], len);
  }
  /* test if optional workstation is there */
  if (msg_len < 32) {
    return;
  }
  /* workstation */
  len = ntoh16(*((uint16_t *)&msg[24]));
  alloc = ntoh16(*((uint16_t *)&msg[26]));
  offset = ntoh32(*((uint32_t *)&msg[28]));
  if (len) {
    hook->workstation = apr_pstrndup(hook->pool, (char *)&msg[offset], len);
  }

}

/**
 * Read type 2 NTLM message
 *
 * @param hook IN htntlm hook
 * @param message IN NTLM message
 */
static void read_type2_msg(htntlm_t *hook, unsigned char *msg, int msg_len) {
  uint16_t len;
  uint16_t alloc;
  uint32_t offset;
  uint16_t subblk;
  char *b64msg;
  int b64len;

  /* target */
  len = ntoh16(*((uint16_t *)&msg[12]));
  alloc = ntoh16(*((uint16_t *)&msg[14]));
  offset = ntoh32(*((uint32_t *)&msg[16]));
  if (len) {
    hook->target = handle_oem(hook, (char *)&msg[offset], len);
  }
  /* flags */
  hook->flags = ntoh32(*((uint32_t *)&msg[20]));
  /* challenge */
  if (*((uint64_t *)&msg[24])) {
    hook->challenge = ntoh64(*((uint64_t *)&msg[24]));
  }
  /* test if optional context is available */
  if (msg_len < 40) {
    return;
  }
  /* context */
  if (*((uint64_t *)&msg[32])) {
    hook->context = ntoh64(*((uint64_t *)&msg[32]));
  }
  /* test if optional target info is available */
  if (msg_len < 52) {
    return;
  }
  /* target info */
  len = ntoh16(*((uint16_t *)&msg[40]));
  alloc = ntoh16(*((uint16_t *)&msg[42]));
  offset = ntoh32(*((uint32_t *)&msg[44]));
  if (len) {
    b64len = apr_base64_encode_len(len);
    b64msg = apr_pcalloc(hook->pool, b64len);
    apr_base64_encode_binary(b64msg, &msg[offset], len);
    hook->target_info = b64msg; 
    while (1) {
      subblk = ntoh16(*((uint16_t *)&msg[offset]));
      if (subblk == 0) {
	break;
      }
      len = ntoh16(*((uint16_t *)&msg[2 + offset]));
      offset += 4;
      switch (subblk) {
      case HTNTLM_SUBBLK_SERVER_NAME:
	hook->server = from_unicode(hook->pool, (char *)&msg[offset], len); 
	break;
      case HTNTLM_SUBBLK_DOMAIN_NAME:
	hook->domain = from_unicode(hook->pool, (char *)&msg[offset], len); 
	break;
      case HTNTLM_SUBBLK_DNS_SERVER:
	hook->dns_server = from_unicode(hook->pool, (char *)&msg[offset], len); 
	break;
      case HTNTLM_SUBBLK_DNS_DOMAIN:
	hook->dns_domain = from_unicode(hook->pool, (char *)&msg[offset], len); 
	break;
      default:
	break;
      }
      offset += len;
    }
  }
}

/**
 * Read type 3 NTLM message
 *
 * @param hook IN htntlm hook
 * @param message IN NTLM message
 */
static void read_type3_msg(htntlm_t *hook, unsigned char *msg, int msg_len) {
  int len;
  int alloc;
  int offset;

  /* lm/lmv2 response */
  len = ntoh16(*((uint16_t *)&msg[12]));
  alloc = ntoh16(*((uint16_t *)&msg[14]));
  offset = ntoh32(*((uint32_t *)&msg[16]));
  if (len) {
    hook->lm.hash = apr_pcalloc(hook->pool, len); 
    memcpy(hook->lm.hash, &msg[offset], len);
    hook->lm.len = len;
  }
  /* ntlm/ntlmv2 response */
  len = ntoh16(*((uint16_t *)&msg[20]));
  alloc = ntoh16(*((uint16_t *)&msg[22]));
  offset = ntoh32(*((uint32_t *)&msg[24]));
  if (len) {
    hook->ntlm.hash = apr_pcalloc(hook->pool, len); 
    memcpy(hook->ntlm.hash, &msg[offset], len);
    hook->ntlm.len = len;
  }
  /* domain */
  len = ntoh16(*((uint16_t *)&msg[28]));
  alloc = ntoh16(*((uint16_t *)&msg[30]));
  offset = ntoh32(*((uint32_t *)&msg[32]));
  if (len) {
    hook->domain = handle_oem(hook, (char *)&msg[offset], len);
  }
  /* user */
  len = ntoh16(*((uint16_t *)&msg[36]));
  alloc = ntoh16(*((uint16_t *)&msg[38]));
  offset = ntoh32(*((uint32_t *)&msg[40]));
  if (len) {
    hook->user = handle_oem(hook, (char *)&msg[offset], len);
  }
  /* workstation */
  len = ntoh16(*((uint16_t *)&msg[44]));
  alloc = ntoh16(*((uint16_t *)&msg[46]));
  offset = ntoh32(*((uint32_t *)&msg[48]));
  if (len) {
    hook->workstation = handle_oem(hook, (char *)&msg[offset], len);
  }

  /* session key */
  /* flags */
}

/**
 * Read a base64 encoded NTLM message
 *
 * @param hook IN htntlm hook
 * @param message IN base64 encode NTLM message
 */
static void read_message(htntlm_t *hook, char *message) {
  int b64len = apr_base64_decode_len(message);
  unsigned char *msg = apr_pcalloc(hook->pool, b64len);
 
  b64len = apr_base64_decode_binary(msg, message);

  /* check start cause this is allways the same */
  if (strncmp("NTLMSSP", (char *)msg, 8) != 0) {
    hook->exception = apr_pstrdup(hook->pool, "NTLM magic error");
    return;
  }

  /* get type */
  hook->type = ntoh32(*(uint32_t *)&msg[8]);
  switch (hook->type) {
  case 1:
    read_type1_msg(hook, msg, b64len);
    break;
  case 2:
    read_type2_msg(hook, msg, b64len);
    break;
  case 3:
    read_type3_msg(hook, msg, b64len);
    break;
  default:
    hook->exception = apr_psprintf(hook->pool, "unknown NTLM message type %d", hook->type);
    return;
    break;
  }
}

/**
 * convert readable flags to binary flags
 *
 * @param hook IN htntlm hook
 * @param flags IN readable flags
 */
static apr_status_t readable_to_flags(htntlm_t *hook, uint32_t *flags, htntlm_flags_map_t *map, 
                                      const char *flags_str) {
  char *tmp = apr_pstrdup(hook->pool, flags_str);
  char *last;
  char *flag;
  int i = 0;

  flag = apr_strtok(tmp, " ", &last);

  while (flag) {
    apr_collapse_spaces(flag, flag);
    i = 0;
    while (map[i].name) {   
      if (strcmp(flag, map[i].name) == 0) {
	*flags |= map[i].flag;
	break;
      }
      ++i;
    }
    flag = apr_strtok(NULL, " ", &last);
  }
  
  return APR_SUCCESS;
}

/** 
 * sort out command-line args and call test 
 *
 * @param argc IN number of arguments
 * @param argv IN argument array
 *
 * @return 0 if success
 */
int main(int argc, const char *const argv[]) {
  apr_status_t status;
  apr_getopt_t *opt;
  const char *optarg;
  char *tmp;
  char *val;
  char *last;
  int c;
  apr_pool_t *pool;
  htntlm_t *hook;
#define ACTION_NONE 0
#define ACTION_INFO 1
#define ACTION_WRITE 2
#define ACTION_READ 4
  int flags = ACTION_NONE;
  char *b64msg = NULL;
  char *chl_str = NULL;
  char *c_chl_str = NULL;
  char *ctx_str = NULL;

  srand(apr_time_now()); 
  
  apr_app_initialize(&argc, &argv, NULL);
  apr_pool_create(&pool, NULL);

  /* set default */
  hook = apr_pcalloc(pool, sizeof(*hook));
  hook->pool = pool; 

  /* get read option do this first before handle all other options */
  apr_getopt_init(&opt, pool, argc, argv);
  while ((status = apr_getopt_long(opt, options, &c, &optarg)) == APR_SUCCESS) {
    switch (c) {
    case 'u':
      hook->func_flags |= HTNTLM_FUNC_FLAGS_UNICODE;
      break;
    case 'r':
      flags |= ACTION_READ;
      b64msg = apr_pstrdup(hook->pool, optarg);
      break;
    }
  }
  if (flags & ACTION_READ) {
    read_message(hook, b64msg);
  }

  /* again get options */
  apr_getopt_init(&opt, pool, argc, argv);
  while ((status = apr_getopt_long(opt, options, &c, &optarg)) == APR_SUCCESS) {
    switch (c) {
    case 'h':
      usage(pool, filename(pool, argv[0]));
      break;
    case 'v':
      copyright(filename(pool, argv[0]));
      return 0;
      break;
    case 'w':
      flags |= ACTION_WRITE;
      break;
    case 'i':
      flags |= ACTION_INFO;
      break;
    case 'D':
      hook->domain = str_copy_to_upper(pool, optarg);
      break;
    case 'W':
      hook->workstation = str_copy_to_upper(pool, optarg);
      break;
    case 'E':
      hook->server = str_copy_to_upper(pool, optarg);
      break;
    case 'T':
      hook->target = str_copy_to_upper(pool, optarg);
      break;
    case 'O':
      tmp = apr_pstrdup(pool, optarg);
      val = apr_strtok(tmp, ".", &last);
      hook->os.major = apr_atoi64(val);
      val = apr_strtok(NULL, ".", &last);
      hook->os.minor = apr_atoi64(val);
      val = apr_strtok(NULL, ".", &last);
      hook->os.maint = apr_atoi64(val);
      break;
    case 'N':
      hook->dns_domain = str_copy_to_upper(pool, optarg);
      break;
    case 'S':
      hook->dns_server = str_copy_to_upper(pool, optarg);
      break;
    case 'U':
      hook->user = str_copy_to_upper(pool, optarg);
      break;
    case 'P':
      hook->password = apr_pstrdup(pool, optarg);
      break;
    case 'C':
      chl_str = apr_pstrdup(pool, optarg);
      break;
    case 'c':
      c_chl_str = apr_pstrdup(pool, optarg);
      break;
    case 'X':
      ctx_str = apr_pstrdup(pool, optarg);
      break;
    case 'K':
      hook->session_key = apr_pstrdup(pool, optarg);
      break;
    case 't':
      hook->type = apr_atoi64(optarg);
      break;
    case 'f':
      readable_to_flags(hook, &hook->flags, flags_map, optarg);
      break;
    case 'R':
      readable_to_flags(hook, &hook->resp, resp_flags_map, optarg);
      break;
    case 'u':
      hook->func_flags |= HTNTLM_FUNC_FLAGS_UNICODE;
      break;
    case 'a':
      hook->target_info = apr_pstrdup(pool, optarg);
      break;
    }
  }

  /* test for wrong options */
  if (!APR_STATUS_IS_EOF(status) || flags == ACTION_NONE) {
    fprintf(stderr, "try \"%s --help\" to get more information\n", 
	    filename(pool, argv[0]));
    exit(1);
  }

  if ((status = apr_file_open_stdout(&hook->out, pool)) != APR_SUCCESS) {
    fprintf(stdout, "Could not open stdout: %s(%d)\n", 
	    my_status_str(pool, status), status);
  }

  if (!c_chl_str) {
    RAND_pseudo_bytes((unsigned char *)&hook->client_challenge, 
	              sizeof(hook->client_challenge));
  }
  else {
    sscanf(c_chl_str, FMT_LLX, &hook->client_challenge);
  }
  
  if (chl_str) {
    sscanf(chl_str, FMT_LLX, &hook->challenge);
  }
  
  if (ctx_str) {
    sscanf(chl_str, FMT_LLX, &hook->context);
  }
  
  if (hook->resp & HTNTLM_RESP_LM) {
    hook->lm.hash = get_lm_hash(hook);
    hook->lm.len = 24;
  }
  
  if (hook->resp & HTNTLM_RESP_NTLM) {
    hook->ntlm.hash = get_ntlm_hash(hook);
    hook->ntlm.len = 24;
  }

  if (hook->resp & HTNTLM_RESP_LM2) {
    hook->lm.hash = get_lm2_hash(hook, &hook->lm.len);
  }

  if (hook->resp & HTNTLM_RESP_NTLM2) {
    hook->ntlm.hash = get_ntlm2_hash(hook, &hook->ntlm.len);
  }

  if (hook->resp & HTNTLM_RESP_NTLM2_SESS) {
    hook->lm.hash = apr_pcalloc(hook->pool, 24);
    hook->lm.len = 24;
    memcpy(hook->lm.hash, &hook->client_challenge, 8);
    hook->ntlm.hash = get_ntlm2_sess(hook, &hook->ntlm.len);
  }
  
  if (flags & ACTION_INFO) {
    print_info(hook);
  }
  
  if (flags & ACTION_WRITE) {
    write_message(hook);
  }
  
  return 0;
}
