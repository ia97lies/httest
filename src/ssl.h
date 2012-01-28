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
 * Interface of the HTTP Test Tool ssl.
 */

#ifndef HTTEST_SSL_H
#define HTTEST_SSL_H

void ssl_util_thread_setup(apr_pool_t * p); 
void ssl_rand_seed(void); 
apr_status_t ssl_handshake(SSL *ssl, char **error, apr_pool_t *pool);
apr_status_t ssl_accept(SSL *ssl, char **error, apr_pool_t *pool); 
#ifndef OPENSSL_NO_ENGINE
ENGINE *setup_engine(BIO *err, const char *engine, int debug); 
#endif
char *ssl_var_lookup_ssl_cert(apr_pool_t *p, X509 *xs, const char *var); 
int debug_verify_callback(int cur_ok, X509_STORE_CTX *ctx); 
int skip_verify_callback(int cur_ok, X509_STORE_CTX *ctx); 

#endif
