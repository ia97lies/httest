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
 * Implementation of the HTTP Test Tool html module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"
#include "libxml/HTMLparser.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct html_wconf_s {
  htmlParserCtxtPtr parser_ctx;
  htmlDocPtr doc;
  xmlNodePtr root_node;
} html_wconf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
const char * html_module = "html_module";

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * Get html config from worker
 *
 * @param worker IN worker
 * @return html config
 */
static html_wconf_t *html_get_worker_config(worker_t *worker) {
  html_wconf_t *config = module_get_config(worker->config, html_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    config->parser_ctx = htmlNewParserCtxt();
    module_set_config(worker->config, apr_pstrdup(worker->pbody, html_module), config);
  }
  return config;
}

/************************************************************************
 * Commands 
 ***********************************************************************/
static apr_status_t block_HTML_PARSE(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *param;
  const xmlChar *html;
  xmlNodePtr cur;
  xmlNodePtr sib;

  html_wconf_t *wconf = html_get_worker_config(worker);

  param = store_get(worker->params, "1");
  if (!param) {
    worker_log_error(worker, "Need a html document as parameter");
    return APR_EINVAL;
  }
  html = worker_get_value_from_param(worker, param, ptmp);

  wconf->doc = htmlCtxtReadDoc(wconf->parser_ctx, html, NULL, NULL, 0);
  if (!wconf->doc) {
    worker_log_error(worker, "Could not parse HTML");
    return APR_EINVAL;
  }
  wconf->root_node = xmlDocGetRootElement(wconf->doc);
  
#if 0
  cur = wconf->root_node;
  while (cur) {
    sib = cur;
    while (sib) {
      fprintf(stderr, "\nXXX: %s:%s\n", sib->name, sib->content);
      sib = sib->next;
    }
    cur = cur->children;
  }
#endif
  return APR_SUCCESS;
}

/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t html_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "HTML", "_PARSE",
	                           "<html>",
	                           "Parse HTML",
	                           block_HTML_PARSE)) != APR_SUCCESS) {
    return status;
  }
  return APR_SUCCESS;
}

