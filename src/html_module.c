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
#include "libxml/xpath.h"
#include "libxml/tree.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct html_wconf_s {
  htmlParserCtxtPtr parser_ctx;
  htmlDocPtr doc;
  xmlXPathContextPtr xpath;
} html_wconf_t;

#if LIBXML_VERSION < 20627
#define XML_CTXT_FINISH_DTD_0 0xabcd1234
static int htmlInitParserCtxt(worker_t *worker,htmlParserCtxtPtr ctxt)
{
  htmlSAXHandler *sax;
  if (ctxt == NULL) return(-1);
  
  memset(ctxt, 0, sizeof(htmlParserCtxt));
  ctxt->dict = xmlDictCreate();
  if (ctxt->dict == NULL) {
     logger_log_error(worker->logger, "htmlInitParserCtxt: out of memory\n");
    return(-1);
  }
  sax = (htmlSAXHandler *) xmlMalloc(sizeof(htmlSAXHandler));
  if (sax == NULL) {
    logger_log_error(worker->logger, "htmlInitParserCtxt: out of memory\n");
    return(-1);
  }
  else
    memset(sax, 0, sizeof(htmlSAXHandler));

  ctxt->inputTab = (htmlParserInputPtr *) xmlMalloc(5 * sizeof(htmlParserInputPtr));
  if (ctxt->inputTab == NULL) {
    logger_log_error(worker->logger, "htmlInitParserCtxt: out of memory\n");
    ctxt->inputNr = 0;
    ctxt->inputMax = 0;
    ctxt->input = NULL;
    return(-1);
  }
  ctxt->inputNr = 0;
  ctxt->inputMax = 5;
  ctxt->input = NULL;
  ctxt->version = NULL;
  ctxt->encoding = NULL;
  ctxt->standalone = -1;
  ctxt->instate = XML_PARSER_START;

  ctxt->nodeTab = (htmlNodePtr *) xmlMalloc(10 * sizeof(htmlNodePtr));
  if (ctxt->nodeTab == NULL) {
    logger_log_error(worker->logger, "htmlInitParserCtxt: out of memory\n");
    ctxt->nodeNr = 0;
    ctxt->nodeMax = 0;
    ctxt->node = NULL;
    ctxt->inputNr = 0;
    ctxt->inputMax = 0;
    ctxt->input = NULL;
    return(-1);
  }
  ctxt->nodeNr = 0;
  ctxt->nodeMax = 10;
  ctxt->node = NULL;

  ctxt->nameTab = (const xmlChar **) xmlMalloc(10 * sizeof(xmlChar *));
  if (ctxt->nameTab == NULL) {
    logger_log_error(worker->logger, "htmlInitParserCtxt: out of memory\n");
    ctxt->nameNr = 0;
    ctxt->nameMax = 10;
    ctxt->name = NULL;
    ctxt->nodeNr = 0;
    ctxt->nodeMax = 0;
    ctxt->node = NULL;
    ctxt->inputNr = 0;
    ctxt->inputMax = 0;
    ctxt->input = NULL;
    return(-1);
  }
  ctxt->nameNr = 0;
  ctxt->nameMax = 10;
  ctxt->name = NULL;
    
  if (sax == NULL) ctxt->sax = (xmlSAXHandlerPtr) &htmlDefaultSAXHandler;
  else {
    ctxt->sax = sax;
    memcpy(sax, &htmlDefaultSAXHandler, sizeof(xmlSAXHandlerV1));
  }
  ctxt->userData = ctxt;
  ctxt->myDoc = NULL;
  ctxt->wellFormed = 1;
  ctxt->replaceEntities = 0;
  ctxt->linenumbers = xmlLineNumbersDefaultValue;
  ctxt->html = 1;
  ctxt->vctxt.finishDtd = XML_CTXT_FINISH_DTD_0;
  ctxt->vctxt.userData = ctxt;
  ctxt->vctxt.error = xmlParserValidityError;
  ctxt->vctxt.warning = xmlParserValidityWarning;
  ctxt->record_info = 0;
  ctxt->validate = 0;
  ctxt->nbChars = 0;
  ctxt->checkIndex = 0;
  ctxt->catalogs = NULL;
  xmlInitNodeInfoSeq(&ctxt->node_seq);
  return(0);
}

static htmlParserCtxtPtr htmlNewParserCtxt(worker_t *worker)
{
  xmlParserCtxtPtr ctxt = (xmlParserCtxtPtr) xmlMalloc(sizeof(xmlParserCtxt));
  if (ctxt == NULL) {
    logger_log_error(worker->logger, "NewParserCtxt: out of memory\n");
    return(NULL);
  }
  memset(ctxt, 0, sizeof(xmlParserCtxt));
  if (htmlInitParserCtxt(worker,ctxt) < 0) {
    htmlFreeParserCtxt(ctxt);
   return(NULL);
  }
  return(ctxt);
}
#endif

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
#if LIBXML_VERSION < 20627
    config->parser_ctx = htmlNewParserCtxt(worker);
#else
    config->parser_ctx = htmlNewParserCtxt();
#endif
    module_set_config(worker->config, apr_pstrdup(worker->pbody, html_module), config);
  }
  return config;
}

/**
 * Convert an xpath object to string
 * @param worker IN callee
 * @param obj IN xpath object
 * @param pool IN pool
 * @return result or NULL
 */
static char *html_node2str(worker_t *worker, xmlXPathObjectPtr obj,
                           apr_pool_t *pool) {
  char *result = NULL;

  switch (obj->type) {
    case XPATH_NODESET:
      if (!xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
        int i;
        xmlBufferPtr buf =  xmlBufferCreate();
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
          if (i != 0 ) {
            xmlBufferWriteChar(buf, "\n");
          }
          xmlNodeDump(buf, NULL, obj->nodesetval->nodeTab[i], 1, 0);
        }
        result = apr_pstrdup(pool, (char *)xmlBufferContent(buf));
        xmlBufferFree(buf);
      } 
      else {
        logger_log_error(worker->logger, "Empty node set");
        result = NULL;
      }
      break;
    case XPATH_BOOLEAN:
      result = apr_psprintf(pool, "%s", obj->boolval?"true":"false");
      break;
    case XPATH_NUMBER:
      result = apr_psprintf(pool, "%0g", obj->floatval);
      break;
    case XPATH_STRING:
      result = apr_psprintf(pool, "%s", obj->stringval);
      break;
    default:
      logger_log_error(worker->logger, "Unknown node type");
      break;
  }

  return result;
}

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Parse HTML block
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return apr status
 */
static apr_status_t block_HTML_PARSE(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *param;
  const char *html;

  html_wconf_t *wconf = html_get_worker_config(worker);

  param = store_get(worker->params, "1");
  if (!param) {
    logger_log_error(worker->logger, "Need a html document as parameter");
    return APR_EINVAL;
  }
  html = worker_get_value_from_param(worker, param, ptmp);

  wconf->doc = htmlCtxtReadDoc(wconf->parser_ctx, (xmlChar *)html, NULL, NULL, 0);
  if (!wconf->doc) {
    logger_log_error(worker->logger, "Could not parse HTML");
    return APR_EINVAL;
  }
  wconf->xpath = xmlXPathNewContext(wconf->doc);
  
  return APR_SUCCESS;
}

/**
 * Xpath query on a parsed HTML block
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return apr status
 */
static apr_status_t block_HTML_XPATH(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *param;
  const char *var;
  char *val;
  xmlXPathObjectPtr obj; 

  html_wconf_t *wconf = html_get_worker_config(worker);

  param = store_get(worker->params, "1");
  if (!param) {
    logger_log_error(worker->logger, "Need a xpath query");
    return APR_EINVAL;
  }

  var = store_get(worker->params, "2");
  if (!var) {
    logger_log_error(worker->logger, "Need a variable to store the result");
    return APR_EINVAL;
  }

  if (!wconf->xpath) {
    logger_log_error(worker->logger, "Do _HTML:PARSE first");
    return APR_EGENERAL;
  }
  
  if ((obj = xmlXPathEval((xmlChar *) param, wconf->xpath)) == NULL) {
    logger_log_error(worker->logger, "Xpath error");
    return APR_EGENERAL;
  }
  val = html_node2str(worker, obj, ptmp);
  if (!val) {
    return APR_ENOENT;
  }
  worker_var_set(parent, var, val);

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
  if ((status = module_command_new(global, "HTML", "_XPATH",
	                           "<query>",
	                           "Return requested object",
	                           block_HTML_XPATH)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

