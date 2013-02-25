/**
 * Copyright 2010 Rafael Torres
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
 * @Author rafael torres rdtorres@gmail.com
 *
 * Implementation of the HTTP Test Tool xml module. Based on the html module 
 */

/************************************************************************
 * Includes
 ***********************************************************************/
#include "module.h"
#include "libxml/parser.h"
#include "libxml/xpath.h"
#include "libxml/tree.h"

/************************************************************************
 * Definitions 
 ***********************************************************************/
typedef struct xml_wconf_s {
  xmlParserCtxtPtr parser_ctx;
  xmlDocPtr doc;
  xmlXPathContextPtr xpath;
} xml_wconf_t;

/************************************************************************
 * Globals 
 ***********************************************************************/
const char * xml_module = "xml_module";

/************************************************************************
 * Local 
 ***********************************************************************/
/**
 * Get xml config from worker
 *
 * @param worker IN worker
 * @return xml config
 */
static xml_wconf_t *xml_get_worker_config(worker_t *worker) {
  xml_wconf_t *config = module_get_config(worker->config, xml_module);
  if (config == NULL) {
    config = apr_pcalloc(worker->pbody, sizeof(*config));
    config->parser_ctx = xmlNewParserCtxt();
    module_set_config(worker->config, apr_pstrdup(worker->pbody, xml_module), config);
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
static char *xml_node2str(worker_t *worker, xmlXPathObjectPtr obj,
                           apr_pool_t *pool) {
  char *result = NULL;

  switch (obj->type) {
    case XPATH_NODESET:
      if (!xmlXPathNodeSetIsEmpty(obj->nodesetval)) {
        int i;
        xmlChar* content;
        xmlBufferPtr buf =  xmlBufferCreate();
        for (i = 0; i < obj->nodesetval->nodeNr; i++) {
          if (i != 0 ) {
            xmlBufferWriteChar(buf, "\n");
          }
          content = xmlNodeGetContent(obj->nodesetval->nodeTab[i]);  
          xmlBufferWriteChar(buf, (const char *)content);
          xmlFree(content);
        }
        result = apr_pstrdup(pool, (char *)xmlBufferContent(buf));
        xmlBufferFree(buf);
      } 
      else {
        worker_log_error(worker, "Empty node set");
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
      worker_log_error(worker, "Unknown node type");
      break;
  }

  return result;
}

/************************************************************************
 * Commands 
 ***********************************************************************/
/**
 * Parse XML block
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return apr status
 */
static apr_status_t block_XML_PARSE(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *param;
  const char *xml;

  xml_wconf_t *wconf = xml_get_worker_config(worker);

  param = store_get(worker->params, "1");
  if (!param) {
    worker_log_error(worker, "Need a xml document as parameter");
    return APR_EINVAL;
  }
  xml = worker_get_value_from_param(worker, param, ptmp);

  wconf->doc = xmlCtxtReadDoc(wconf->parser_ctx, (xmlChar *)xml, NULL, NULL, 0);
  if (!wconf->doc) {
    worker_log_error(worker, "Could not parse XML");
    return APR_EINVAL;
  }
  wconf->xpath = xmlXPathNewContext(wconf->doc);
  
  return APR_SUCCESS;
}

/**
 * Xpath query on a parsed XML block
 * @param worker IN callee
 * @param parent IN caller
 * @param ptmp IN temporary pool
 * @return apr status
 */
static apr_status_t block_XML_XPATH(worker_t *worker, worker_t *parent, apr_pool_t *ptmp) {
  const char *param;
  const char *var;
  char *val;
  xmlXPathObjectPtr obj; 

  xml_wconf_t *wconf = xml_get_worker_config(worker);

  param = store_get(worker->params, "1");
  if (!param) {
    worker_log_error(worker, "Need a xpath query");
    return APR_EINVAL;
  }

  var = store_get(worker->params, "2");
  if (!var) {
    worker_log_error(worker, "Need a variable to store the result");
    return APR_EINVAL;
  }

  if (!wconf->xpath) {
    worker_log_error(worker, "Do _XML:PARSE first");
    return APR_EGENERAL;
  }
  
  if ((obj = xmlXPathEvalExpression((xmlChar *) param, wconf->xpath)) == NULL) {
    worker_log_error(worker, "Xpath error");
    return APR_EGENERAL;
  }
  val = xml_node2str(worker, obj, ptmp);
  if (!val) {
    return APR_ENOENT;
  }
  worker_var_set(parent, var, val);

  return APR_SUCCESS;
}
/************************************************************************
 * Module
 ***********************************************************************/
apr_status_t xml_module_init(global_t *global) {
  apr_status_t status;
  if ((status = module_command_new(global, "XML", "_PARSE",
	                           "<xml>",
	                           "Parse XML",
	                           block_XML_PARSE)) != APR_SUCCESS) {
    return status;
  }
  if ((status = module_command_new(global, "XML", "_XPATH",
	                           "<query>",
	                           "Return requested object",
	                           block_XML_XPATH)) != APR_SUCCESS) {
    return status;
  }

  return APR_SUCCESS;
}

