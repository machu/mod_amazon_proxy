/* 
**  mod_amazon_proxy.c -- amazon auth proxy for PAAPI
**
**    #   httpd.conf
**    LoadModule amazon_proxy_module modules/mod_amazon_proxy.so
**    <Location /amazon_proxy/ja>
**    AmazonAccessKey your_access_key
**    AmazonSecretKey your_secret_key
**    AmazonDefaultAid your_associate_id (optional)
**    AmazonEndPoint amazon_endpoint (ex: webservices.amazon.co.jp)
**    SetHandler amazon_proxy
**    </Location>
**
**  Then after restarting Apache via
**
**    $ apachectl restart
**
*/ 

#include <openssl/hmac.h>

#include "apr_strings.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "ap_config.h"
#include <apreq2/apreq_param.h>

typedef struct {
    const char *access_key;
    const char *secret_key;
    const char *default_aid;
    const char *endpoint;
    const char *xslt_endpoint;
} amazon_proxy_dir_config;

module AP_MODULE_DECLARE_DATA amazon_proxy_module;

static char* sign(apr_pool_t *p, const char *key, const char *message)
{
    // sha256 returns 256bit (32byte) binary data.
    unsigned char hmac[32];
    unsigned int hmac_size;

    char *signature = apr_pcalloc(p, apr_base64_encode_len(32) + 1);
    if (HMAC(EVP_sha256(), (const void*)key, strlen(key), (const unsigned char*)message, strlen(message), hmac, &hmac_size) )
    {
        apr_base64_encode_binary(signature, hmac, hmac_size);
    }
    return signature;
}

static int compare_string(const void *a, const void *b)
{
    return strcmp(*(char *const *)a, *(char *const *)b);
}

static char* create_message(apr_pool_t *p, const char *url, const char *path, const char *query)
{
    return (char *)apr_pstrcat(p,
            "GET", "\n",
            url, "\n",
            path, "\n",
            query, NULL);
}

static char* create_timestamp(apr_pool_t *p)
{
    int ts_size = sizeof(char) * 21;
    char *timestamp = apr_pcalloc(p, ts_size);
    time_t tm = time(NULL);
    strftime(timestamp, ts_size, "%Y-%m-%dT%XZ", gmtime(&tm));

    return timestamp;
}

static char* url_encode(apr_pool_t *p, char *src)
{
    char *dest = apr_pcalloc(p, sizeof(char) * strlen(src) * 3 + 1);
    apreq_encode(dest, src, strlen(src));
    return dest;
}

static char* array_join(apr_pool_t *p, apr_array_header_t *array, char *delimiter)
{
    int i;
    char *query_string =  "";

    char **elts = (char **)array->elts;
    for (i = 0; i < array->nelts; i++) {
        query_string = (char *)apr_pstrcat(p, query_string, elts[i], delimiter, NULL);
    }
    // remove last delimiter
    if (strlen(query_string) > 0) {
        query_string[strlen(query_string) - 1] = '\0';
    }
    return query_string;
}

static apr_array_header_t* canonical(apr_pool_t *p, apr_table_t *param, const char *access_key, const char *aid)
{
    int i;
    apr_array_header_t *queries = apr_array_make(p, 10, sizeof(char *));

    const apr_array_header_t *headers = apr_table_elts(param);
    apr_table_entry_t *entries = (apr_table_entry_t *)headers->elts;
    for (i = 0; i < headers->nelts; i++) {
        char *key = entries[i].key;
        char *val = entries[i].val;
        if (strncmp(key, "AWSAccessKeyId", 14) == 0 || strncmp(key, "SubscriptionId", 14) == 0) {
            *(char **)apr_array_push(queries) = 
                (char *)apr_pstrcat(p, key, "=", url_encode(p, (char *)access_key), NULL);
        } else if (strncmp(key, "Timestamp", 9) == 0) {
            // ignore this key
        } else {
            *(char **)apr_array_push(queries) = 
                (char *)apr_pstrcat(p, url_encode(p, key), "=", url_encode(p, val), NULL);
        }
    }
    // add assticate tag
    if (!apr_table_get(param, "AssociateTag") && aid) {
        *(char **)apr_array_push(queries) =
            (char *)apr_pstrcat(p, "AssociateTag=", url_encode(p, (char *)aid), NULL);
    }
    // add timestamp
    *(char **)apr_array_push(queries) =
        (char *)apr_pstrcat(p, "Timestamp=", url_encode(p, create_timestamp(p)), NULL);

    return queries;
}

static int amazon_proxy_handler(request_rec *r)
{
    if (strcmp(r->handler, "amazon_proxy")) {
        return DECLINED;
    }
    // r->content_type = "text/plain";

    amazon_proxy_dir_config *conf = ap_get_module_config(r->per_dir_config, &amazon_proxy_module);
    const char *access_key = conf->access_key;
    const char *secret_key = conf->secret_key;
    const char *default_aid = conf->default_aid;
    const char *api_host = conf->endpoint;
    const char *xslt_host = conf->xslt_endpoint;

    // validate httpd.conf
    if (!access_key) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "not found AmazonAccessKey in httpd.conf");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!secret_key) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "not found AmazonSecretKey in httpd.conf");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!api_host) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "not found AmazonEndPoint in httpd.conf");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    if (!xslt_host) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "not found AmazonXsltEndPoint in httpd.conf");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_table_t *param = apr_table_make(r->pool, 16);
    apreq_parse_query_string(r->pool, param, (r->args)?r->args:"");

    // canonical params
    apr_array_header_t *params = canonical(r->pool, param, conf->access_key, conf->default_aid);
    qsort(params->elts, params->nelts, sizeof(char *), compare_string);

    // create message and sign
    char *query = array_join(r->pool, params, "&");
    char *path = "/onca/xml";
    const char *host = (strlen(apreq_params_as_string(r->pool, param, "Style", APREQ_JOIN_AS_IS)) == 0) ?
        api_host : xslt_host;
    char *message = create_message(r->pool, host, path, query);
    char *signature = sign(r->pool, conf->secret_key, message);
    query = (char *)apr_pstrcat(r->pool, query, "&Signature=", url_encode(r->pool, signature), NULL);

    // create redirect url
    char *url = (char *)apr_pstrcat(r->pool, "http://", host, path, "?", query, NULL);
    apr_table_setn(r->headers_out, "Location", url);
    return HTTP_MOVED_TEMPORARILY;
}

static void *create_dir_amazon_proxy_config(apr_pool_t *p, char *dummy)
{
    amazon_proxy_dir_config *dir_config = 
        (amazon_proxy_dir_config *)apr_pcalloc(p, sizeof(amazon_proxy_dir_config));
    dir_config->access_key = NULL;
    dir_config->secret_key = NULL;
    dir_config->default_aid = NULL;
    dir_config->endpoint = NULL;
    dir_config->xslt_endpoint = NULL;

    return (void *)dir_config;
}

static const char *set_amazonaccesskey(cmd_parms *cmd, void *in_dir_config, const char *access_key)
{
    amazon_proxy_dir_config *dir_config = in_dir_config;
    dir_config->access_key = access_key;
    return NULL;
}

static const char *set_amazonsecretkey(cmd_parms *cmd, void *in_dir_config, const char *secret_key)
{
    amazon_proxy_dir_config *dir_config = in_dir_config;
    dir_config->secret_key = secret_key;
    return NULL;
}

static const char *set_amazondefaultaid(cmd_parms *cmd, void *in_dir_config, const char *default_aid)
{
    amazon_proxy_dir_config *dir_config = in_dir_config;
    dir_config->default_aid = default_aid;
    return NULL;
}

static const char *set_amazonendpoint(cmd_parms *cmd, void *in_dir_config, const char *endpoint)
{
    amazon_proxy_dir_config *dir_config = in_dir_config;
    dir_config->endpoint = endpoint;
    return NULL;
}

static const char *set_amazonxsltendpoint(cmd_parms *cmd, void *in_dir_config, const char *xslt_endpoint)
{
    amazon_proxy_dir_config *dir_config = in_dir_config;
    dir_config->xslt_endpoint = xslt_endpoint;
    return NULL;
}

static const command_rec amazon_proxy_cmds[] =
{
    AP_INIT_TAKE1("AmazonAccessKey", set_amazonaccesskey, NULL, OR_LIMIT, "your access key for amazon api"),
    AP_INIT_TAKE1("AmazonSecretKey", set_amazonsecretkey, NULL, OR_LIMIT, "your secret key for amazon api"),
    AP_INIT_TAKE1("AmazonDefaultAid", set_amazondefaultaid, NULL, OR_LIMIT, "your aid if you want"),
    AP_INIT_TAKE1("AmazonEndPoint", set_amazonendpoint, NULL, OR_LIMIT, "amazon api end point"),
    AP_INIT_TAKE1("AmazonXsltEndPoint", set_amazonxsltendpoint, NULL, OR_LIMIT, "amazon xslt end point"),
    { NULL }
};

static void amazon_proxy_register_hooks(apr_pool_t *p)
{
    ap_hook_handler(amazon_proxy_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Dispatch list for API hooks */
module AP_MODULE_DECLARE_DATA amazon_proxy_module = {
    STANDARD20_MODULE_STUFF, 
    create_dir_amazon_proxy_config, /* create per-dir    config structures */
    NULL,                  /* merge  per-dir    config structures */
    NULL,                  /* create per-server config structures */
    NULL,                  /* merge  per-server config structures */
    amazon_proxy_cmds,              /* table of config file commands       */
    amazon_proxy_register_hooks  /* register hooks                      */
};

