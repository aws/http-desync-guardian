/*
* Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include <ngx_http.h>
#include "http_desync_guardian_detect_module.h"

#define HDG_ARRAY_SIZE(a) (sizeof((a)) / sizeof((a)[0]))

typedef struct {
    int enum_value;
    ngx_str_t str_value;
} http_desync_guardian_detect_enum_mapping_t;

enum {
    // http_desync_guardian classification tier
    http_desync_guardian_detect_var_tier,

    // http_desync_guardian classification reason
    http_desync_guardian_detect_var_reason,
} http_desync_guardian_detect_var_type_e;

// callback definition to iterate over http headers
typedef struct {
    ngx_int_t index;
    void *data;
} http_desync_guardian_detect_header_cb_data_t;

typedef ngx_int_t (*http_desync_guardian_detect_header_callback_fn)(const ngx_table_elt_t *h,
                                                                    http_desync_guardian_detect_header_cb_data_t *data);

static ngx_int_t http_desync_guardian_detect_add_variables(ngx_conf_t *cf);

static ngx_int_t http_desync_guardian_detect_variable_handler(ngx_http_request_t *r,
                                                              ngx_http_variable_value_t *v,
                                                              uintptr_t data);

static void *http_desync_guardian_detect_create_conf(ngx_conf_t *cf);

static char *http_desync_guardian_detect_merge_conf(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t http_desync_guardian_detect_init(ngx_conf_t *);

static ngx_int_t http_desync_guardian_detect_handler(ngx_http_request_t *);

static ngx_int_t http_desync_guardian_detect_construct_request(http_desync_guardian_request_t *,
                                                               ngx_http_request_t *);

http_desync_guardian_detect_enum_mapping_t http_desync_guardian_detect_tier_str[] = {
        {
                .enum_value = REQUEST_SAFETY_TIER_COMPLIANT,
                .str_value  = ngx_null_string,  //'-' for Compliant
        },
        {
                .enum_value = REQUEST_SAFETY_TIER_ACCEPTABLE,
                .str_value  = ngx_string("Acceptable"),
        },
        {
                .enum_value = REQUEST_SAFETY_TIER_AMBIGUOUS,
                .str_value  = ngx_string("Ambiguous"),
        },
        {
                .enum_value = REQUEST_SAFETY_TIER_SEVERE,
                .str_value  = ngx_string("Severe"),
        }
};

http_desync_guardian_detect_enum_mapping_t http_desync_guardian_detect_reason_str[] = {
        /* Initial value */
        {
                .enum_value = CLASSIFICATION_REASON_COMPLIANT,
                .str_value  = ngx_null_string, // '-' for Compliant
        },
        /* Header specific reason */
        {
                .enum_value = CLASSIFICATION_REASON_EMPTY_HEADER,
                .str_value  = ngx_string("EmptyHeader"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_SUSPICIOUS_HEADER,
                .str_value  = ngx_string("SuspiciousHeader"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_NON_COMPLIANT_HEADER,
                .str_value  = ngx_string("NonCompliantHeader"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_BAD_HEADER,
                .str_value  = ngx_string("BadHeader"),
        },
        /* URI specific reasons */
        {
                .enum_value = CLASSIFICATION_REASON_AMBIGUOUS_URI,
                .str_value  = ngx_string("AmbiguousUri"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_SPACE_IN_URI,
                .str_value  = ngx_string("SpaceInUri"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_BAD_URI,
                .str_value  = ngx_string("BadUri"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_NON_COMPLIANT_VERSION,
                .str_value  = ngx_string("NonCompliantVersion"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_BAD_VERSION,
                .str_value  = ngx_string("BadVersion"),
        },
        /* Content Length specific reasons */
        {
                .enum_value = CLASSIFICATION_REASON_GET_HEAD_ZERO_CONTENT_LENGTH,
                .str_value  = ngx_string("GetHeadZeroContentLength"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_UNDEFINED_CONTENT_LENGTH_SEMANTICS,
                .str_value  = ngx_string("UndefinedContentLengthSemantics"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_MULTIPLE_CONTENT_LENGTH,
                .str_value  = ngx_string("MultipleContentLength"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_DUPLICATE_CONTENT_LENGTH,
                .str_value  = ngx_string("DuplicateContentLength"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_BAD_CONTENT_LENGTH,
                .str_value  = ngx_string("BadContentLength"),
        },
        /* Transfer Encoding specific reasons */
        {
                .enum_value = CLASSIFICATION_REASON_UNDEFINED_TRANSFER_ENCODING_SEMANTICS,
                .str_value  = ngx_string("UndefinedTransferEncodingSemantics"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_MULTIPLE_TRANSFER_ENCODING_CHUNKED,
                .str_value  = ngx_string("MultipleTransferEncodingChunked"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_BAD_TRANSFER_ENCODING,
                .str_value  = ngx_string("BadTransferEncoding"),
        },
        /* Both Transfer Encoding and Content Length present */
        {
                .enum_value = CLASSIFICATION_REASON_BOTH_TE_CL_PRESENT,
                .str_value  = ngx_string("BothTeClPresent"),
        },
        /* Http Method related */
        {
                .enum_value = CLASSIFICATION_REASON_BAD_METHOD,
                .str_value  = ngx_string("BadMethod"),
        },
        /* Request parsing issues */
        {
                .enum_value = CLASSIFICATION_REASON_NON_CR_LF_LINE_TERMINATION,
                .str_value  = ngx_string("NonCrLfLineTermination"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_MULTILINE_HEADER,
                .str_value  = ngx_string("MultilineHeader"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_PARTIAL_HEADER_LINE,
                .str_value  = ngx_string("PartialHeaderLine"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_MISSING_LAST_EMPTY_LINE,
                .str_value  = ngx_string("MissingLastEmptyLine"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_MISSING_HEADER_COLON,
                .str_value  = ngx_string("MissingHeaderColon"),
        },
        {
                .enum_value = CLASSIFICATION_REASON_MISSING_URI,
                .str_value  = ngx_string("MissingUri"),
        },
};

static ngx_command_t http_desync_guardian_detect_commands[] = {
        {ngx_string("http_desync_guardian_detect_enable"),
         NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_FLAG,
         ngx_conf_set_flag_slot,
         NGX_HTTP_LOC_CONF_OFFSET,
         offsetof(http_desync_guardian_detect_conf_t, http_desync_guardian_detect_enabled),
         NULL},

        ngx_null_command
};

static ngx_http_module_t http_desync_guardian_detect_module_ctx = {
        http_desync_guardian_detect_add_variables,     /* preconfiguration */
        http_desync_guardian_detect_init,              /* postconfiguration */
        NULL,                                   /* create main configuration */
        NULL,                                   /* init main */
        NULL,                                   /* create server configuration */
        NULL,                                   /* merge server configuration */
        http_desync_guardian_detect_create_conf,       /* create location configuration */
        http_desync_guardian_detect_merge_conf         /* merge location configuration */
};

ngx_module_t http_desync_guardian_detect_module = {
        NGX_MODULE_V1,
        &http_desync_guardian_detect_module_ctx,       /* module context */
        http_desync_guardian_detect_commands,          /* module directives */
        NGX_HTTP_MODULE,                        /* module type */
        NULL,                                   /* init master */
        NULL,                                   /* init module */
        NULL,                                   /* init process */
        NULL,                                   /* init thread */
        NULL,                                   /* exit thread */
        NULL,                                   /* exit process */
        NULL,                                   /* exit master */
        NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t http_desync_guardian_detect_vars[] = {
        {ngx_string("http_desync_guardian_tier"),   NULL,
                                                          http_desync_guardian_detect_variable_handler,
                                                                http_desync_guardian_detect_var_tier,   NGX_HTTP_VAR_NOCACHEABLE, 0},

        {ngx_string("http_desync_guardian_reason"), NULL,
                                                          http_desync_guardian_detect_variable_handler,
                                                                http_desync_guardian_detect_var_reason, NGX_HTTP_VAR_NOCACHEABLE, 0},

        {ngx_null_string,                           NULL, NULL, 0,                                      0,                        0}
};

static ngx_int_t
http_desync_guardian_detect_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *v;
    for (v = http_desync_guardian_detect_vars; v->name.len; v++) {
        ngx_http_variable_t *var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!var) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
http_desync_guardian_detect_variable_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    http_desync_guardian_detect_ctx_t *ctx = ngx_http_get_module_ctx(r->main, http_desync_guardian_detect_module);
    if (!ctx) {
        // Ignore if http_desync_guardian_detect disabled or request failed during parsing headers
        return NGX_ERROR;
    }

    ngx_str_t *var = NULL;
    switch (data) {
        case http_desync_guardian_detect_var_tier:
            var = &http_desync_guardian_detect_tier_str[ctx->classify_tier].str_value;
            break;
        case http_desync_guardian_detect_var_reason:
            var = &http_desync_guardian_detect_reason_str[ctx->classify_reason].str_value;
            break;
        default:
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0,
                          __func__ " http desync guardian variable %d is not recognizable",
                          data);
            break;
    }

    if (var && var->data) {
        v->data = var->data;
        v->len = var->len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    } else {
        v->data = NULL;
        v->len = 0;
        v->valid = 0;
        v->no_cacheable = 1;
        v->not_found = 1;
    }

    return NGX_OK;
}

static void *http_desync_guardian_detect_create_conf(ngx_conf_t *cf)
{
    http_desync_guardian_detect_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(http_desync_guardian_detect_conf_t));
    if (!conf) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      __func__ ": Failed to allocate memory for configuration.");
        return NULL;
    }

    conf->http_desync_guardian_detect_enabled = NGX_CONF_UNSET;

    return conf;

}

static char *http_desync_guardian_detect_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    http_desync_guardian_detect_conf_t *prev = parent;
    http_desync_guardian_detect_conf_t *conf = child;

    ngx_conf_merge_value(conf->http_desync_guardian_detect_enabled, prev->http_desync_guardian_detect_enabled, 1);

    return NGX_CONF_OK;
}


const ngx_str_t *
http_desync_guardian_get_classify_reason_str(http_desync_guardian_classification_reason_t classify_reason)
{
    if (classify_reason < 0 || classify_reason >= HDG_ARRAY_SIZE(http_desync_guardian_detect_reason_str)) {
        return NULL;
    }

    return &http_desync_guardian_detect_reason_str[classify_reason].str_value;
}

static ngx_int_t http_desync_guardian_validate_tier_and_reason_enums(ngx_conf_t *cf)
{
    /**
     * Make sure the http_desync_guardian enums are in sync with the module definitions.
     */
    if (HDG_ARRAY_SIZE(http_desync_guardian_detect_tier_str) != REQUEST_SAFETY_TIER_SENTINEL) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                      __func__ " size of http_desync_guardian_detect_tier_str[%d] does not align with REQUEST_SAFETY_TIER_SENTINEL[%d], "
                      "check what changed in HttpDesyncGuardian src/lib.rs",
                      HDG_ARRAY_SIZE(http_desync_guardian_detect_tier_str), REQUEST_SAFETY_TIER_SENTINEL);
        return NGX_ERROR;
    }

    for (int i = 0; i < REQUEST_SAFETY_TIER_SENTINEL; i++) {
        if (i != http_desync_guardian_detect_tier_str[i].enum_value) {
            ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                          __func__ " http_desync_guardian_detect_tier_str[%d]=[%d] does not align with HttpDesyncGuardian, tier: %d",
                          i, http_desync_guardian_detect_tier_str[i].enum_value, i);
            return NGX_ERROR;
        }
    }

    if (HDG_ARRAY_SIZE(http_desync_guardian_detect_reason_str) != CLASSIFICATION_REASON_SENTINEL) {
        ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                      __func__ " sizeof http_desync_guardian_detect_reason_str[%d] does not align with CLASSIFICATION_REASON_SENTINEL[%d], "
                      "check what changed in HttpDesyncGuardian src/lib.rs",
                      HDG_ARRAY_SIZE(http_desync_guardian_detect_reason_str), CLASSIFICATION_REASON_SENTINEL);
        return NGX_ERROR;
    }

    for (int i = 0; i < CLASSIFICATION_REASON_SENTINEL; i++) {
        if (i != http_desync_guardian_detect_reason_str[i].enum_value) {
            ngx_log_error(NGX_LOG_CRIT, cf->log, 0,
                          "[%s] http_desync_guardian_detect_reason_str[%d]=[%d] does not align with HttpDesyncGuardian, reason: %d",
                          __func__, i, http_desync_guardian_detect_reason_str[i].enum_value, i);
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}

static ngx_int_t http_desync_guardian_detect_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    if (http_desync_guardian_validate_tier_and_reason_enums(cf) != NGX_OK) {
        return NGX_ERROR;
    }

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (h == NULL) {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0,
                      "[%s]: Could not associate handler to NGX_HTTP_POST_READ_PHASE",
                      __func__);
        return NGX_ERROR;
    }

    *h = http_desync_guardian_detect_handler;

    return NGX_OK;
}

static ngx_int_t http_desync_guardian_run_detector(ngx_http_request_t *r,
                                                   http_desync_guardian_detect_ctx_t *ctx)
{
    http_desync_guardian_request_t gr = {0};
    http_desync_guardian_verdict_t verdict = {0};

    if (http_desync_guardian_detect_construct_request(&gr, r) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "[%s] Failed to populate http desync guardian request", __func__);
        return NGX_ERROR;
    }

    http_desync_guardian_analyze_request(&gr, &verdict);

    ctx->classify_tier = verdict.tier;
    ctx->classify_reason = verdict.reason;
    return NGX_DECLINED;
}

/**
 * HTTP Guardian handler to detect invalid requests
 */
static ngx_int_t http_desync_guardian_detect_handler(ngx_http_request_t *r)
{
    http_desync_guardian_detect_conf_t *conf;
    http_desync_guardian_detect_ctx_t *ctx;
    ngx_connection_t *c = r->connection;

    /**
     * Flag to enable/disable http_desync_guardian_detect_module
     */
    conf = ngx_http_get_module_loc_conf(r, http_desync_guardian_detect_module);
    if (!conf->http_desync_guardian_detect_enabled) {
        return NGX_DECLINED;
    }

    /**
     * Ignore if the request is an internal request or a subrequest.
     */
    if (r->internal || r->parent || r != r->main) {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, http_desync_guardian_detect_module);
    if (!ctx) {
        ctx = ngx_pcalloc(r->pool, sizeof(http_desync_guardian_detect_ctx_t));
        if (!ctx) {
            ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                          "[%s]: Allocate memory failed for context.", __func__);
            return NGX_ERROR;
        }

        ngx_http_set_ctx(r, ctx, http_desync_guardian_detect_module);
    }

    return http_desync_guardian_run_detector(r, ctx);
}

static ngx_int_t http_desync_guardian_detect_add_header(const ngx_table_elt_t *h,
                                                        http_desync_guardian_detect_header_cb_data_t *cb_data)
{
    http_desync_guardian_http_header_t *hg_all_headers = (http_desync_guardian_http_header_t *) cb_data->data;
    http_desync_guardian_http_header_t *hg_header = &hg_all_headers[cb_data->index];

    hg_header->name.length = h->key.len;
    hg_header->name.data_ptr = (int8_t *) h->key.data;
    hg_header->value.length = h->value.len;
    hg_header->value.data_ptr = (int8_t *) h->value.data;

    return NGX_OK;
}

void http_desync_guardian_detect_for_each_header(const ngx_list_part_t *part,
                                                 http_desync_guardian_detect_header_callback_fn cb,
                                                 http_desync_guardian_detect_header_cb_data_t *cb_data)
{
    ngx_uint_t i;
    ngx_table_elt_t *h = part->elts;

    cb_data->index = 0;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (cb && cb(&h[i], cb_data)) {
            return;
        }

        cb_data->index++;
    }
}

ngx_int_t
http_desync_guardian_detect_construct_request(http_desync_guardian_request_t *request_data, ngx_http_request_t *r)
{
    request_data->method.length = r->method_name.len;
    request_data->method.data_ptr = r->method_name.data;

    request_data->version.length = r->http_protocol.len;
    request_data->version.data_ptr = r->http_protocol.data;

    request_data->uri.length = r->unparsed_uri.len;
    request_data->uri.data_ptr = r->unparsed_uri.data;

    http_desync_guardian_detect_header_cb_data_t counter_data = {
            .index = 0,
            .data = NULL,
    };
    http_desync_guardian_detect_for_each_header(&r->headers_in.headers.part, NULL, &counter_data);

    size_t size = counter_data.index * sizeof(http_desync_guardian_http_header_t);

    request_data->headers.count = counter_data.index;
    request_data->headers.pairs = ngx_pcalloc(r->pool, size);
    if (request_data->headers.pairs == NULL) {
        ngx_log_error(NGX_LOG_CRIT, r->connection->log, 0,
                      "[%s] Failed to alloc memory for http desync guardian headers, size=%u",
                      __func__, size);
        return NGX_ERROR;
    }

    http_desync_guardian_detect_header_cb_data_t cb_data = {
            .index = 0,
            .data = request_data->headers.pairs,
    };
    http_desync_guardian_detect_for_each_header(&r->headers_in.headers.part,
                                                &http_desync_guardian_detect_add_header,
                                                &cb_data);

    return NGX_OK;
}
