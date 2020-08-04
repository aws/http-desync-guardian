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

#ifndef _HTTP_DESYNC_GUARDIAN_DETECT_NGINX_MODULE_H
#define _HTTP_DESYNC_GUARDIAN_DETECT_NGINX_MODULE_H

#include "http_desync_guardian.h"

extern ngx_module_t http_desync_guardian_detect_module;

typedef struct {
    ngx_flag_t http_desync_guardian_detect_enabled;
} http_desync_guardian_detect_conf_t;

typedef struct {
    http_desync_guardian_request_safety_tier_t   classify_tier;
    http_desync_guardian_classification_reason_t classify_reason;
} http_desync_guardian_detect_ctx_t;

const ngx_str_t *http_desync_guardian_get_classify_reason_str(
        http_desync_guardian_classification_reason_t classify_reason);

#endif //_HTTP_DESYNC_GUARDIAN_DETECT_NGINX_MODULE_H
