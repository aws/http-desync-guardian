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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "http_desync_guardian.h"
#include "defs.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"

void analyze_raw_request()
{
    http_desync_guardian_verdict_t verdict = {0};

    const char request[] =
            "PUT / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Content-Length: 10\r\n"
            "Transfer-Encoding: chunked\r\n"
            "\r\n";

    http_desync_guardian_analyze_raw_request(sizeof(request), request, &verdict);

    switch (verdict.tier) {
        case REQUEST_SAFETY_TIER_COMPLIANT:
            // the request is good. green light
            printf("Request is OK\n");
            break;
        case REQUEST_SAFETY_TIER_ACCEPTABLE:
            // the request is acceptable, as Transfer-Encoding and Content-Length are good. green light
            printf("Request is OK-ish\n");
            break;
        case REQUEST_SAFETY_TIER_AMBIGUOUS:
            // the request is suspicious. you can send it, but close both FE/BE connections immediately
            printf("Request is Ambiguous: %.*s\n", verdict.message_length, verdict.message_data);
            break;
        case REQUEST_SAFETY_TIER_SEVERE:
            // send 400 and close the connection
            printf("Request is BAD: %.*s\n", verdict.message_length, verdict.message_data);
            break;
        default:
            // an integration bug
            abort();
    }
}

int main()
{
    analyze_raw_request();
    return HDG_OK;
}

#pragma clang diagnostic pop