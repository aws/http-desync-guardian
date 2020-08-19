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
#include <time.h>
#include "defs.h"
#include "http_desync_guardian.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"

const bool client_prefers_to_send_ambiguous_requests = true;
const bool client_prefers_to_debug_request_data = true;

const http_desync_guardian_string_t PUT = HDG_STRING("PUT");
const http_desync_guardian_string_t HTTP1_1 = HDG_STRING("HTTP/1.1");
const http_desync_guardian_string_t URI = HDG_STRING("/foo/bar");

void check_headers(http_desync_guardian_request_t *request_data);

void analyze_request(http_desync_guardian_request_t *request_data)
{
    http_desync_guardian_verdict_t verdict = {0};
    http_desync_guardian_analyze_request(request_data, &verdict);

    if (verdict.tier > REQUEST_SAFETY_TIER_COMPLIANT && client_prefers_to_debug_request_data) {
        char buffer[4096];
        int request_data_length = http_desync_guardian_print_request(request_data, sizeof(buffer), buffer);
        printf("Non-compliant request:\n%.*s\n", request_data_length, buffer);
    }

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
            if (client_prefers_to_send_ambiguous_requests) {
                check_headers(request_data);
            }
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

/* Demo callback for logging. */
void log_message(http_desync_guardian_request_safety_tier_t tier, uint32_t len, const uint8_t *msg)
{
    if (tier >= REQUEST_SAFETY_TIER_AMBIGUOUS) {
        // call apps' log. e.g. LOGGER(WARN, "%.*s", len, msg);
    }
}

/* Demo callback for metrics. */
void log_metrics(uint32_t len, const uint8_t *msg)
{
    // report to the existing metrics engine
    // e.g. append_to_metrics_file(len, msg);
}

/* Demo callback for granular tier metrics. */
void log_tier_metrics(uint32_t len, const http_desync_guardian_tier_count_t *tier_metrics_list)
{
    // report to the existing metrics engine
    // e.g. append_to_metrics_file(len, msg);
    // Extract the metrics from the struct
    for (int i = 0; i < len; i++) {
        time_t current_time = time(NULL);

        char tier[15];
        switch (tier_metrics_list[i].counter_type) {
            case REQUEST_SAFETY_TIER_COMPLIANT:
                // the request is good. green light
                strcpy(tier, "Compliant");
                break;
            case REQUEST_SAFETY_TIER_ACCEPTABLE:
                // the request is acceptable, as Transfer-Encoding and Content-Length are good. green light
                strcpy(tier, "Acceptable");
                break;
            case REQUEST_SAFETY_TIER_AMBIGUOUS:
                // the request is suspicious. you can send it, but close both FE/BE connections immediately
                strcpy(tier, "Ambiguous");
                break;
            case REQUEST_SAFETY_TIER_SEVERE:
                // send 400 and close the connection
                strcpy(tier, "Severe");
                break;
            default:
                // an integration bug
                abort();
        }
        printf("[%ld] Method: \"%.*s\", Type: %s, Count: %d\n",
               current_time,
               tier_metrics_list[i].method.length,
               tier_metrics_list[i].method.data_ptr,
               tier,
               tier_metrics_list[i].count);
    }
}

/*
 * This is optional.
 * The library limits logs to 100 messages per second
 * and reports metrics every 10 seconds.
 * However, your app can use existing mechanisms, just follow the metrics format.
 * */
void initialize_http_desync_guardian()
{
    // initialize granular tier metrics first
    http_desync_guardian_tier_metrics_settings_t tier_metrics_settings = {
            .period_seconds = 10,
            .callback = log_tier_metrics
    };
    http_desync_guardian_register_tier_metrics_callback(&tier_metrics_settings);

    // initialize logger
    http_desync_guardian_logging_settings_t logging_settings = {
            .callback = log_message
    };
    http_desync_guardian_initialize_logging_settings(&logging_settings);
}

void check_headers(http_desync_guardian_request_t *request_data)
{// If the request is not compliant, but chosen to be sent downstream.
    for (int i = 0; i < request_data->headers.count; i++) {
        http_desync_guardian_header_safety_tier_t header_tier = request_data->headers.pairs[i].compliant;
        switch (header_tier) {
            case HEADER_SAFETY_TIER_COMPLIANT:
                // Green light.
                break;
            case HEADER_SAFETY_TIER_NON_COMPLIANT:
                // The header is not RFC compliant.
                // Should be deleted if the customer chose STRICT mode.
                // Yellow light.
                printf("Warning header \"%.*s\": \"%.*s\"\n",
                       request_data->headers.pairs[i].name.length,
                       request_data->headers.pairs[i].name.data_ptr,
                       request_data->headers.pairs[i].value.length,
                       request_data->headers.pairs[i].value.data_ptr);
                break;
            case HEADER_SAFETY_TIER_BAD:
                // The header must be deleted.
                // Read light.
                printf("(!) Remove header \"%.*s\": \"%.*s\"\n",
                       request_data->headers.pairs[i].name.length,
                       request_data->headers.pairs[i].name.data_ptr,
                       request_data->headers.pairs[i].value.length,
                       request_data->headers.pairs[i].value.data_ptr);
                break;
            default:
                // an integration bug
                abort();
        }
    }
}

int construct_http_desync_guardian_request(http_desync_guardian_request_t *request_data)
{
    request_data->method = PUT;
    request_data->version = HTTP1_1;
    request_data->uri = URI;

    static http_desync_guardian_string_t empty_string = {.length = 0, .data_ptr = NULL};

    http_desync_guardian_http_header_t headers[] = {
            {
                    .name = HDG_STRING("Accept-Language"),
                    .value = HDG_STRING(" en-US,en;q=0.9,ru;q=0.8"),
            },
            {
                    .name = HDG_STRING("Cache-Control"),
                    .value = HDG_STRING(" max-age=0"),
            },
            {
                    .name = HDG_STRING("Connection"),
                    .value = HDG_STRING(" keep-alive"),
            },
            {
                    .name = HDG_STRING("Host"),
                    .value = HDG_STRING(" d23y7p7aql5sme.cloudfront.net"),
            },
            {
                    .name = HDG_STRING("User-Agent"),
                    .value = HDG_STRING(
                            " Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.130 Safari/537.36"),
            },
            // you can mess around with the headers below, to cause different classification outcomes
            {
                    .name = HDG_STRING("Transfer-Encoding"),
                    .value = HDG_STRING("chunked"),
            },
            {
                    .name = HDG_STRING("Content-Length"),
                    .value = HDG_STRING("1000"),
            },
            {
                    .name = HDG_STRING("X-Empty-Header"),
                    .value = empty_string,
            },
    };

    request_data->headers.count = sizeof(headers) / sizeof(http_desync_guardian_http_header_t);
    request_data->headers.pairs = malloc(sizeof(headers));
    GUARD_PTR(request_data->headers.pairs)
    memcpy(request_data->headers.pairs, headers, sizeof(headers));

    return HDG_OK;
}


int main()
{
    // initialize the library
    initialize_http_desync_guardian();

    http_desync_guardian_request_t request_data = {0};
    GUARD(construct_http_desync_guardian_request(&request_data))

    analyze_request(&request_data);
    free(request_data.headers.pairs);

    return HDG_OK;
}

#pragma clang diagnostic pop