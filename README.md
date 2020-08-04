![](docs/http-desync-guardian-logo.png)

[![Apache 2 License](https://img.shields.io/github/license/awslabs/s2n.svg)](http://aws.amazon.com/apache-2-0/)

Overview
========

`http_desync_guardian` library is designed to analyze HTTP requests to prevent HTTP Desync attacks.
It can be used to either for raw HTTP request headers or already parsed by an HTTP engine.
Consumers may configure logging and metrics collection.
Logging is rate limited and all user data is obfuscated. 

If you think you might have found a security impacting issue, please follow [our Security Notification Process.](#security-issue-notifications)

Priorities
=======

* **Uniformity across services is key.** This means request classification, logging, and metrics must happen under the hood and with minimally available settings (e.g., such as log file destination).
* **Focus on reviewability.** The test suite must require no knowledge about the library/programming languages but only about HTTP protocol. So it's easy to review, contribute, and re-use.
* **Security is efficient when it's easy for users.** Our goal is to make integration of the library as simple as possible.
* **Ultralight.** The overhead must be minimal and impose no tangible tax on request handling.

Supported HTTP versions
======

* `HTTP/0.9` - all traffic is classified as `Acceptable`.
* `HTTP/1.0` - the presence of `Transfer-Encoding` makes a request `Ambiguous`.
* `HTTP/1.1` - the main focus of this library (see [tests](./tests)).
* `HTTP/2`+ - out of scope. But if your proxy downgrades `HTTP/2` to `HTTP/1.1`, make sure the outgoing request is analyzed. 

See [documentation](./docs) to learn more.

Usage from C
=====

This library is designed to be primarily used from HTTP engines written in `C/C++`.  

Run `cargo build --release` and see generated `target/release/build/http_desync_guardian-*/out/http_desync_guardian.h`.

Learn more: [generic](./misc/demo-c) and [Nginx](./misc/demo-nginx) examples.

```c
#include "http_desync_guardian.h"

/* 
 * http_engine_request_t - already parsed by an HTTP engine 
 */
static int check_request(http_engine_request_t *req) {
    http_desync_guardian_request guardian_request = construct_http_desync_guardian_from(req); 
    http_desync_guardian_verdict verdict = {0};

    http_desync_guardian_analyze_request(&guardian_request, &verdict);

    switch (verdict.tier) {
        case REQUEST_SAFETY_TIER_COMPLIANT:
            // The request is good. green light
            break;
        case REQUEST_SAFETY_TIER_ACCEPTABLE:
            // Reject, if mode == STRICTEST
            // Otherwise, OK
            break;
        case REQUEST_SAFETY_TIER_AMBIGUOUS:
            // The request is ambiguous.
            // Reject, if mode == STRICTEST 
            // Otherwise send it, but don't reuse both FE/BE connections.
            break;
        case REQUEST_SAFETY_TIER_SEVERE:
            // Send 400 and close the FE connection.
            break;
        default:
            // unreachable code
            abort();
    }
}
```

Usage from Rust
====

See [benchmarks](./benches/benchmarks.rs) as an example of usage from Rust. 

## Security issue notifications
If you discover a potential security issue in `http_desync_gardian` we ask that you notify
AWS Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue. 

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This project is licensed under the [Apache-2.0 License](./LICENSE).