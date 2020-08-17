<img src="docs/http-desync-guardian-logo.png" width="200">

[![Apache 2 License](https://img.shields.io/github/license/awslabs/s2n.svg)](http://aws.amazon.com/apache-2-0/)
[![Crate](https://img.shields.io/crates/v/http_desync_guardian.svg)](https://crates.io/crates/http_desync_guardian)
![Clippy/Fmt](https://github.com/aws/http-desync-guardian/workflows/Clippy/Fmt/badge.svg)
![Tests](https://github.com/aws/http-desync-guardian/workflows/Tests/badge.svg)
[![Coverage Status](https://coveralls.io/repos/github/aws/http-desync-guardian/badge.svg?branch=master)](https://coveralls.io/github/aws/http-desync-guardian?branch=master)



Overview
========

`HTTP/1.1` went through a long evolution since 1991 to 2014:

* [HTTP/0.9](https://www.w3.org/Protocols/HTTP/AsImplemented.html) – 1991
* [HTTP/1.0](https://tools.ietf.org/html/rfc1945) – 1996
* HTTP/1.1
  * [RFC 2068](https://tools.ietf.org/html/rfc2068) – 1997
  * [RFC 2616](https://tools.ietf.org/html/rfc2616) - 1999
  * [RFC 7230](https://tools.ietf.org/html/rfc7230) - 2014

This means there is a variety of servers and clients, which might have different views on request boundaries, creating opportunities for desynchronization attacks (a.k.a. HTTP Desync). 	 
  
It might seem simple to follow the latest RFC recommendations. However, for large scale systems that have been there for a while, it may come with unacceptable availability impact.	 
  
`http_desync_guardian` library is designed to analyze HTTP requests to prevent HTTP Desync attacks, balancing security and availability. 
It classifies requests into different [categories](/docs#request-classification) and provides recommendations on how each tier should be handled.

It can be used either for raw HTTP request headers or already parsed by an HTTP engine.
Consumers may configure logging and metrics collection.
Logging is rate limited and all user data is obfuscated. 

If you think you might have found a security impacting issue, please follow [our Security Notification Process.](#security-issue-notifications)

Priorities
=======

* **Uniformity across services is key.** This means request classification, logging, and metrics must happen under the hood and with minimally available settings (e.g., such as log file destination).
* **Focus on reviewability.** The test suite must require no knowledge about the library/programming languages but only about HTTP protocol. So it's easy to review, contribute, and re-use.
* **Security is efficient when it's easy for users.** Our goal is to make integration of the library as simple as possible.
* **Ultralight.** The overhead must be minimal and impose no tangible tax on request handling (see [benchmarks](./benches)).

Supported HTTP versions
======

The main focus of this library is `HTTP/1.1`. See [tests](./tests) for all covered cases. Predecessors of `HTTP/1.1` don't support connection re-use which limits opportunities for HTTP Desync,
however some proxies may upgrade such requests to `HTTP/1.1` and re-use backend connections, which may allow to craft malicious `HTTP/1.0` requests. 
That's why they are analyzed using the same criteria as `HTTP/1.1`. For other protocol versions have the following exceptions:

* `HTTP/0.9` requests are never considered `Compliant`, but are classified as `Acceptable`. If any of `Content-Length`/`Transfer-Encoding` is present then it's `Ambiguous`.
* `HTTP/1.0` - the presence of `Transfer-Encoding` makes a request `Ambiguous`.
* `HTTP/2+` is out of scope. But if your proxy downgrades `HTTP/2` to `HTTP/1.1`, make sure the outgoing request is analyzed. 

See [documentation](./docs) to learn more.

Usage from C
=====

This library is designed to be primarily used from HTTP engines written in `C/C++`.  

1. Install [cbindgen](https://github.com/eqrion/cbindgen#cbindgen-----): `cargo install --force cbindgen`
1. Generate the header file: 
   * Run `cbindgen --output http_desync_guardian.h --lang c` for C.
   * Run `cbindgen --output http_desync_guardian.h --lang c++` for C++.
1. Run `cargo build --release`. The binaries are in `./target/release/libhttp_desync_guardian.*` files.

Learn more: [generic](./misc/demo-c) and [Nginx](./misc/demo-nginx) examples.

```c
#include "http_desync_guardian.h"

/* 
 * http_engine_request_t - already parsed by the HTTP engine 
 */
static int check_request(http_engine_request_t *req) {
    http_desync_guardian_request_t guardian_request = construct_http_desync_guardian_from(req); 
    http_desync_guardian_verdict_t verdict = {0};

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

If you discover a potential security issue in `http_desync_guardian` we ask that you notify
AWS Security via our [vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/). Please do **not** create a public github issue. 

## Security

See [CONTRIBUTING](./CONTRIBUTING.md#contributing-guidelines) for more information.

## License

This project is licensed under the [Apache-2.0 License](./LICENSE).
