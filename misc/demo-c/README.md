Overview
=======

This directory contains examples of using `http_desync_guardian` library from C.

Running demo examples
=====================

```bash
git clone https://github.com/aws/http-desync-guardian.git
cd ./http-desync-guardian
cargo build --release
cargo install --force cbindgen
cbindgen --output ./misc/demo-c/http_desync_guardian.h --lang c
cd ./misc/demo-c/
gcc -o analyze_parsed_request analyze_parsed_request.c ../../target/release/libhttp_desync_guardian.so
gcc -o analyze_raw_request analyze_raw_request.c ../../target/release/libhttp_desync_guardian.so
```

Then running `./analyze_raw_request` or `./analyze_parsed_request` should output something like:

```
- $ ./analyze_raw_request
Request is Ambiguous: "PUT", Ambiguous:  BothTeClPresent "Content-Length": " 10", tier: Bad
```

Benchmarks
==========

Benchmarked on the same `c5.2xlarge` instance as the [Rust benchmarks](./benches):

Only compliant requests: 
```
➜  HttpDesyncGuardianDemoC ✗ ./http_desync_guardian_benchmarks -c
Time per op (Compliant) 0.975 us/op. 1026071.150 ops/sec
severe_count: 0
ambiguous_count: 0
acceptable_count: 0
compliant_count: 500000
=========================================

Avg. request size 1095
Throughput 1071.499 MiB/s
```

The worst-case (`Ambiguous` and `Severe`):

```bash
➜  HttpDesyncGuardianDemoC ✗ ./http_desync_guardian_benchmarks -b
Time per op (Bad) 2.252 us/op. 444057.376 ops/sec
severe_count: 250000
ambiguous_count: 250000
acceptable_count: 0
compliant_count: 0
=========================================

Avg. request size 1011
Throughput 428.144 MiB/s
Warning header "Transfer-Encoding	": " compress, deflate, 	chunked	"
```

Analyze raw requests
====================
Compliant only:
```bash
➜  HttpDesyncGuardianDemoC ✗ ./http_desync_guardian_benchmarks_raw -c
Time per op (Compliant) 1.622 us/op. 616514.562 ops/sec
severe_count: 0
ambiguous_count: 0
acceptable_count: 0
compliant_count: 500000
=========================================

Avg. request size 1095
Throughput 643.810 MiB/s
```

The worst-case (ambiguous and dangerous ones):

```bash
➜  HttpDesyncGuardianDemoC ✗ ./http_desync_guardian_benchmarks_raw -b
Time per op (Bad) 2.449 us/op. 408410.611 ops/sec
severe_count: 225000
ambiguous_count: 275000
acceptable_count: 0
compliant_count: 0
=========================================

Avg. request size 1146
Throughput 446.629 MiB/s
```
