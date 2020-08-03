use criterion::measurement::WallTime;
///
/// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
///
/// Licensed under the Apache License, Version 2.0 (the "License").
/// You may not use this file except in compliance with the License.
/// A copy of the License is located at
///
///  http://aws.amazon.com/apache2.0
///
/// or in the "license" file accompanying this file. This file is distributed
/// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
/// express or implied. See the License for the specific language governing
/// permissions and limitations under the License.
///
use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use http_desync_guardian::http_token_utils::http_token;
use http_desync_guardian::request_analyzer::{
    HttpHeader, HttpRequestData, HEADERS_STACK_STORAGE_SIZE,
};
use http_desync_guardian::ultralight_rate_limiter::UltraLightRateLimiter;
use http_desync_guardian::{
    http_desync_guardian_initialize_logging_settings,
    http_desync_guardian_register_tier_metrics_callback, ExtLoggingSettings,
    ExtRequestAnalysisMetricsUnit, ExtString, ExtTierMetricsSettings, RequestSafetyTier,
};
use lazy_static::lazy_static;
use smallvec::SmallVec;
use std::slice;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

lazy_static! {
    pub static ref START_TIME: Instant = Instant::now();
}

static LOG_COUNTER: AtomicU64 = AtomicU64::new(0);
static LAST_TIME: AtomicU64 = AtomicU64::new(0);
static SKIPS: AtomicU64 = AtomicU64::new(0);

/// Monotonic clock function, returning `ms` since startup.
/// Makes a system call only in 10% of cases (coarse-grained time, good enough)
fn get_current_time_millis() -> u64 {
    let start_time = *START_TIME;
    let x = SKIPS.fetch_add(1, Ordering::Relaxed);
    if x > 10 {
        SKIPS.fetch_and(0, Ordering::Relaxed);
    }
    if x == 1 {
        let current = Instant::now().duration_since(start_time).as_millis() as u64;
        LAST_TIME.store(current, Ordering::Relaxed);
        current
    } else {
        LAST_TIME.load(Ordering::Relaxed)
    }
}

fn as_bytes(s: &ExtString) -> &[u8] {
    let len = s.length - 1;
    let ptr = s.data_ptr as *const u8;
    // we know it's safe in this benchmark
    // as we control the input which is always valid
    unsafe { slice::from_raw_parts(ptr, len as usize + 1) }
}

extern "C" fn handle_log_messages(_tier: RequestSafetyTier, n: u32, msg: *const u8) {
    let string = ExtString {
        length: n,
        data_ptr: msg as *const i8,
    };
    let x = std::str::from_utf8(as_bytes(&string)).unwrap();
    LOG_COUNTER.fetch_add(x.len() as u64, Ordering::Relaxed);
}

extern "C" fn handle_metrics(
    n: u32,
    _msg: *const ExtRequestAnalysisMetricsUnit<RequestSafetyTier>,
) {
    LOG_COUNTER.fetch_add(n as u64, Ordering::Relaxed);
}

fn benchmark_ultralight_rate_limiter(c: &mut Criterion) {
    let rate_limiter = UltraLightRateLimiter::new(100., get_current_time_millis);

    c.bench_function(format!("Rate limiter").as_str(), |b| {
        b.iter(|| black_box(rate_limiter.try_acquire()))
    });
}

fn calculate_request_size(request: &HttpRequestData) -> usize {
    let mut size = 0;
    size += request.uri.len();
    size += request.method.len();
    size += request.version.len();
    for header in &request.headers {
        size += header.name.len();
        size += header.value.len();
    }
    size
}

struct SyntheticRequestParameters {
    name: &'static str,
    bad: bool,
    malicious: bool,
}

fn benchmark_request_analysis(
    c: &mut Criterion<WallTime>,
    request_params: SyntheticRequestParameters,
) {
    let mut group = c.benchmark_group(request_params.name);
    group.warm_up_time(Duration::from_secs(5)).sample_size(200);
    for size in &[50, 100, 500] {
        let c = if request_params.malicious {
            '\x01'
        } else {
            'a'
        };
        let mut field_value = std::iter::repeat(c).take(*size).collect::<String>();

        if request_params.bad {
            field_value.pop();
            field_value.pop();
            field_value.push('\x01');
            field_value.push('\x00');
        }

        let header_names: Vec<String> = (0..=size / 10)
            .map(|i| format!("Header-name-{}", i))
            .collect();

        let mut headers: SmallVec<[HttpHeader; HEADERS_STACK_STORAGE_SIZE]> = (0..=size / 10)
            .map(|i| HttpHeader::new(http_token(&header_names[i]), http_token(&field_value)))
            .collect();

        if request_params.bad {
            headers.push(HttpHeader::new(
                http_token("transfer-encoding"),
                http_token("gzip, chunked"),
            ));
            headers.push(HttpHeader::new(
                http_token("content-length"),
                http_token("123456789"),
            ));
        }

        let mut request = HttpRequestData {
            uri: http_token(&field_value),
            version: http_token("HTTP/1.1"),
            method: http_token("POST"),
            headers,
        };
        group
            .throughput(Throughput::Bytes(calculate_request_size(&request) as u64))
            .bench_function(
                format!(
                    "analyze_request: size {} bytes",
                    calculate_request_size(&request)
                ),
                |b| b.iter(|| black_box(request.analyze_parsed_request())),
            );
    }
    group.finish();
}

fn benchmark_request_parsing(
    c: &mut Criterion<WallTime>,
    request_params: SyntheticRequestParameters,
) {
    use std::fmt::Write;

    let mut group = c.benchmark_group(request_params.name);
    group.warm_up_time(Duration::from_secs(5)).sample_size(200);
    for size in &[50, 100, 500] {
        let c = if request_params.malicious {
            '\x01'
        } else {
            'a'
        };
        let field_value = std::iter::repeat(c).take(*size).collect::<String>();
        let mut request_as_string = String::new();
        write!(request_as_string, "GET {} HTTP/1.1\r\n", field_value,).ok();

        for i in 0..=size / 10 {
            write!(request_as_string, "Header-Name-{}: {}\r\n", i, field_value).ok();
        }
        write!(request_as_string, "\r\n").ok();

        let request_blob = request_as_string.as_bytes();

        group
            .throughput(Throughput::Bytes(request_blob.len() as u64))
            .bench_function(
                format!("analyze_raw_request: size {} bytes", request_blob.len()),
                |b| b.iter(|| black_box(HttpRequestData::analyze_raw_request(request_blob))),
            );
    }
    group.finish();
}

fn benchmark_compliant_request(c: &mut Criterion) {
    benchmark_request_analysis(
        c,
        SyntheticRequestParameters {
            name: "Compliant",
            bad: false,
            malicious: false,
        },
    );
}

fn benchmark_simplest_compliant_request_with_logging(c: &mut Criterion) {
    http_desync_guardian_register_tier_metrics_callback(Some(&ExtTierMetricsSettings {
        period_seconds: 10,
        callback: Some(handle_metrics),
    }));
    http_desync_guardian_initialize_logging_settings(Some(&ExtLoggingSettings {
        callback: Some(handle_log_messages),
    }));
    benchmark_request_analysis(
        c,
        SyntheticRequestParameters {
            name: "Compliant with logging",
            bad: false,
            malicious: false,
        },
    );
}

fn benchmark_non_compliant_request(c: &mut Criterion) {
    benchmark_request_analysis(
        c,
        SyntheticRequestParameters {
            name: "Non-Compliant",
            bad: true,
            malicious: false,
        },
    );
}

fn benchmark_malicious_request(c: &mut Criterion) {
    benchmark_request_analysis(
        c,
        SyntheticRequestParameters {
            name: "Malicious",
            bad: true,
            malicious: true,
        },
    );
}

fn benchmark_parse_request(c: &mut Criterion) {
    benchmark_request_parsing(
        c,
        SyntheticRequestParameters {
            name: "Parsing",
            bad: false,
            malicious: false,
        },
    );
}

criterion_group!(
    benches,
    benchmark_ultralight_rate_limiter,
    benchmark_parse_request,
    benchmark_compliant_request,
    benchmark_non_compliant_request,
    benchmark_malicious_request,
    benchmark_simplest_compliant_request_with_logging,
);

criterion_main!(benches);
