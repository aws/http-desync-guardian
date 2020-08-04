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
use crate::http_token_utils::HttpToken;
use crate::metrics::{ClassificationMetricsSettings, LoggingSettings, TierMetricsSettings};
use crate::request_analyzer::{HttpRequestData, RequestAnalysisResult};
use std::hash::Hash;
use std::slice;

pub mod http_token_utils;
mod metrics;
mod raw_request_parser;
pub mod request_analyzer;
pub mod ultralight_rate_limiter;
use crate::SettingsReturnCode::{ACCEPTED, REJECTED};
use strum_macros::EnumIter;

/// The maximum length of an error message.
pub const MESSAGE_MAX_SIZE: usize = 300;

/// The classification of HTTP requests.
#[repr(C)]
#[derive(PartialOrd, PartialEq, Clone, Copy, Debug, Hash, Eq, EnumIter)]
pub enum RequestSafetyTier {
    /// All headers are RFC compliant.
    Compliant,
    /// Some headers are not RFC compliant, but there are no known security risks coming
    /// from these violations
    Acceptable,
    /// Different HTTP engines may interpret the request boundaries differently.
    Ambiguous,
    /// Either malformed or contains highly suspicious headers.
    Severe,
}

/// The classification of HTTP headers.
#[repr(C)]
#[derive(Copy, PartialOrd, PartialEq, Clone, Debug)]
pub enum HeaderSafetyTier {
    /// RFC compliant header name and value.
    Compliant,
    /// Either header name or value is not compliant.
    NonCompliant,
    /// Bad headers MUST be removed before sending to backends.
    Bad,
}

/// The reason why a request received a particular Request Safety Tier.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Hash, Eq, EnumIter)]
pub enum ClassificationReason {
    /// Initial value
    Compliant,
    /// Header specific reason
    EmptyHeader,
    SuspiciousHeader,
    NonCompliantHeader,
    BadHeader,
    /// URI specific reasons
    AmbiguousUri,
    SpaceInUri,
    BadUri,
    NonCompliantVersion,
    BadVersion,
    /// Content Length specific reasons
    GetHeadZeroContentLength,
    UndefinedContentLengthSemantics,
    MultipleContentLength,
    DuplicateContentLength,
    BadContentLength,
    /// Transfer Encoding specific reasons
    UndefinedTransferEncodingSemantics,
    MultipleTransferEncodingChunked,
    BadTransferEncoding,
    /// Both Transfer Encoding and Content Length present
    BothTeClPresent,
    /// Http Method related
    BadMethod,
    /// Request parsing issues
    NonCrLfLineTermination,
    MultilineHeader,
    PartialHeaderLine,
    MissingLastEmptyLine,
    MissingHeaderColon,
    MissingUri,
}

/// A pointer to a string.
#[repr(C)]
#[derive(Clone)]
pub struct ExtString {
    pub length: u32,
    pub data_ptr: *const i8,
}

/// Represents an HTTP header.
#[repr(C)]
pub struct ExtHttpHeader {
    name: ExtString,
    value: ExtString,
    /// After classification each header is marked accordingly.
    compliant: HeaderSafetyTier,
}

/// A collection of HTTP headers.
#[repr(C)]
pub struct ExtHttpHeaders {
    count: u32,
    pairs: *mut ExtHttpHeader,
}

/// Represents and HTTP request for analysis.
#[repr(C)]
pub struct ExtHttpRequestData {
    /// Http Method, e.g. GET, POST, PUT, etc.
    method: ExtString,
    /// Protocol version HTTP/1.0 or HTTP/1.1.
    version: ExtString,
    /// Request URI.
    uri: ExtString,
    /// Http headers (assuming they were parsed by the HTTP engine).
    headers: ExtHttpHeaders,
}

/// The result of request analysis.
#[repr(C)]
pub struct ClassificationVerdict {
    /// The request safety tier.
    tier: RequestSafetyTier,
    /// Classification reason for tier upgrade.
    reason: ClassificationReason,
    /// Error message (might be empty).
    message_length: u32,
    message_data: [u8; MESSAGE_MAX_SIZE],
}

/// Unit structure for emitting Metrics.
#[repr(C)]
#[derive(Clone)]
pub struct ExtRequestAnalysisMetricsUnit<T>
where
    T: Hash + Eq,
{
    /// Method name
    pub method: ExtString,
    /// Request safety tier.
    pub counter_type: T,
    /// Count for the request safety tier.
    pub count: u32,
}

/// The library can be configured only once.
/// The return code indicates if settings were accepted,
/// or it was a subsequent call.  
#[repr(C)]
pub enum SettingsReturnCode {
    ACCEPTED,
    REJECTED,
}

/// Configuration for logging.
#[repr(C)]
pub struct ExtLoggingSettings {
    /// A callback for logging messages.
    pub callback: Option<extern "C" fn(RequestSafetyTier, u32, *const u8)>,
}

/// Structured Request Safety Tier Metrics reporting.
#[repr(C)]
pub struct ExtTierMetricsSettings {
    /// Time period for emitting metrics in seconds.
    pub period_seconds: usize,
    /// A callback for emitting structured metrics for HeaderSafetyTier.
    pub callback:
        Option<extern "C" fn(u32, *const ExtRequestAnalysisMetricsUnit<RequestSafetyTier>)>,
}

/// Structured Classification Reason Metrics reporting.
#[repr(C)]
pub struct ExtClassificationMetricsSettings {
    /// Time period for emitting metrics in seconds.
    pub period_seconds: usize,
    /// A callback for emitting structured metrics for ClassificationReason.
    pub callback:
        Option<extern "C" fn(u32, *const ExtRequestAnalysisMetricsUnit<ClassificationReason>)>,
}

impl ExtString {
    pub fn from_slice(s: &str) -> Self {
        debug_assert!(
            s.len() < 0xffff,
            "In context of HTTP headers we do not expect more than 64k of data"
        );
        Self {
            length: s.len() as u32,
            data_ptr: s.as_ptr() as *const i8,
        }
    }

    pub fn from_http_token(s: HttpToken) -> Self {
        debug_assert!(
            s.len() < 0xffff,
            "In context of HTTP headers we do not expect more than 64k of data"
        );
        Self {
            length: s.len() as u32,
            data_ptr: s.as_ptr() as *const i8,
        }
    }

    fn as_http_token(&self, name: &'static str) -> HttpToken {
        assert!(
            self.length == 0 || !self.data_ptr.is_null(),
            "Bad {}: length is {}, but the pointer is NULL",
            name,
            self.length
        );

        if self.length > 0 {
            // `HttpToken` is not going to outlive the pointer in the context of this library
            // as they exist only during analysis
            // Also we checked it for not being NULL.
            unsafe { slice::from_raw_parts(self.data_ptr as *const u8, self.length as usize) }
        } else {
            b""
        }
    }
}

impl ExtHttpHeaders {
    fn to_slice(&self) -> &[ExtHttpHeader] {
        assert!(
            self.count == 0 || !self.pairs.is_null(),
            "Headers count is {}, but the pointer is NULL",
            self.count
        );
        if self.count > 0 {
            // The slice is not going to outlive the underlying pointer.
            unsafe { slice::from_raw_parts(self.pairs, self.count as usize) }
        } else {
            &[]
        }
    }
}

/// Analyzes a given HTTP request.
/// # Arguments
/// * `request` a pointer to request
/// * `verdict` a pointer to verdict placeholder (being populated by this method)
/// Both arguments are being changed during execution of this method.
/// # Safety
/// As long as request is well-formed and verdict is a valid pointer.
/// Which means no NULLs are allowed for names or values. Pass an empty string instead:
/// Also headers must be fully initialized, e.g.
/// ```c
/// #define http_desync_guardian_string(str) { .length = sizeof(str) - 1, .data_ptr = (uint8_t *) (str) }
///
/// guardian_header = {
///    .name = http_desync_guardian_string("Connection"),
///    .value = http_desync_guardian_string(" keep-alive"),
/// },
/// ```
/// # Note
/// This method may abort execution, if any parameter is invalid. Which includes:
/// 1. Any input is `NULL`
/// 2. Header count > 0, but the pointer is `NULL`
/// 3. Any string has > 0 length, but the pointer is `NULL`
#[no_mangle]
pub extern "C" fn http_desync_guardian_analyze_request(
    request: Option<&mut ExtHttpRequestData>,
    verdict: Option<&mut ClassificationVerdict>,
) {
    let request = request.expect("Request must not be NULL");
    let verdict = verdict.expect("Verdict must not be NULL");

    let mut request_for_analysis = HttpRequestData::new(request);

    let verdict_internal = request_for_analysis.analyze_parsed_request();

    // copy for consumption in C
    let request_headers = if request.headers.count > 0 {
        // The slice is not going to outlive the underlying pointer.
        unsafe { slice::from_raw_parts_mut(request.headers.pairs, request.headers.count as usize) }
    } else {
        &mut []
    };

    debug_assert_eq!(request_headers.len(), request_for_analysis.headers.len());
    for (idx, analyzed_header) in request_for_analysis.headers.iter().enumerate() {
        request_headers[idx].compliant = analyzed_header.get_tier();
    }

    populate_external_verdict(verdict, verdict_internal);
}

/// Parses and analyzes a given HTTP request.
/// # Arguments
/// * `size` length of the request header. Constant.
/// * `request_buffer` a pointer to the request buffer. Constant.
/// * `verdict` a pointer to verdict placeholder (being populated by this method). Mutable.
///
/// # Safety
/// As long as `request_buffer` and `verdict` are valid pointers and the size is a positive integer.
///
/// # Note
/// This method may abort execution, if any parameter is invalid. Which includes:
/// 1. `request_buffer` is `NULL`
/// 1. `verdict` is `NULL`
/// 1. `size` is `0`
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn http_desync_guardian_analyze_raw_request(
    size: u32,
    request_buffer: *const u8,
    verdict: Option<&mut ClassificationVerdict>,
) {
    assert!(size > 0, "Request size cannot be 0");
    assert!(!request_buffer.is_null(), "Request buffer must not be NULL");
    let verdict = verdict.expect("Verdict must not be NULL");

    // `http_request_buffer` is not going to outlive the underlying pointer.
    // Also we checked it for not being NULL.
    let http_request_buffer = unsafe { slice::from_raw_parts(request_buffer, size as usize) };

    let verdict_internal = HttpRequestData::analyze_raw_request(http_request_buffer);

    populate_external_verdict(verdict, verdict_internal);
}

fn populate_external_verdict(
    verdict: &mut ClassificationVerdict,
    verdict_internal: RequestAnalysisResult,
) {
    verdict.tier = verdict_internal.tier;
    verdict.reason = verdict_internal.reason;
    if let Some(message) = verdict_internal.message {
        verdict.message_length = (MESSAGE_MAX_SIZE - 1).min(message.len()) as u32;

        unsafe {
            // we checked the length of the source and the destination
            std::ptr::copy(
                message.as_ptr(),
                verdict.message_data.as_mut_ptr(),
                verdict.message_length as usize,
            );
        }
    } else {
        verdict.message_length = 0;
    }
    // \0 string termination. Just in case it might be misused in sprintf with `%s` instead of `%.*s`
    verdict.message_data[verdict.message_length as usize] = 0;
}

/// Return request information with Customer sensitive data obfuscated
/// The callback must be non-null.
/// Populates a buffer with the data in an HTTP Request that has been analyzed.
/// # Arguments
/// * `request` a pointer to request
/// * `buffer_len` the size of the buffer
/// * `buffer` a raw pointer to the buffer being written to
/// `request` and `buffer` are being changed during execution of this method.
/// # Safety
/// Request needs to be well-formed.
/// Which means no NULLs are allowed for names or values. Pass an empty string instead:
/// `http_desync_guardian_string_t empty = {.length = 0, .data_ptr = NULL};`
/// Also headers must be fully initialized, e.g.
/// ```c
/// guardian_header = {
///    .name = http_desync_guardian_string("Connection"),
///    .value = http_desync_guardian_string(" keep-alive"),
/// },
/// ```
/// # Note
/// This method may abort execution, if any parameter is invalid. Which includes:
/// 1. Any input is `NULL`
/// 2. Header count > 0, but the pointer is `NULL`
/// 3. Any string has > 0 length, but the pointer is `NULL`
/// 4. `buffer_len` is less than or equal to 0
/// 5. `buffer` is `NULL`
#[no_mangle]
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn http_desync_guardian_print_request(
    request: Option<&mut ExtHttpRequestData>,
    buffer_len: usize,
    buffer: *mut u8,
) -> u32 {
    let request = request.expect("Request must not be NULL");
    assert!(!buffer.is_null(), "Buffer must not be NULL");
    assert!(buffer_len > 0, "Buffer length cannot be empty");

    let request_data = HttpRequestData::new(request).to_string();
    let data_len: u32 = (buffer_len - 1).min(request_data.len()) as u32;
    unsafe {
        // we checked the length of the source and the destination
        std::ptr::copy(request_data.as_ptr(), buffer, data_len as usize);
        // \0 string termination. Just in case it might be misused in sprintf with `%s` instead of `%.*s`
        buffer.add(data_len as usize).write(0);
    }
    data_len
}

/// Configure logging parameters. Only first call matters (subsequent are ignored).
/// The `settings` and `settings.callback` must be non-null.
/// # Returns
/// Either `ACCEPTED` for the first call or `REJECTED` for any subsequent ones.
#[no_mangle]
pub extern "C" fn http_desync_guardian_initialize_logging_settings(
    settings: Option<&ExtLoggingSettings>,
) -> SettingsReturnCode {
    match LoggingSettings::set(settings.expect("Settings can not be NULL")) {
        Ok(_) => ACCEPTED,
        Err(_) => REJECTED,
    }
}

/// Configure Aggregated Request Safety Tier metrics reporting.
/// Only first call matters (subsequent calls are ignored).
/// The callback must be non-null.
/// # Returns
/// Either `ACCEPTED` for the first call or `REJECTED` for any subsequent ones.
#[no_mangle]
pub extern "C" fn http_desync_guardian_register_tier_metrics_callback(
    settings: Option<&ExtTierMetricsSettings>,
) -> SettingsReturnCode {
    match TierMetricsSettings::set(settings.expect("Settings can not be NULL")) {
        Ok(_) => ACCEPTED,
        Err(_) => REJECTED,
    }
}

/// Configure Aggregated Classification Reason metrics reporting.
/// Only first call matters (subsequent calls are ignored).
/// # Panics
/// If the parameter or the callback is `NULL`.
/// # Returns
/// Either `ACCEPTED` for the first call or `REJECTED` for any subsequent ones.
#[no_mangle]
pub extern "C" fn http_desync_guardian_register_classification_metrics_callback(
    settings: Option<&ExtClassificationMetricsSettings>,
) -> SettingsReturnCode {
    match ClassificationMetricsSettings::set(settings.expect("Settings can not be NULL")) {
        Ok(_) => ACCEPTED,
        Err(_) => REJECTED,
    }
}

#[cfg(test)]
mod tests {
    use crate::http_token_utils::{http_token, to_quoted_ascii, HttpToken};
    use crate::{
        http_desync_guardian_analyze_raw_request, http_desync_guardian_analyze_request,
        http_desync_guardian_initialize_logging_settings, http_desync_guardian_print_request,
        http_desync_guardian_register_classification_metrics_callback,
        http_desync_guardian_register_tier_metrics_callback, ClassificationReason,
        ClassificationVerdict, ExtClassificationMetricsSettings, ExtHttpHeader, ExtHttpHeaders,
        ExtHttpRequestData, ExtLoggingSettings, ExtRequestAnalysisMetricsUnit, ExtString,
        ExtTierMetricsSettings, HeaderSafetyTier, HttpRequestData, RequestSafetyTier,
        MESSAGE_MAX_SIZE,
    };
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicU32, Ordering};

    static LOG_COUNT: AtomicU32 = AtomicU32::new(0);
    static TIER_COUNT: AtomicU32 = AtomicU32::new(0);
    static CLASSIFICATION_COUNT: AtomicU32 = AtomicU32::new(0);

    extern "C" fn handle_log_messages(tier: RequestSafetyTier, n: u32, msg: *const u8) {
        let string = ExtString {
            length: n,
            data_ptr: msg as *const i8,
        };
        LOG_COUNT.fetch_add(1, Ordering::SeqCst);
        println!(
            "{:?} {}",
            tier,
            to_quoted_ascii(string.as_http_token("Log message"))
        );
    }

    extern "C" fn handle_structured_tier_metrics(
        size: u32,
        tier_metrics_list: *const ExtRequestAnalysisMetricsUnit<RequestSafetyTier>,
    ) {
        let slice = unsafe { std::slice::from_raw_parts(tier_metrics_list, size as usize) };
        assert!(!slice.is_empty());

        TIER_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    extern "C" fn handle_structured_classification_metrics(
        size: u32,
        classification_metrics_list: *const ExtRequestAnalysisMetricsUnit<ClassificationReason>,
    ) {
        let slice =
            unsafe { std::slice::from_raw_parts(classification_metrics_list, size as usize) };
        assert!(!slice.is_empty());

        CLASSIFICATION_COUNT.fetch_add(1, Ordering::SeqCst);
    }

    /// Simple test to verify serialization-deserialization
    /// of data structures between C and Rust.
    #[test]
    fn test_http_desync_guardian_analyze_request() {
        let mut header = ExtHttpHeader {
            name: ExtString::from_slice("Transfer-Encoding"),
            value: ExtString::from_slice("xchunked"),
            compliant: HeaderSafetyTier::Compliant,
        };
        let parts_mut = &mut header as *mut _;
        let mut request = ExtHttpRequestData {
            method: ExtString::from_slice("POST"),
            version: ExtString::from_slice("HTTP/1.1"),
            uri: ExtString::from_slice("/foo/bar"),
            headers: ExtHttpHeaders {
                count: 1,
                pairs: parts_mut,
            },
        };
        let mut verdict = ClassificationVerdict {
            tier: RequestSafetyTier::Compliant,
            reason: ClassificationReason::Compliant,
            message_length: 0,
            message_data: [0; MESSAGE_MAX_SIZE],
        };

        http_desync_guardian_analyze_request(Some(&mut request), Some(&mut verdict));

        assert_eq!(verdict.tier, RequestSafetyTier::Severe);
        assert!(verdict.message_length > 0);
        assert_eq!(verdict.reason, ClassificationReason::BadTransferEncoding);
        assert_eq!(
            HttpRequestData::new(&request)
                .headers
                .get(0)
                .unwrap()
                .get_tier(),
            HeaderSafetyTier::Bad
        );

        const BUFFER_LEN: usize = 4096;
        let mut buffer = [0; BUFFER_LEN];
        let request_data_len =
            http_desync_guardian_print_request(Some(&mut request), BUFFER_LEN, buffer.as_mut_ptr());
        let request_data_string =
            std::str::from_utf8(buffer.as_ref()).expect("ASCII -> UTF8 never fails");

        assert!(request_data_len > 0);
        assert!(request_data_string.contains("xchunked"));

        let msg_part = http_token("Transfer-Encoding");
        let found = find_message(&verdict, &msg_part);
        assert!(
            found,
            "{} was not found in the message",
            to_quoted_ascii(msg_part)
        );

        assert_eq!(
            request.headers.to_slice()[0].compliant,
            HeaderSafetyTier::Bad
        );
    }

    #[test]
    fn test_log_callback() {
        let logging_settings = ExtLoggingSettings {
            callback: Some(handle_log_messages),
        };

        http_desync_guardian_initialize_logging_settings(Some(&logging_settings));

        analyze_vanilla_request();

        assert_ne!(LOG_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_request_tier_metrics_callback() {
        let tier_metrics_settings = ExtTierMetricsSettings {
            period_seconds: 1,
            callback: Some(handle_structured_tier_metrics),
        };

        http_desync_guardian_register_tier_metrics_callback(Some(&tier_metrics_settings));

        analyze_vanilla_request();

        assert_ne!(TIER_COUNT.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_classification_reason_metrics_callback() {
        let classification_metrics_settings = ExtClassificationMetricsSettings {
            period_seconds: 1,
            callback: Some(handle_structured_classification_metrics),
        };

        http_desync_guardian_register_classification_metrics_callback(Some(
            &classification_metrics_settings,
        ));

        analyze_vanilla_request();

        assert_ne!(CLASSIFICATION_COUNT.load(Ordering::SeqCst), 0);
    }

    fn analyze_vanilla_request() {
        let mut header = ExtHttpHeader {
            name: ExtString::from_slice("Transfer-Encoding"),
            value: ExtString::from_slice("xchunked"),
            compliant: HeaderSafetyTier::Compliant,
        };
        let parts_mut = &mut header as *mut _;
        let mut request = ExtHttpRequestData {
            method: ExtString::from_slice("POST"),
            version: ExtString::from_slice("HTTP/1.1"),
            uri: ExtString::from_slice("/foo/bar"),
            headers: ExtHttpHeaders {
                count: 1,
                pairs: parts_mut,
            },
        };
        let mut verdict = ClassificationVerdict {
            tier: RequestSafetyTier::Compliant,
            reason: ClassificationReason::Compliant,
            message_length: 0,
            message_data: [0; MESSAGE_MAX_SIZE],
        };

        http_desync_guardian_analyze_request(Some(&mut request), Some(&mut verdict));
    }

    #[test]
    fn test_http_desync_guardian_analyze_raw_request() {
        let mut verdict = ClassificationVerdict {
            tier: RequestSafetyTier::Compliant,
            reason: ClassificationReason::Compliant,
            message_length: 0,
            message_data: [0; MESSAGE_MAX_SIZE],
        };

        const GET_REQUEST: HttpToken =
            http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost\x00GET /smuggle HTTP/1.1\r\n\r\n");

        http_desync_guardian_analyze_raw_request(
            GET_REQUEST.len() as u32,
            GET_REQUEST.as_ptr(),
            Some(&mut verdict),
        );

        assert_eq!(verdict.tier, RequestSafetyTier::Severe);
        assert!(verdict.message_length > 0);
        assert_eq!(verdict.reason, ClassificationReason::BadHeader);
        let msg_part = http_token("Host");
        let found = find_message(&mut verdict, &msg_part);

        assert!(
            found,
            "{} was not found in the message",
            to_quoted_ascii(msg_part)
        );
    }

    fn find_message(verdict: &ClassificationVerdict, msg_part: &[u8]) -> bool {
        let mut found = false;
        for i in 0..=verdict.message_length as usize - msg_part.len() {
            if &verdict.message_data[i..i + msg_part.len()] == msg_part {
                found = true;
                break;
            }
        }
        found
    }

    #[test]
    fn test_http_desync_guardian_validate_print_request_insufficient_buffer_length() {
        let mut header = ExtHttpHeader {
            name: ExtString::from_slice("Transfer-Encoding"),
            value: ExtString::from_slice("chunked"),
            compliant: HeaderSafetyTier::Compliant,
        };
        let parts_mut = &mut header as *mut _;
        let mut request = ExtHttpRequestData {
            method: ExtString::from_slice("GET"),
            version: ExtString::from_slice("HTTP/1.1"),
            uri: ExtString::from_slice("/foo/bar"),
            headers: ExtHttpHeaders {
                count: 1,
                pairs: parts_mut,
            },
        };

        const BUFFER_LEN: usize = 10;
        let mut buffer = [0; BUFFER_LEN];
        let request_data_len =
            http_desync_guardian_print_request(Some(&mut request), BUFFER_LEN, buffer.as_mut_ptr());

        assert_eq!(request_data_len, 9);
    }

    #[test]
    fn test_non_compliant_header_tier() {
        // Create a valid header with HeaderSafetyTier set to non-compliant
        let mut header = ExtHttpHeader {
            name: ExtString::from_slice("Transfer-Encoding"),
            value: ExtString::from_slice("chunked"),
            compliant: HeaderSafetyTier::NonCompliant,
        };
        let parts_mut = &mut header as *mut _;

        let request = &ExtHttpRequestData {
            method: ExtString::from_slice("GET"),
            version: ExtString::from_slice("HTTP/1.1"),
            uri: ExtString::from_slice("/foo/bar"),
            headers: ExtHttpHeaders {
                count: 1,
                pairs: parts_mut,
            },
        };

        assert_eq!(
            HttpRequestData::new(request)
                .headers
                .get(0)
                .unwrap()
                .get_tier(),
            HeaderSafetyTier::NonCompliant
        );
    }

    #[test]
    fn test_invalid_header_tier() {
        // Create an unsafe, invalid enum entry
        let mut invalid_tier: HeaderSafetyTier = HeaderSafetyTier::Compliant;
        let ptr = (&mut invalid_tier) as *mut _ as *mut u8;
        unsafe {
            ptr.write(255);
        }
        assert_ne!(invalid_tier, HeaderSafetyTier::Compliant);

        let mut header = ExtHttpHeader {
            name: ExtString::from_slice("Transfer-Encoding"),
            value: ExtString::from_slice("chunked"),
            compliant: invalid_tier,
        };
        let parts_mut = &mut header as *mut _;

        let request = &ExtHttpRequestData {
            method: ExtString::from_slice("GET"),
            version: ExtString::from_slice("HTTP/1.1"),
            uri: ExtString::from_slice("/foo/bar"),
            headers: ExtHttpHeaders {
                count: 1,
                pairs: parts_mut,
            },
        };

        assert_eq!(
            HttpRequestData::new(request)
                .headers
                .get(0)
                .unwrap()
                .get_tier(),
            HeaderSafetyTier::Compliant
        );
    }

    #[test]
    #[should_panic(expected = "Callback to send logs is required")]
    fn test_logger_callback_required() {
        let logging_settings = ExtLoggingSettings { callback: None };

        http_desync_guardian_initialize_logging_settings(Some(&logging_settings));
    }

    #[test]
    #[should_panic(expected = "Settings can not be NULL")]
    fn test_logger_settings_required() {
        http_desync_guardian_initialize_logging_settings(None);
    }

    #[test]
    #[should_panic(expected = "Callback to send tier metrics is required")]
    fn test_tier_metrics_callback_required() {
        let logging_settings = ExtTierMetricsSettings {
            period_seconds: 10,
            callback: None,
        };

        http_desync_guardian_register_tier_metrics_callback(Some(&logging_settings));
    }

    #[test]
    #[should_panic(expected = "Settings can not be NULL")]
    fn test_tier_metrics_settings_required() {
        http_desync_guardian_register_tier_metrics_callback(None);
    }

    #[test]
    #[should_panic(expected = "Callback to send classification metrics is required")]
    fn test_classification_metrics_callback_required() {
        let logging_settings = ExtClassificationMetricsSettings {
            period_seconds: 10,
            callback: None,
        };

        http_desync_guardian_register_classification_metrics_callback(Some(&logging_settings));
    }

    #[test]
    #[should_panic(expected = "Settings can not be NULL")]
    fn test_classification_metrics_settings_required() {
        http_desync_guardian_register_classification_metrics_callback(None);
    }

    #[test]
    #[should_panic(expected = "Request must not be NULL")]
    fn test_http_desync_guardian_validate_print_request_parameters_null_request() {
        http_desync_guardian_print_request(None, 1, [0].as_mut_ptr());
    }

    #[test]
    #[should_panic(expected = "Buffer must not be NULL")]
    fn test_http_desync_guardian_validate_print_request_parameters_null_buffer() {
        let mut request = new_request();
        http_desync_guardian_print_request(Some(&mut request), 1, std::ptr::null_mut());
    }

    #[test]
    #[should_panic(expected = "Buffer length cannot be empty")]
    fn test_http_desync_guardian_validate_print_request_parameters_invalid_buffer_length() {
        let mut request = new_request();
        http_desync_guardian_print_request(Some(&mut request), 0, [0].as_mut_ptr());
    }

    #[test]
    #[should_panic(expected = "Request must not be NULL")]
    fn test_http_desync_guardian_validate_request_analysis_parameters_null_request() {
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_request(None, Some(&mut verdict));
    }

    #[test]
    #[should_panic(expected = "Verdict must not be NULL")]
    fn test_http_desync_guardian_validate_request_analysis_parameters_null_verdict() {
        let mut request = new_request();
        http_desync_guardian_analyze_request(Some(&mut request), None);
    }

    #[test]
    #[should_panic(expected = "Bad method: length is 3, but the pointer is NULL")]
    fn test_http_desync_guardian_validate_request_analysis_parameters_null_method() {
        let mut request = new_request();
        request.method = ExtString {
            length: 3,
            data_ptr: null(),
        };
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_request(Some(&mut request), Some(&mut verdict));
    }

    #[test]
    #[should_panic(expected = "Bad version: length is 8, but the pointer is NULL")]
    fn test_http_desync_guardian_validate_request_analysis_parameters_null_version() {
        let mut request = new_request();
        request.version = ExtString {
            length: 8,
            data_ptr: null(),
        };
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_request(Some(&mut request), Some(&mut verdict));
    }

    #[test]
    #[should_panic(expected = "Bad URI: length is 1, but the pointer is NULL")]
    fn test_http_desync_guardian_validate_request_analysis_parameters_null_uri() {
        let mut request = new_request();
        request.uri = ExtString {
            length: 1,
            data_ptr: null(),
        };
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_request(Some(&mut request), Some(&mut verdict));
    }

    #[test]
    #[should_panic(expected = "Bad header name: length is 10, but the pointer is NULL")]
    fn test_http_desync_guardian_validate_request_analysis_parameters_null_header_name() {
        let mut header = ExtHttpHeader {
            name: ExtString {
                length: 10,
                data_ptr: null(),
            },
            value: ExtString::from_slice("chunked"),
            compliant: HeaderSafetyTier::Compliant,
        };
        let parts_mut = &mut header as *mut _;
        let mut request = new_request();
        request.headers = ExtHttpHeaders {
            count: 1,
            pairs: parts_mut,
        };
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_request(Some(&mut request), Some(&mut verdict));
    }

    #[test]
    #[should_panic(expected = "Bad header value: length is 10, but the pointer is NULL")]
    fn test_http_desync_guardian_validate_request_analysis_parameters_null_header_value() {
        let mut header = ExtHttpHeader {
            name: ExtString::from_slice("X-My-Header"),
            value: ExtString {
                length: 10,
                data_ptr: null(),
            },
            compliant: HeaderSafetyTier::Compliant,
        };
        let parts_mut = &mut header as *mut _;
        let mut request = new_request();
        request.headers = ExtHttpHeaders {
            count: 1,
            pairs: parts_mut,
        };
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_request(Some(&mut request), Some(&mut verdict));
    }

    #[test]
    #[should_panic(expected = "Request buffer must not be NULL")]
    fn test_http_desync_guardian_validate_request_raw_request_null_buffer() {
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_raw_request(100, null(), Some(&mut verdict));
    }

    #[test]
    #[should_panic(expected = "Verdict must not be NULL")]
    fn test_http_desync_guardian_validate_request_raw_request_null_verdict() {
        http_desync_guardian_analyze_raw_request(100, [0].as_ptr(), None);
    }

    #[test]
    #[should_panic(expected = "Request size cannot be 0")]
    fn test_http_desync_guardian_validate_request_raw_request_zero_buffer_size() {
        let mut verdict = new_verdict();
        http_desync_guardian_analyze_raw_request(0, [0].as_ptr(), Some(&mut verdict));
    }

    fn new_verdict() -> ClassificationVerdict {
        ClassificationVerdict {
            tier: RequestSafetyTier::Compliant,
            reason: ClassificationReason::Compliant,
            message_length: 0,
            message_data: [0; MESSAGE_MAX_SIZE],
        }
    }

    fn new_request() -> ExtHttpRequestData {
        ExtHttpRequestData {
            method: ExtString::from_slice("GET"),
            version: ExtString::from_slice("HTTP/1.1"),
            uri: ExtString::from_slice("/"),
            headers: ExtHttpHeaders {
                count: 0,
                pairs: null_mut(),
            },
        }
    }
}
