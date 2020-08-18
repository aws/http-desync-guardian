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
use crate::http_token_utils::TokenSimilarity::*;
use crate::http_token_utils::*;
use crate::metrics::*;
use crate::raw_request_parser::{RequestBuffer, COLON, LF, SP};
use crate::HeaderSafetyTier::{Bad, Compliant, NonCompliant};
use crate::{ClassificationReason, ExtHttpRequestData, HeaderSafetyTier, RequestSafetyTier};
use smallvec::SmallVec;
use std::fmt::{Display, Error, Formatter};

const GET: HttpToken = http_token("GET");
const HEAD: HttpToken = http_token("HEAD");
const HTTP_0_9: HttpToken = http_token("HTTP/0.9");
const HTTP_1_0: HttpToken = http_token("HTTP/1.0");
const HTTP_1_: HttpToken = http_token("HTTP/1.");
const HTTP_1_1: HttpToken = http_token("HTTP/1.1");
const HTTP_2: HttpToken = http_token("HTTP/2");

/// How many headers are stored on stack. If more, it spills over to the heap.
pub const HEADERS_STACK_STORAGE_SIZE: usize = 64;

///
/// Lazy error details evaluation.
/// It might happen multiple times during request analysis,
/// so the difference was benchmarked and it's totally justified.
///
/// Using a method with `FnOnce() -> ErrorMessage` would produce more overhead.
///
macro_rules! upgrade_verdict {
    ($state:expr, $tier:expr, $error:expr) => {
        if $state.tier < $tier {
            $state.tier = $tier;
            $state.reason = $error.reason_message;
            $state.error_message = Some($error);
        }
    };
}

pub struct RequestAnalysisResult {
    pub tier: RequestSafetyTier,
    pub reason: ClassificationReason,
    pub message: Option<String>,
}

struct RequestAnalysisState<'a> {
    tier: RequestSafetyTier,
    reason: ClassificationReason,
    error_message: Option<ErrorMessage<'a>>,
}

#[derive(Clone)]
pub struct HttpHeader<'a> {
    pub name: HttpToken<'a>,
    pub value: HttpToken<'a>,
    is_essential: bool,
    tier: HeaderSafetyTier,
}

pub struct HttpRequestData<'a> {
    /// Http Method, e.g. GET, POST, PUT, etc.
    pub method: HttpToken<'a>,
    /// Protocol version 1.0 or 1.1
    pub version: HttpToken<'a>,
    /// Request URI
    pub uri: HttpToken<'a>,
    /// Http headers (assuming they were parsed by the HTTP engine)
    pub headers: SmallVec<[HttpHeader<'a>; HEADERS_STACK_STORAGE_SIZE]>,
}

struct ErrorMessage<'a> {
    /// Header whose tier severity was upgraded
    header: Option<HttpHeader<'a>>,
    /// Reason for tier upgrade
    reason_message: ClassificationReason,
    /// Specific message details
    details: Option<String>,
}

impl<'a> ErrorMessage<'a> {
    fn from_header(reason: ClassificationReason, header: HttpHeader<'a>) -> Self {
        Self {
            header: Some(header),
            reason_message: reason,
            details: None,
        }
    }

    fn from_message(reason: ClassificationReason, details: String) -> Self {
        Self {
            header: None,
            reason_message: reason,
            details: Some(details),
        }
    }
}

impl<'a> HttpRequestData<'a> {
    ///
    /// Convert a C struct into an internal struct for Rust.
    /// It converts data from an external C call into internal data structures (without copying).
    /// Headers are constructed from external data from C with caution.
    /// Any invalid value for HeaderSafetyTier is defaulted to Compliant.
    ///
    pub fn new(request: &'a ExtHttpRequestData) -> Self {
        Self {
            method: request.method.as_http_token("method"),
            version: request.version.as_http_token("version"),
            uri: request.uri.as_http_token("URI"),
            headers: request
                .headers
                .to_slice()
                .iter()
                .map(|h| HttpHeader {
                    name: h.name.as_http_token("header name"),
                    value: h.value.as_http_token("header value"),
                    tier: match h.compliant {
                        HeaderSafetyTier::NonCompliant => HeaderSafetyTier::NonCompliant,
                        HeaderSafetyTier::Bad => HeaderSafetyTier::Bad,
                        _ => HeaderSafetyTier::Compliant,
                    },
                    is_essential: false,
                })
                .collect(),
        }
    }

    /// Copy-free parsing of HTTP requests _for analysis only_.
    /// The output of this is not supposed to be used for application logic,
    /// and that's why it's private (only the analysis result is public).
    ///
    /// TODO we can combine with validation to perform analysis in a single pass.
    ///
    /// If during parsing errors were encountered, they
    /// are populated in the `RequestAnalysisState`
    fn parse(buf: HttpToken<'a>) -> (Self, RequestAnalysisState) {
        let mut parse_state = RequestAnalysisState {
            tier: RequestSafetyTier::Compliant,
            reason: ClassificationReason::Compliant,
            error_message: None,
        };

        let mut buffer = RequestBuffer::new(buf);

        let (method, version, uri) =
            HttpRequestData::parse_request_line(&mut buffer, &mut parse_state);

        (
            Self {
                method,
                version,
                uri,
                headers: HttpRequestData::parse_headers(&mut buffer, &mut parse_state),
            },
            parse_state,
        )
    }

    /// request-line = method SP request-target SP HTTP-version CRLF
    ///
    /// https://tools.ietf.org/html/rfc7230#section-3.1.1
    fn parse_request_line(
        buffer: &mut RequestBuffer<'a>,
        parse_state: &mut RequestAnalysisState<'a>,
    ) -> (HttpToken<'a>, HttpToken<'a>, HttpToken<'a>) {
        let mut request_line = buffer.next_token(LF);
        if !request_line.trim_last_cr() {
            HttpRequestData::report_partial_line_termination(
                "Request line is \\n terminated (not \\r\\n)",
                parse_state,
            );
        }
        let method = request_line.next_token(SP);
        let mut version = request_line.last_token(SP);
        let mut uri = request_line;
        // check if the URI is missing.
        if (uri.is_partial() && version.as_http_token().starts_with(HTTP_1_))
            || (version.is_done() && uri.is_done())
        {
            upgrade_verdict!(
                parse_state,
                RequestSafetyTier::Ambiguous,
                ErrorMessage::from_message(
                    ClassificationReason::MissingUri,
                    format!(
                        "Missing URI: {} {} {}",
                        to_quoted_ascii(method.as_http_token()),
                        to_quoted_ascii(uri.as_http_token()),
                        to_quoted_ascii(version.as_http_token())
                    ),
                )
            );
        } else if uri.is_partial() {
            uri = version;
            // missing version => HTTP/0.9
            version = RequestBuffer::new(&[]);
        }
        (
            method.as_http_token(),
            version.as_http_token(),
            uri.as_http_token(),
        )
    }

    /// header-field   = field-name ":" OWS field-value OWS
    ///
    /// field-name     = token
    /// field-value    = *( field-content / obs-fold )
    /// field-content  = field-vchar [ 1*( SP / HTAB ) field-vchar ]
    /// field-vchar    = VCHAR / obs-text
    ///
    /// obs-fold       = CRLF 1*( SP / HTAB )
    ///                ; obsolete line fold
    ///
    /// https://tools.ietf.org/html/rfc7230#section-3.2
    fn parse_headers(
        buffer: &mut RequestBuffer<'a>,
        parse_state: &mut RequestAnalysisState<'a>,
    ) -> SmallVec<[HttpHeader<'a>; HEADERS_STACK_STORAGE_SIZE]> {
        // exception that allows multi-line headers
        const CONTENT_TYPE_HEADER_NAME: HttpToken = http_token("content-type");

        let mut headers: SmallVec<[HttpHeader<'a>; HEADERS_STACK_STORAGE_SIZE]> = SmallVec::new();
        let mut multiline_header_name: Option<HttpToken> = None;
        let mut media_type = false;

        loop {
            let mut header_line = buffer.next_token(LF);
            if !header_line.trim_last_cr() {
                HttpRequestData::report_partial_line_termination(
                    "Header line is \\n terminated (not \\r\\n)",
                    parse_state,
                );
            }
            if header_line.is_done() {
                // an empty line. Done parsing the header.
                break;
            }
            let multi_line = header_line.starts_with_rfc_whitespace();
            let first_token = header_line.next_token(COLON).as_http_token();

            if !multi_line && !header_line.is_partial() {
                media_type = first_token.eq_ignore_ascii_case(CONTENT_TYPE_HEADER_NAME);
                multiline_header_name = Some(first_token);
            }

            let (header_name, header_value) = if multi_line
                && multiline_header_name.is_some()
                && (media_type || header_line.is_partial())
            {
                // either we're in a context of a multiline header
                // and the line doesn't mimic a header (i.e. doesn't have ':' in the value)
                (
                    multiline_header_name.expect("Code bug. It must be present in this branch"),
                    first_token,
                )
            } else {
                // or it's a regular header
                // or a multiline mimicking a regular header (i.e. " Content-Length: 10").
                (first_token, header_line.as_http_token())
            };

            headers.push(HttpHeader::new(header_name, header_value));

            if !multi_line && header_line.is_partial() {
                HttpRequestData::report_missing_header_delimiter(header_name, parse_state);
            }

            if multi_line && !media_type {
                // Here we ignore multiline and treat them as regular headers starting with SP
                // 1. multiline headers are deprecated (except 'Content-Type').
                // 2. we'd like to make sure that the multiline header is not mimicking regular headers
                //    to trick some HTTP engines which trim the header name
                //    so " Transfer-Encoding: chunked" becomes "Transfer-Encoding: chunked"
                //    for one layer, while it's "invisible" to the other in the chain
                // See doc inside `handle_multiline_header`
                HttpRequestData::report_multiline_header(header_name, parse_state);
            }

            if buffer.is_partial() {
                HttpRequestData::report_missing_header_termination(parse_state);
                break;
            } else if buffer.is_done() {
                HttpRequestData::report_missing_empty_line(parse_state);
                break;
            }
        }
        headers
    }

    fn report_missing_empty_line(parse_state: &mut RequestAnalysisState<'a>) {
        upgrade_verdict!(
            parse_state,
            RequestSafetyTier::Ambiguous,
            ErrorMessage::from_message(
                ClassificationReason::MissingLastEmptyLine,
                "Did not find an empty line at the end of request header".to_string(),
            )
        );
    }

    fn report_partial_line_termination(
        message: &'a str,
        parse_state: &mut RequestAnalysisState<'a>,
    ) {
        upgrade_verdict!(
            parse_state,
            RequestSafetyTier::Acceptable,
            ErrorMessage::from_message(
                ClassificationReason::NonCrLfLineTermination,
                message.to_string(),
            )
        );
    }

    fn report_missing_header_delimiter(
        header_name: HttpToken<'a>,
        parse_state: &mut RequestAnalysisState<'a>,
    ) {
        upgrade_verdict!(
            parse_state,
            RequestSafetyTier::Ambiguous,
            ErrorMessage::from_message(
                ClassificationReason::MissingHeaderColon,
                format!("Header colon is missing: {}", to_quoted_ascii(header_name)),
            )
        );
    }

    fn report_missing_header_termination(parse_state: &mut RequestAnalysisState<'a>) {
        // the buffer was exhausted, however we expected more data
        upgrade_verdict!(
            parse_state,
            RequestSafetyTier::Ambiguous,
            ErrorMessage::from_message(
                ClassificationReason::PartialHeaderLine,
                "A header line is not terminated".to_string(),
            )
        );
    }

    fn report_multiline_header(
        header_name: HttpToken<'a>,
        parse_state: &mut RequestAnalysisState<'a>,
    ) {
        // Historically, HTTP header field values could be extended over multiple lines by
        // preceding each extra line with at least one space or horizontal tab (obs-fold).
        // This specification deprecates such line folding except within the message/http media
        // type (Section 8.3.1). A sender MUST NOT generate a message that includes line folding
        // (i.e., that has any field-value that contains a match to the obs-fold rule) unless the message
        // is intended for packaging within the message/http media type.
        // https://tools.ietf.org/html/rfc7230#section-3.2.4
        upgrade_verdict!(
            parse_state,
            RequestSafetyTier::Ambiguous,
            ErrorMessage::from_message(
                ClassificationReason::MultilineHeader,
                format!("Multiline header found: {}", to_quoted_ascii(header_name)),
            )
        );
    }
}

impl<'a> RequestAnalysisState<'a> {
    /// Upgrades the result severity depending on a header's tier and importance
    /// If the header is essential, it overrides the same severity from a non-essential header.
    /// Otherwise, it changes the severity, if it's strictly higher.
    fn upgrade_from_header_tier(&mut self, header: &HttpHeader<'a>) {
        if self.tier == RequestSafetyTier::Severe {
            // Already the highest severity. Do nothing
            // as we want to preserve the first message
            return;
        }

        use HeaderSafetyTier::*;

        let (upgrade_to_tier, reason) = match header.tier {
            Bad => (RequestSafetyTier::Severe, ClassificationReason::BadHeader),
            NonCompliant => (
                RequestSafetyTier::Acceptable,
                ClassificationReason::NonCompliantHeader,
            ),
            Compliant => return, // No action for compliant headers
        };

        upgrade_verdict!(
            self,
            upgrade_to_tier,
            ErrorMessage::from_header(reason, header.clone())
        );
    }
}

impl<'a> HttpRequestData<'a> {
    /// Parse and analyze a raw HTTP request.
    /// This is the most consistent option, but comes with additional overhead, roughly doubled
    /// compared to `analyze_parsed_request`. See benchmarks for more info.
    pub fn analyze_raw_request(buf: HttpToken<'a>) -> RequestAnalysisResult {
        let (mut request, state) = HttpRequestData::parse(buf);
        request.analyze_request_internal(state)
    }

    /// If the HTTP engine doesn't sanitize data and is not lenient in parsing
    /// requests (e.g. doesn't treat "\n\r" as a valid line separator), then to avoid
    /// double parsing this method can be used.
    pub fn analyze_parsed_request(&mut self) -> RequestAnalysisResult {
        self.analyze_request_internal(RequestAnalysisState {
            tier: RequestSafetyTier::Compliant,
            reason: ClassificationReason::Compliant,
            error_message: None,
        })
    }

    /// Analyzes a request and returns a result (safety-tier + message + auxiliary info)
    fn analyze_request_internal(
        &mut self,
        mut analysis_state: RequestAnalysisState<'a>,
    ) -> RequestAnalysisResult {
        // H2+ validation is not supported
        if self.version >= HTTP_2 {
            return RequestAnalysisResult {
                tier: RequestSafetyTier::Compliant,
                reason: ClassificationReason::Compliant,
                message: None,
            };
        }
        // empty version means HTTP/0.9
        if rfc_whitespace_trim(self.version).is_empty() {
            self.version = HTTP_0_9
        }

        let mut te_indexes: SmallVec<[usize; 8]> = SmallVec::new();
        let mut cl_indexes: SmallVec<[usize; 4]> = SmallVec::new();

        for (idx, header) in self.headers.iter_mut().enumerate() {
            let te_similarity = determine_similarity(TE, header.name);

            let cl_similarity = if te_similarity == Distant {
                determine_similarity(CL, header.name)
            } else {
                Distant
            };

            header.is_essential = te_similarity == Identical || cl_similarity == Identical;

            header.tier = header.header_tier();
            analysis_state.upgrade_from_header_tier(&header);

            let trimmed_name = rfc_whitespace_trim(header.name);
            if trimmed_name.is_empty() || is_colon(trimmed_name[0]) {
                header.tier = Bad;
                upgrade_verdict!(
                    analysis_state,
                    RequestSafetyTier::Ambiguous,
                    ErrorMessage::from_header(ClassificationReason::EmptyHeader, header.clone())
                );
            } else if !header.is_essential && header.tier != HeaderSafetyTier::Bad {
                let suspicious_header = if te_similarity == SameLetters {
                    te_indexes.push(idx);
                    Some(TE)
                } else if cl_similarity == SameLetters {
                    cl_indexes.push(idx);
                    Some(CL)
                } else {
                    None
                };
                if let Some(important_header) = suspicious_header {
                    header.tier = NonCompliant;
                    upgrade_verdict!(
                        analysis_state,
                        RequestSafetyTier::Ambiguous,
                        ErrorMessage::from_message(
                            ClassificationReason::SuspiciousHeader,
                            format!(
                                "{} too close to {}",
                                header,
                                to_quoted_ascii(important_header)
                            ),
                        )
                    );
                }
            } else if te_similarity == Identical {
                te_indexes.push(idx);
            } else if cl_similarity == Identical {
                cl_indexes.push(idx);
            }
        }

        self.verify_te_cl_headers(&mut analysis_state, &te_indexes, &cl_indexes);

        self.check_method(&mut analysis_state);

        self.check_version(&mut analysis_state);

        self.check_uri(&mut analysis_state);

        let result = self.create_analysis_result(analysis_state);

        self.emit_logs_and_metrics(&result);

        result
    }

    fn create_analysis_result(
        &self,
        analysis_state: RequestAnalysisState,
    ) -> RequestAnalysisResult {
        let message = if let Some(error_message) = analysis_state.error_message.as_ref() {
            Some(format!(
                "{}, {:?}:  {}",
                to_quoted_ascii(self.method),
                analysis_state.tier,
                error_message,
            ))
        } else {
            None
        };
        RequestAnalysisResult {
            tier: analysis_state.tier,
            reason: analysis_state.reason,
            message,
        }
    }

    fn emit_logs_and_metrics(&mut self, result: &RequestAnalysisResult) {
        TIER_STATS.update_counters(&self, &result);
        CLASSIFICATION_STATS.update_counters(&self, &result);
        if let Some(message) = &result.message {
            LoggingSettings::log_message(result.tier, &message);
        }
    }

    fn check_uri(&mut self, result: &mut RequestAnalysisState) {
        for c in self.uri {
            let ch = *c;
            if is_valid_uri_char(ch) {
                // do nothing
            } else if is_bad_http_character(ch) {
                upgrade_verdict!(
                    result,
                    RequestSafetyTier::Severe,
                    ErrorMessage::from_message(
                        ClassificationReason::BadUri,
                        obfuscate_value(self.uri)
                    )
                );
                break;
            } else if is_space(ch) {
                // spaces are rejected by some web-engines
                // some allow it.
                // however, if it didn't end up with messing the request line
                // it's OK. If it did, it would break the protocol anyway and it is checked separately.
                upgrade_verdict!(
                    result,
                    RequestSafetyTier::Acceptable,
                    ErrorMessage::from_message(
                        ClassificationReason::SpaceInUri,
                        obfuscate_value(self.uri)
                    )
                );
            } else {
                upgrade_verdict!(
                    result,
                    RequestSafetyTier::Ambiguous,
                    ErrorMessage::from_message(
                        ClassificationReason::AmbiguousUri,
                        obfuscate_value(self.uri)
                    )
                );
            }
        }
    }

    fn check_method(&mut self, result: &mut RequestAnalysisState) {
        for c in self.method {
            if !is_rfc_tchar(*c) {
                upgrade_verdict!(
                    result,
                    RequestSafetyTier::Severe,
                    ErrorMessage::from_message(
                        ClassificationReason::BadMethod,
                        to_quoted_ascii(self.method)
                    )
                );
                break;
            }
        }
    }

    fn check_version(&mut self, result: &mut RequestAnalysisState) {
        // more lightweight that RegExp
        let trimmed = rfc_whitespace_trim(self.version);
        if trimmed == HTTP_0_9 {
            // HTTP/0.9 doesn't have RFC
            upgrade_verdict!(
                result,
                RequestSafetyTier::Acceptable,
                ErrorMessage::from_message(
                    ClassificationReason::NonCompliantVersion,
                    to_quoted_ascii(self.version)
                )
            );
            return;
        }
        let valid_version = trimmed.len() == HTTP_1_1.len()
            && trimmed.starts_with(HTTP_1_)
            && trimmed[HTTP_1_.len()].is_ascii_digit();

        if !valid_version {
            upgrade_verdict!(
                result,
                RequestSafetyTier::Severe,
                ErrorMessage::from_message(
                    ClassificationReason::BadVersion,
                    to_quoted_ascii(self.version)
                )
            );
        } else if trimmed.len() != self.version.len() || trimmed[HTTP_1_.len()] > b'1' {
            // versions like HTTP/1.2 are not harmful, but are not compliant either
            // as well as extra spaces around the version
            upgrade_verdict!(
                result,
                RequestSafetyTier::Acceptable,
                ErrorMessage::from_message(
                    ClassificationReason::NonCompliantVersion,
                    to_quoted_ascii(self.version)
                )
            );
        }
    }

    /// Checks if Transfer-Encoding and Content-Length headers are in order.
    fn verify_te_cl_headers(
        &mut self,
        result_tier: &mut RequestAnalysisState<'a>,
        te_indexes: &[usize],
        cl_indexes: &[usize],
    ) {
        if te_indexes.is_empty() && cl_indexes.is_empty() {
            // nothing to do
            return;
        }

        if self.not_valid_for_predecessor_versions(result_tier, te_indexes, cl_indexes) {
            return;
        }

        let has_te = self.has_transfer_encoding(result_tier, &te_indexes);

        let cl_value = self.extract_content_length(result_tier, &cl_indexes);

        if self.method_without_body() {
            self.check_te_for_get_head(result_tier, has_te, te_indexes);
            self.check_cl_for_get_head(result_tier, cl_value, cl_indexes);
        }

        if cl_value.is_some() && has_te {
            self.mark_all_as(cl_indexes, HeaderSafetyTier::Bad);
            upgrade_verdict!(
                result_tier,
                RequestSafetyTier::Ambiguous,
                ErrorMessage::from_header(
                    ClassificationReason::BothTeClPresent,
                    self.headers[cl_indexes[0]].clone(),
                )
            );
        }
    }

    fn not_valid_for_predecessor_versions(
        &mut self,
        result_tier: &mut RequestAnalysisState,
        te_indexes: &[usize],
        cl_indexes: &[usize],
    ) -> bool {
        if self.version <= HTTP_1_0 && !te_indexes.is_empty() {
            {
                upgrade_verdict!(
                    result_tier,
                    RequestSafetyTier::Ambiguous,
                    ErrorMessage::from_message(
                        ClassificationReason::UndefinedTransferEncodingSemantics,
                        to_quoted_ascii(self.version),
                    )
                );
            }
            // mark all message-body headers as bad
            // as at this point it's not clear how to interpret them
            self.mark_all_as(te_indexes, HeaderSafetyTier::NonCompliant);
            self.mark_all_as(cl_indexes, HeaderSafetyTier::Bad);
            true
        } else if self.version < HTTP_1_0 && !cl_indexes.is_empty() {
            {
                upgrade_verdict!(
                    result_tier,
                    RequestSafetyTier::Ambiguous,
                    ErrorMessage::from_message(
                        ClassificationReason::UndefinedContentLengthSemantics,
                        to_quoted_ascii(self.version),
                    )
                );
            }
            // mark all message-body headers as bad
            // as at this point it's not clear how to interpret them
            self.mark_all_as(cl_indexes, HeaderSafetyTier::NonCompliant);
            true
        } else {
            false
        }
    }

    fn mark_all_as(&mut self, indexes: &[usize], tier: HeaderSafetyTier) {
        indexes.iter().for_each(|i| {
            if self.headers[*i].tier < tier {
                self.headers[*i].tier = tier;
            }
        });
    }

    fn method_without_body(&self) -> bool {
        // https://tools.ietf.org/html/rfc7231#section-4.3
        // A payload within a GET/HEAD request message has no defined semantics.
        self.method == GET || self.method == HEAD
    }

    /// Checks if a GET/HEAD request doesn't contain TE (otherwise it's Ambiguous)
    fn check_te_for_get_head(
        &mut self,
        result_tier: &mut RequestAnalysisState<'a>,
        has_te: bool,
        te_indexes: &[usize],
    ) {
        debug_assert!(self.method_without_body());

        if has_te {
            upgrade_verdict!(
                result_tier,
                RequestSafetyTier::Ambiguous,
                ErrorMessage::from_message(
                    ClassificationReason::UndefinedTransferEncodingSemantics,
                    format!("{} has Transfer-Encoding", to_quoted_ascii(self.method)),
                )
            );
            self.mark_all_as(te_indexes, HeaderSafetyTier::NonCompliant);
        }
    }

    /// Checks if a GET/HEAD request doesn't contain CL (otherwise it's Ambiguous or Acceptable)
    fn check_cl_for_get_head(
        &mut self,
        result_tier: &mut RequestAnalysisState<'a>,
        cl_value: Option<u64>,
        cl_indexes: &[usize],
    ) {
        debug_assert!(self.method_without_body());

        match cl_value {
            Some(cl) if cl == 0 => {
                upgrade_verdict!(
                    result_tier,
                    RequestSafetyTier::Acceptable,
                    ErrorMessage::from_message(
                        ClassificationReason::GetHeadZeroContentLength,
                        format!("{} has Content-Length:0", to_quoted_ascii(self.method)),
                    )
                );
            }
            Some(cl) if cl > 0 => {
                upgrade_verdict!(
                    result_tier,
                    RequestSafetyTier::Ambiguous,
                    ErrorMessage::from_message(
                        ClassificationReason::UndefinedContentLengthSemantics,
                        format!(
                            "{} has Content-Length: {}",
                            to_quoted_ascii(self.method),
                            cl
                        ),
                    )
                );
            }
            _ => return,
        }
        self.mark_all_as(cl_indexes, HeaderSafetyTier::NonCompliant);
    }

    /// Extracts the `Content-Length` value, if present.
    /// If there are duplicate/multiple values updates the result accordingly.
    fn extract_content_length(
        &mut self,
        result_tier: &mut RequestAnalysisState<'a>,
        cl_indexes: &[usize],
    ) -> Option<u64> {
        let mut content_length_value: Option<u64> = None;
        let mut all_bad = false;
        for i in cl_indexes {
            let cl = &mut self.headers[*i];
            match parse_num(cl.value) {
                Ok(new_v) => {
                    match content_length_value {
                        Some(v) if v != new_v => {
                            all_bad = true;
                            upgrade_verdict!(
                                result_tier,
                                RequestSafetyTier::Severe,
                                ErrorMessage::from_header(
                                    ClassificationReason::MultipleContentLength,
                                    cl.clone()
                                )
                            );
                        }
                        Some(v) if v == new_v => {
                            cl.tier = HeaderSafetyTier::Bad;
                            upgrade_verdict!(
                                result_tier,
                                RequestSafetyTier::Ambiguous,
                                ErrorMessage::from_header(
                                    ClassificationReason::DuplicateContentLength,
                                    cl.clone()
                                )
                            );
                        }
                        _ => content_length_value = Some(new_v),
                    };
                }
                Err(s) => {
                    all_bad = true;
                    upgrade_verdict!(
                        result_tier,
                        RequestSafetyTier::Severe,
                        ErrorMessage::from_message(
                            ClassificationReason::BadContentLength,
                            format!("{}: {}", cl.clone(), s),
                        )
                    );
                }
            }
        }
        if all_bad {
            self.mark_all_as(cl_indexes, HeaderSafetyTier::Bad);
        }
        content_length_value
    }

    /// Checks if the request's `Transfer-Encoding` headers are in order
    /// and returns `true` if it has at least one of them.
    fn has_transfer_encoding(
        &mut self,
        result_tier: &mut RequestAnalysisState<'a>,
        te_indexes: &[usize],
    ) -> bool {
        // Check only multiple "chunked" headers as it might confuse web-servers
        let mut has_te_chunked = false;
        let mut all_bad = false;
        for i in te_indexes {
            let te = &mut self.headers[*i];
            let te_values: SmallVec<[HttpToken; 8]> = te.value.split(|c| *c == b',').collect();

            for te_item in te_values {
                match is_valid_te(te_item) {
                    Some(val) => {
                        let is_chunked = CHUNKED == val;
                        if has_te_chunked && is_chunked {
                            all_bad = true;
                            te.tier = HeaderSafetyTier::Bad;
                            upgrade_verdict!(
                                result_tier,
                                RequestSafetyTier::Severe,
                                ErrorMessage::from_header(
                                    ClassificationReason::MultipleTransferEncodingChunked,
                                    te.clone()
                                )
                            );
                        }
                        has_te_chunked = is_chunked;
                    }
                    None => {
                        te.tier = HeaderSafetyTier::Bad;
                        upgrade_verdict!(
                            result_tier,
                            RequestSafetyTier::Severe,
                            ErrorMessage::from_header(
                                ClassificationReason::BadTransferEncoding,
                                te.clone()
                            )
                        );
                    }
                }
            }
        }
        if all_bad {
            self.mark_all_as(te_indexes, HeaderSafetyTier::Bad);
        }
        !te_indexes.is_empty()
    }
}

impl<'a> HttpHeader<'a> {
    ///
    /// Creates a new instance of a header.
    /// # Parameters
    /// `name` - header name
    /// `value` - header value
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn new(name: HttpToken<'a>, value: HttpToken<'a>) -> Self {
        Self {
            name,
            value,
            is_essential: false,
            tier: Compliant,
        }
    }

    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn get_tier(&self) -> HeaderSafetyTier {
        self.tier
    }

    /// Safety tier of the header name.
    fn field_name_tier(&self) -> HeaderSafetyTier {
        let name = self.name;
        let mut result = HeaderSafetyTier::Compliant;
        for c in name {
            let ch = *c;
            if !is_rfc_tchar(ch) {
                if is_bad_http_character(ch) {
                    result = HeaderSafetyTier::Bad;
                    break;
                } else {
                    result = HeaderSafetyTier::NonCompliant
                }
            }
        }
        result
    }

    /// Safety tier of the header value.
    fn field_value_tier(&self) -> HeaderSafetyTier {
        let value = self.value;
        let mut result = HeaderSafetyTier::Compliant;

        for c in value {
            let ch = *c;
            if !is_valid_header_value_char(ch) {
                if is_bad_http_character(ch) {
                    result = HeaderSafetyTier::Bad;
                    break;
                } else {
                    result = HeaderSafetyTier::NonCompliant
                }
            }
        }
        result
    }

    /// Calculates the HTTP header safety tier based on both name and value.
    fn header_tier(&self) -> HeaderSafetyTier {
        let name_tier = self.field_name_tier();
        let value_tier = self.field_value_tier();
        // important headers cannot have non-RFC compliant values
        if name_tier > value_tier {
            name_tier
        } else {
            value_tier
        }
    }
}

impl Display for RequestAnalysisResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        if let Some(message) = self.message.as_ref() {
            write!(f, "{}", message,)
        } else {
            write!(f, "Compliant")
        }
    }
}

impl<'a> Display for RequestAnalysisState<'a> {
    #[cfg_attr(feature = "coverage", inline(never))]
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        if let Some(error_message) = self.error_message.as_ref() {
            write!(f, "{:?}: {}", self.tier, error_message,)
        } else {
            write!(f, "Compliant")
        }
    }
}

impl<'a> Display for HttpHeader<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "{}: {}, tier: {:?}",
            to_quoted_ascii(self.name),
            if self.is_essential {
                to_quoted_ascii(self.value)
            } else {
                obfuscate_value(self.value)
            },
            self.tier,
        )
    }
}

impl<'a> Display for HttpRequestData<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        write!(
            f,
            "Method={}, Url={}, Version={}, Headers=",
            to_quoted_ascii(self.method),
            obfuscate_value(self.uri),
            to_quoted_ascii(self.version),
        )?;
        const IMPORTANT_HEADERS: &[HttpToken] = &[TE, CL];
        for (count, header) in self.headers.iter().enumerate() {
            let print_full_value = IMPORTANT_HEADERS
                .iter()
                .map(|important_header| determine_similarity(important_header, header.name))
                .any(|similarity| similarity <= SameLetters);

            if count != 0 {
                write!(f, ", ")?;
            }

            write!(
                f,
                "{}: {}, tier: {:?}",
                to_quoted_ascii(header.name),
                if print_full_value {
                    to_quoted_ascii(header.value)
                } else {
                    obfuscate_value(header.value)
                },
                header.tier,
            )?;
        }
        Ok(())
    }
}

impl<'a> Display for ErrorMessage<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        if let Some(header) = self.header.as_ref() {
            write!(f, "{:?} {}", self.reason_message, header)
        } else if let Some(details) = self.details.as_ref() {
            write!(f, "{:?} {}", self.reason_message, details)
        } else {
            write!(f, "{:?}", self.reason_message)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::http_token_utils::{http_token, to_quoted_ascii, HttpToken};
    use crate::request_analyzer::{HttpHeader, HttpRequestData, GET, HTTP_1_1};
    use crate::ClassificationReason::*;
    use crate::RequestSafetyTier::*;
    use crate::{ClassificationReason, HeaderSafetyTier, RequestSafetyTier};
    use smallvec::smallvec;
    use std::collections::{HashMap, HashSet};
    use std::io::Read;
    use std::ops::AddAssign;
    use std::panic::catch_unwind;
    use yaml_rust::YamlLoader;
    const EMPTY_TOKEN: HttpToken = http_token("");

    #[test]
    fn test_field_name_tier() {
        let test_cases = vec![
            ("header-ok", HeaderSafetyTier::Compliant),
            ("CAPITALS-OK", HeaderSafetyTier::Compliant),
            ("header_ok", HeaderSafetyTier::Compliant),
            ("tchars-ok-.!#$%&'*+^_`|~", HeaderSafetyTier::Compliant),
            (" space-not-ok", HeaderSafetyTier::NonCompliant),
            ("tab-not-ok\t", HeaderSafetyTier::NonCompliant),
            ("\u{1}CTL-not-ok\t", HeaderSafetyTier::NonCompliant),
            ("\u{1f}CTL-not-ok\t", HeaderSafetyTier::NonCompliant),
            ("\u{7F}CTL-not-ok\t", HeaderSafetyTier::NonCompliant),
            ("caret-not-accepted\r", HeaderSafetyTier::Bad),
            ("line-not-accepted\n", HeaderSafetyTier::Bad),
            ("nil-not-accepted\x00", HeaderSafetyTier::Bad),
        ];
        test_cases.iter().for_each(|(text, result)| {
            let header = HttpHeader::new(http_token(text), http_token("compliant-text"));
            assert_eq!(header.field_name_tier(), *result, "{}", text);
        });
    }

    #[test]
    fn test_field_value_tier() {
        let test_cases = vec![
            ("normal_text", HeaderSafetyTier::Compliant),
            ("\t\tOWS \t   ", HeaderSafetyTier::Compliant),
            (
                "obs-text\u{60}\u{85}\u{93}\u{A0}",
                HeaderSafetyTier::Compliant,
            ),
            (
                "field content\t\tmay have \t\twhite-spaces",
                HeaderSafetyTier::Compliant,
            ),
            ("\u{01}s are non compliant", HeaderSafetyTier::NonCompliant),
            ("\u{7f}s are non compliant", HeaderSafetyTier::NonCompliant),
            ("\u{00} is bad", HeaderSafetyTier::Bad),
            ("\r is bad", HeaderSafetyTier::Bad),
            ("\n is bad", HeaderSafetyTier::Bad),
        ];
        test_cases.iter().for_each(|(text, result)| {
            let header = HttpHeader::new(http_token("compliant-name"), http_token(text));
            assert_eq!(header.field_value_tier(), *result)
        });
    }

    #[test]
    fn test_header_tier() {
        let test_cases = vec![
            (
                HttpHeader::new(http_token("ok-header"), http_token("ok-text")),
                HeaderSafetyTier::Compliant,
            ),
            (
                HttpHeader::new(http_token("not-ok-header\t"), http_token("ok-text")),
                HeaderSafetyTier::NonCompliant,
            ),
            (
                HttpHeader::new(http_token("ok-header"), http_token("not-ok-text\u{11}")),
                HeaderSafetyTier::NonCompliant,
            ),
            (
                HttpHeader {
                    name: http_token("essential-header"),
                    value: http_token("not-ok-text-makes-it-noncompliant\u{11}"),
                    is_essential: false,
                    tier: HeaderSafetyTier::Compliant,
                },
                HeaderSafetyTier::NonCompliant,
            ),
        ];
        test_cases.iter().for_each(|(header, result)| {
            assert_eq!(
                header.header_tier(),
                *result,
                "{}: {}",
                to_quoted_ascii(header.name),
                to_quoted_ascii(header.value)
            );
        });
    }

    struct TestCase {
        name: String,
        uri: String,
        method: String,
        version: String,
        headers: Vec<TestCaseHeader>,
        expected: TestCaseExpected,
    }

    struct TestCaseHeader {
        name: String,
        value: String,
        tier: String,
    }

    struct TestCaseExpected {
        tier: String,
        reason: String,
        required_message_items: Vec<String>,
    }

    fn unescape_value(s: &str) -> String {
        let mut result = String::with_capacity(s.len());
        let mut chars = s.chars();
        while let Some(ch) = chars.next() {
            result.push(if ch != '\\' {
                ch
            } else {
                match chars.next() {
                    Some('x') => {
                        let value = chars
                            .by_ref()
                            .take(2)
                            .fold(0, |acc, c| acc * 16 + c.to_digit(16).unwrap())
                            as u8;
                        char::from(value)
                    }
                    Some('b') => '\x08',
                    Some('f') => '\x0c',
                    Some('n') => '\n',
                    Some('r') => '\r',
                    Some('t') => '\t',
                    Some(ch) => ch,
                    _ => panic!("Malformed escape"),
                }
            })
        }
        result
    }

    /// We'd like to have a human-friendly error reporting of errors in test-case YAML files
    macro_rules! extract_value {
        ($v: ident, $yaml: expr, $field_name: expr) => {
            match $v[$field_name].as_str() {
                Some(s) => unescape_value(s),
                None => match $v[$field_name].as_i64() {
                    Some(n) => format!("{}", n),
                    None => panic!(
                        "Test case [{}] has missing field [{}]",
                        $yaml["name"].as_str().unwrap(),
                        $field_name
                    ),
                },
            }
        };
        (map $v: expr, $yaml: expr, $field_name: expr) => {
            match $v.as_str() {
                Some(s) => unescape_value(s),
                None => panic!(
                    "Test case [{}] has invalid field [{}]",
                    $yaml["name"].as_str().unwrap(),
                    $field_name
                ),
            }
        };
        ($v: ident, $field_name:expr) => {
            match $v[$field_name].as_str() {
                Some(s) => unescape_value(s),
                None => panic!(
                    "Test case [{}] has missing field [{}]",
                    $v["name"].as_str().unwrap(),
                    $field_name
                ),
            }
        };
    }

    #[test]
    fn file_tests() {
        let count: Vec<(i32, i32)> = vec![
            test_file("tests/single-case.yaml"), // for faster debugging of single cases
            test_file("tests/edge-cases.yaml"),
            test_file("tests/rfc-compliant.yaml"),
            test_file("tests/acceptable.yaml"),
            test_file("tests/ambiguous.yaml"),
            test_file("tests/bad-header-characters.yaml"),
            test_file("tests/more-compliant-tests.yaml"),
            test_file("tests/severe.yaml"),
            test_file("tests/uri-specific-test-cases.yaml"),
            test_file("tests/real-life-test-cases.yaml"),
        ];

        let total: i32 = count.iter().map(|(t, _)| *t).sum();
        let failed: i32 = count.iter().map(|(_, f)| *f).sum();
        println!(
            "Total: Test cases: {}, Passed: {}, Failed: {}",
            total,
            total - failed,
            failed
        );
        assert_eq!(failed, 0);
    }

    fn test_file(file_name: &str) -> (i32, i32) {
        let mut f = match std::fs::File::open(file_name) {
            Ok(file) => file,
            Err(e) => panic!("Error reading file {}: {}", file_name, e),
        };
        let mut yaml_string = String::new();

        match f.read_to_string(&mut yaml_string) {
            Ok(_) => {}
            Err(e) => panic!("Failed to read file {} with error {}", file_name, e),
        };

        let all_yaml = YamlLoader::load_from_str(yaml_string.as_str())
            .expect(format!("File {} is not valid yaml", file_name).as_str());
        let test_cases = all_yaml[0].as_vec().unwrap();
        let mut failed: usize = 0;
        let test_case_count: usize = test_cases.len();

        for ti in 0..test_case_count {
            let test_case = &test_cases[ti];
            let headers: Vec<TestCaseHeader> = match test_case["headers"].as_vec() {
                Some(v) => v
                    .iter()
                    .map(|hdr| TestCaseHeader {
                        name: extract_value!(hdr, test_case, "name"),
                        value: extract_value!(hdr, test_case, "value"),
                        tier: extract_value!(hdr, test_case, "tier"),
                    })
                    .collect(),
                None => vec![],
            };

            let message: Vec<String> =
                match test_case["expected"]["required_message_items"].as_vec() {
                    Some(v) => v
                        .iter()
                        .map(|item| extract_value!(map item, test_case, "required_message_items"))
                        .collect(),
                    None => vec![],
                };
            let case_name = match test_case["name"].as_str() {
                Some(s) => s.to_string(),
                None => panic!("Test case has no name {:?}", test_case),
            };

            let case: TestCase = TestCase {
                name: case_name,
                uri: extract_value!(test_case, "uri"),
                version: extract_value!(test_case, "version"),
                method: extract_value!(test_case, "method"),
                expected: TestCaseExpected {
                    tier: extract_value!(map test_case["expected"]["tier"], test_case, "expected.tier"),
                    reason: extract_value!(map test_case["expected"]["reason"], test_case, "expected.reason"),
                    required_message_items: message,
                },
                headers,
            };

            match catch_unwind(|| run_test_case(&case)) {
                Ok(_) => println!("Test {}: passed.", case.name),
                Err(_) => {
                    failed += 1;
                    println!("Test {}: failed.", case.name)
                }
            };
        }
        println!("{}", std::iter::repeat('-').take(80).collect::<String>());
        println!(
            "Test suite \"{}\": Test cases: {}, Passed: {}, Failed: {}",
            file_name,
            test_case_count,
            test_case_count - failed,
            failed
        );
        println!("{}\n", std::iter::repeat('=').take(80).collect::<String>());

        (test_case_count as i32, failed as i32)
    }

    fn run_test_case(case: &TestCase) {
        use std::fmt::Write;

        let uri = case.uri.to_owned();
        let version = case.version.to_owned();
        let method = case.method.to_owned();
        let mut headers: Vec<(String, String, HeaderSafetyTier)> = Vec::new();

        for h in &case.headers {
            let tier = match h.tier.as_str() {
                "Compliant" => HeaderSafetyTier::Compliant,
                "NonCompliant" => HeaderSafetyTier::NonCompliant,
                "Bad" => HeaderSafetyTier::Bad,
                _ => panic!(
                    "Bad test case. Tier must be one of Compliant, NonCompliant, Bad. But was [{}]",
                    h.tier
                ),
            };
            headers.push((h.name.to_owned(), h.value.to_owned(), tier));
        }
        let original_headers: Vec<HttpHeader> = headers
            .iter()
            .map(|h| HttpHeader {
                name: http_token(&h.0),
                value: http_token(&h.1),
                is_essential: false,
                tier: h.2,
            })
            .collect();

        let mut request = HttpRequestData {
            uri: http_token(&uri),
            version: http_token(&version),
            method: http_token(&method),
            headers: original_headers.iter().map(|h| h.clone()).collect(),
        };

        // build a raw request to make sure classification is consistent
        let mut raw_request = String::new();
        write!(raw_request, "{} {} {}\r\n", method, uri, version).ok();
        case.headers.iter().for_each(|h| {
            write!(raw_request, "{}: {}\r\n", h.name, h.value).ok();
        });
        write!(raw_request, "\r\n").ok();

        let verdict = request.analyze_parsed_request();
        let raw_verdict = HttpRequestData::analyze_raw_request(raw_request.as_bytes());

        let expectation = match case.expected.tier.as_str() {
            "Compliant" => RequestSafetyTier::Compliant,
            "Acceptable" => RequestSafetyTier::Acceptable,
            "Ambiguous" => RequestSafetyTier::Ambiguous,
            "Severe" => RequestSafetyTier::Severe,
            _ => panic!("Bad test case. Tier must be one of Compliant, Acceptable, Ambiguous, Severe. But was [{}]", case.expected.tier),
        };

        println!(
            "Verdict expected: {:?} => parsed: {}, raw: {}",
            expectation, verdict, raw_verdict
        );
        assert_eq!(verdict.tier, expectation, "Parsed: Case {}", case.name);
        // some parsing errors may affect the reason and tier
        // due to differences in construction of the raw request.
        if ![
            ClassificationReason::MultilineHeader,
            ClassificationReason::MissingHeaderColon,
            ClassificationReason::SpaceInUri,
            ClassificationReason::AmbiguousUri,
            ClassificationReason::NonCrLfLineTermination,
        ]
        .contains(&raw_verdict.reason)
        {
            assert_eq!(
                raw_verdict.tier, expectation,
                "Raw: Case {}, reason: {:?}",
                case.name, raw_verdict.reason
            );
        } else {
            assert_ne!(verdict.tier, RequestSafetyTier::Compliant);
        }
        assert_eq!(
            format!("{:?}", verdict.reason),
            case.expected.reason,
            "Case {}",
            case.name
        );
        assert_message_contains_all_items(&case, verdict.to_string());

        for (i, header) in request.headers.iter().enumerate() {
            assert_eq!(
                header.tier,
                original_headers[i].tier,
                "Case {}, header {}",
                case.name,
                to_quoted_ascii(original_headers[i].name)
            );
        }
    }

    fn assert_message_contains_all_items(case: &TestCase, s: String) {
        case.expected.required_message_items.iter().for_each(|m| {
            assert!(
                s.to_lowercase().contains(m.to_lowercase().as_str()),
                format!("Case {}. Expected '{}' to be in '{}'", case.name, m, s)
            );
        });
    }

    #[test]
    fn test_no_headers() {
        let mut request = HttpRequestData {
            uri: http_token("/foo/bar"),
            version: HTTP_1_1,
            method: GET,
            headers: smallvec!(),
        };

        let verdict = request.analyze_parsed_request();

        assert_eq!(verdict.tier, RequestSafetyTier::Compliant);
    }

    #[test]
    fn test_very_many_headers() {
        let mut headers = smallvec!();
        for _ in 0..200 {
            headers.push(HttpHeader {
                name: http_token("name"),
                value: http_token("value"),
                is_essential: false,
                tier: HeaderSafetyTier::Compliant,
            })
        }
        for _ in 0..100 {
            headers.push(HttpHeader {
                name: http_token("transfer-encoding"),
                value: http_token("chunked"),
                is_essential: false,
                tier: HeaderSafetyTier::Compliant,
            })
        }
        for _ in 0..100 {
            headers.push(HttpHeader {
                name: http_token("content-length"),
                value: http_token("500"),
                is_essential: false,
                tier: HeaderSafetyTier::Compliant,
            })
        }
        let mut request = HttpRequestData {
            uri: http_token("/foo/bar"),
            version: HTTP_1_1,
            method: GET,
            headers,
        };

        let verdict = request.analyze_parsed_request();

        assert_eq!(verdict.tier, RequestSafetyTier::Severe);
    }

    #[test]
    fn test_very_many_headers_raw() {
        use std::fmt::Write;
        let mut request = String::new();
        write!(request, "GET /foo HTTP/1.1\r\n").ok();
        for _ in 0..200 {
            write!(request, "name: value\r\n").ok();
        }
        for _ in 0..100 {
            write!(request, "transfer-encoding: chunked\r\n").ok();
        }
        for _ in 0..100 {
            write!(request, "content-length: 500\r\n").ok();
        }
        write!(request, "\r\n").ok();

        let (parsed_request, state) = HttpRequestData::parse(request.as_bytes());
        assert_eq!(
            state.tier,
            RequestSafetyTier::Compliant,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(parsed_request.headers.len(), 400);

        let verdict = HttpRequestData::analyze_raw_request(request.as_bytes());

        assert_eq!(verdict.tier, RequestSafetyTier::Severe);
    }

    #[test]
    fn test_te_ok() {
        let mut request = HttpRequestData {
            uri: http_token("/foo/bar"),
            version: HTTP_1_1,
            method: http_token("POST"),
            headers: smallvec!(HttpHeader::new(
                http_token("Transfer-Encoding"),
                http_token("chunked")
            )),
        };

        let verdict = request.analyze_parsed_request();

        assert_eq!(verdict.tier, RequestSafetyTier::Compliant);
    }

    #[test]
    fn test_te_with_space() {
        let mut request = HttpRequestData {
            uri: http_token("/foo/bar"),
            version: HTTP_1_1,
            method: http_token("PUT"),
            headers: smallvec!(HttpHeader::new(
                http_token("Transfer-Encoding "),
                http_token("chunked")
            )),
        };

        let verdict = request.analyze_parsed_request();

        println!("{}", verdict);

        assert_eq!(verdict.tier, RequestSafetyTier::Ambiguous);
        assert_eq!(verdict.reason, ClassificationReason::SuspiciousHeader);
        assert!(verdict.message.is_some());
        assert!(
            verdict.to_string().contains("transfer-encoding"),
            "{}",
            verdict
        );
    }

    #[test]
    fn test_h2_not_analyzed() {
        let mut request = HttpRequestData {
            uri: http_token("/foo/bar"),
            version: http_token("HTTP/2"),
            method: http_token("PUT"),
            headers: smallvec!(HttpHeader::new(
                http_token("Transfer-Encoding "),
                http_token("chunked")
            )),
        };

        let verdict = request.analyze_parsed_request();

        assert_eq!(verdict.tier, RequestSafetyTier::Compliant);
        assert_eq!(verdict.reason, ClassificationReason::Compliant);
        assert!(verdict.message.is_none());
    }

    #[test]
    fn test_h3_not_analyzed() {
        let mut request = HttpRequestData {
            uri: http_token("/foo/bar"),
            version: http_token("HTTP/3"),
            method: http_token("PUT"),
            headers: smallvec!(HttpHeader::new(
                http_token("Transfer-Encoding "),
                http_token("chunked")
            )),
        };

        let verdict = request.analyze_parsed_request();

        assert_eq!(verdict.tier, RequestSafetyTier::Compliant);
        assert_eq!(verdict.reason, ClassificationReason::Compliant);
        assert!(verdict.message.is_none());
    }

    const GET_REQUEST: HttpToken = http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n\r\n");

    #[test]
    fn test_parse_request() {
        let (request, state) = HttpRequestData::parse(GET_REQUEST);
        assert_eq!(
            state.tier,
            RequestSafetyTier::Compliant,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(
            state.reason,
            ClassificationReason::Compliant,
            "{}",
            state.error_message.unwrap()
        );
        assert!(
            state.error_message.is_none(),
            "{}",
            state.error_message.unwrap()
        );

        assert_eq!(GET, request.method, "{}", to_quoted_ascii(request.method));
        assert_eq!(
            http_token("/foo/bar"),
            request.uri,
            "{}",
            to_quoted_ascii(request.uri)
        );
        assert_eq!(
            HTTP_1_1,
            request.version,
            "{}",
            to_quoted_ascii(request.version)
        );

        assert_eq!(1, request.headers.len());
        assert_eq!(
            http_token("Host"),
            request.headers[0].name,
            "{}",
            to_quoted_ascii(request.headers[0].name)
        );
        assert_eq!(
            http_token(" localhost"),
            request.headers[0].value,
            "{}",
            to_quoted_ascii(request.headers[0].value)
        );
    }

    #[test]
    fn test_parse_request_multiline() {
        let (request, state) = HttpRequestData::parse(http_token(
            "GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n another-line\r\n\r\n",
        ));
        assert_eq!(
            state.tier,
            RequestSafetyTier::Ambiguous,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(
            state.reason,
            ClassificationReason::MultilineHeader,
            "{}",
            state.error_message.unwrap()
        );
        assert!(
            state.error_message.is_some(),
            "{}",
            state.error_message.unwrap()
        );

        assert_eq!(GET, request.method, "{}", to_quoted_ascii(request.method));
        assert_eq!(
            http_token("/foo/bar"),
            request.uri,
            "{}",
            to_quoted_ascii(request.uri)
        );
        assert_eq!(
            HTTP_1_1,
            request.version,
            "{}",
            to_quoted_ascii(request.version)
        );

        assert_eq!(2, request.headers.len());
        assert_eq!(
            http_token("Host"),
            request.headers[0].name,
            "{}",
            to_quoted_ascii(request.headers[0].name)
        );
        assert_eq!(
            http_token(" localhost"),
            request.headers[0].value,
            "{}",
            to_quoted_ascii(request.headers[0].value)
        );
        assert_eq!(
            http_token("Host"),
            request.headers[1].name,
            "{}",
            to_quoted_ascii(request.headers[1].name)
        );
        assert_eq!(
            http_token(" another-line"),
            request.headers[1].value,
            "{}",
            to_quoted_ascii(request.headers[1].value)
        );
    }

    #[test]
    fn test_parse_request_first_multiline() {
        let (request, state) = HttpRequestData::parse(http_token(
            "GET /foo/bar HTTP/1.1\r\n Host: localhost\r\n\r\n",
        ));
        assert_eq!(
            state.tier,
            RequestSafetyTier::Ambiguous,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(
            state.reason,
            ClassificationReason::MultilineHeader,
            "{}",
            state.error_message.unwrap()
        );
        assert!(
            state.error_message.is_some(),
            "{}",
            state.error_message.unwrap()
        );

        assert_eq!(GET, request.method, "{}", to_quoted_ascii(request.method));
        assert_eq!(
            http_token("/foo/bar"),
            request.uri,
            "{}",
            to_quoted_ascii(request.uri)
        );
        assert_eq!(
            HTTP_1_1,
            request.version,
            "{}",
            to_quoted_ascii(request.version)
        );

        assert_eq!(1, request.headers.len());
        assert_eq!(
            http_token(" Host"),
            request.headers[0].name,
            "{}",
            to_quoted_ascii(request.headers[0].name)
        );
        assert_eq!(
            http_token(" localhost"),
            request.headers[0].value,
            "{}",
            to_quoted_ascii(request.headers[0].value)
        );
    }

    #[test]
    fn test_parse_request_missing_empty_line() {
        let (request, state) =
            HttpRequestData::parse(http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n"));
        assert_eq!(
            state.tier,
            RequestSafetyTier::Ambiguous,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(
            state.reason,
            ClassificationReason::MissingLastEmptyLine,
            "{}",
            state.error_message.unwrap()
        );
        assert!(
            state.error_message.is_some(),
            "{}",
            state.error_message.unwrap()
        );

        assert_eq!(1, request.headers.len());
        assert_eq!(
            http_token("Host"),
            request.headers[0].name,
            "{}",
            to_quoted_ascii(request.headers[0].name)
        );
        assert_eq!(
            http_token(" localhost"),
            request.headers[0].value,
            "{}",
            to_quoted_ascii(request.headers[0].value)
        );
    }

    #[test]
    fn test_parse_request_partial_header() {
        let (request, state) =
            HttpRequestData::parse(http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost"));
        assert_eq!(
            state.tier,
            RequestSafetyTier::Ambiguous,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(
            state.reason,
            ClassificationReason::PartialHeaderLine,
            "{}",
            state.error_message.unwrap()
        );
        assert!(
            state.error_message.is_some(),
            "{}",
            state.error_message.unwrap()
        );

        assert_eq!(1, request.headers.len());
        assert_eq!(
            http_token("Host"),
            request.headers[0].name,
            "{}",
            to_quoted_ascii(request.headers[0].name)
        );
        assert_eq!(
            http_token(" localhost"),
            request.headers[0].value,
            "{}",
            to_quoted_ascii(request.headers[0].value)
        );
    }

    #[test]
    fn test_parse_empty_header_name() {
        // an empty header name should pass parsing
        let (request, state) =
            HttpRequestData::parse(http_token("GET /foo/bar HTTP/1.1\r\n: localhost\r\n\r\n"));
        assert_eq!(
            state.tier,
            RequestSafetyTier::Compliant,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(
            state.reason,
            ClassificationReason::Compliant,
            "{}",
            state.error_message.unwrap()
        );
        assert!(
            state.error_message.is_none(),
            "{}",
            state.error_message.unwrap()
        );

        assert_eq!(1, request.headers.len());
        assert_eq!(
            EMPTY_TOKEN,
            request.headers[0].name,
            "{}",
            to_quoted_ascii(request.headers[0].name)
        );
        assert_eq!(
            http_token(" localhost"),
            request.headers[0].value,
            "{}",
            to_quoted_ascii(request.headers[0].value)
        );
    }

    #[test]
    fn test_parse_empty_header_name_double_colon() {
        // an empty header name should pass parsing
        let (request, state) =
            HttpRequestData::parse(http_token("GET /foo/bar HTTP/1.1\r\n:: localhost\r\n\r\n"));
        assert_eq!(
            state.tier,
            RequestSafetyTier::Compliant,
            "{}",
            state.error_message.unwrap()
        );
        assert_eq!(
            state.reason,
            ClassificationReason::Compliant,
            "{}",
            state.error_message.unwrap()
        );
        assert!(
            state.error_message.is_none(),
            "{}",
            state.error_message.unwrap()
        );

        assert_eq!(1, request.headers.len());
        assert_eq!(
            EMPTY_TOKEN,
            request.headers[0].name,
            "{}",
            to_quoted_ascii(request.headers[0].name)
        );
        assert_eq!(
            http_token(": localhost"),
            request.headers[0].value,
            "{}",
            to_quoted_ascii(request.headers[0].value)
        );
    }

    #[test]
    fn test_analyze_malformed_status_line() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET\t/foo/bar\tHTTP/1.1\r\nHost: localhost\r\n\r\n",
        ));
        assert_eq!(
            result.tier,
            RequestSafetyTier::Severe,
            "{:?}",
            result.message
        );
        assert_eq!(
            result.reason,
            ClassificationReason::BadMethod,
            "{:?}",
            result.message
        );
        assert!(result.message.is_some(), "{:?}", result.message);
    }

    #[test]
    fn test_analyze_spaces_in_uri() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar?foo=A new request HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ));
        assert_eq!(
            result.tier,
            RequestSafetyTier::Acceptable,
            "{:?}",
            result.message
        );
        assert_eq!(
            result.reason,
            ClassificationReason::SpaceInUri,
            "{:?}",
            result.message
        );
        assert!(result.message.is_some(), "{:?}", result.message);
    }

    #[test]
    fn test_parse_spaces_in_uri() {
        let (request, _) = HttpRequestData::parse(http_token(
            "GET /foo/bar?foo=A new request HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ));
        assert_eq!(http_token("/foo/bar?foo=A new request"), request.uri);
    }

    #[test]
    fn test_parse_missing_uri() {
        let (request, state) =
            HttpRequestData::parse(http_token("GET HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        assert_eq!(request.uri, EMPTY_TOKEN, "{}", to_quoted_ascii(request.uri));
        assert_eq!(
            request.version,
            HTTP_1_1,
            "{}",
            to_quoted_ascii(request.version)
        );
        assert_eq!(state.tier, RequestSafetyTier::Ambiguous,);
        assert_eq!(state.reason, ClassificationReason::MissingUri,);
        assert!(
            state.error_message.is_some(),
            "{}",
            state.error_message.unwrap()
        );
    }

    #[test]
    fn test_parse_empty_uri() {
        let (request, _) =
            HttpRequestData::parse(http_token("GET  HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        assert_eq!(request.uri, EMPTY_TOKEN, "{}", to_quoted_ascii(request.uri));
        assert_eq!(
            request.version,
            HTTP_1_1,
            "{}",
            to_quoted_ascii(request.version)
        );
    }

    #[test]
    fn test_analyze_bad_uri() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /\rHTTP/1.1\r\nHost: localhost\r\n\r\n",
        ));
        assert_eq!(result.tier, Severe, "{:?}", result.message);
        assert_eq!(result.reason, BadUri, "{:?}", result.message);
    }

    #[test]
    fn test_parse_bad_request_line() {
        let (request, state) =
            HttpRequestData::parse(http_token("GET_/_HTTP/1.1\r\nHost: localhost\r\n\r\n"));
        assert_eq!(request.uri, EMPTY_TOKEN, "{}", to_quoted_ascii(request.uri));
        assert_eq!(
            request.version,
            EMPTY_TOKEN,
            "{}",
            to_quoted_ascii(request.version)
        );
        assert_eq!(
            request.method,
            http_token("GET_/_HTTP/1.1"),
            "{}",
            to_quoted_ascii(request.version)
        );
        assert_eq!(state.tier, RequestSafetyTier::Ambiguous);
        assert_eq!(state.reason, ClassificationReason::MissingUri);
    }

    #[test]
    fn test_analyze_non_tchar_request_line() {
        let result = HttpRequestData::analyze_raw_request(&mut http_token(
            "GET /foo/bar HTTP/1.1 абра кадабра\r\nHost: localhost\r\n\r\n",
        ));
        assert_eq!(
            result.tier,
            RequestSafetyTier::Severe,
            "{:?}",
            result.message
        );
        assert_eq!(
            result.reason,
            ClassificationReason::BadVersion,
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_parse_malformed_request_single_line() {
        let (request, state) =
            HttpRequestData::parse(http_token("GET_/foo/bar_HTTP/1.1\rHost:localhost\n"));
        assert_eq!(request.uri, EMPTY_TOKEN, "{}", to_quoted_ascii(request.uri));
        assert_eq!(
            request.version,
            EMPTY_TOKEN,
            "{}",
            to_quoted_ascii(request.version)
        );
        assert_eq!(
            request.method,
            http_token("GET_/foo/bar_HTTP/1.1\rHost:localhost"),
            "{}",
            to_quoted_ascii(request.version)
        );
        assert_eq!(state.tier, RequestSafetyTier::Ambiguous);
        assert_eq!(state.reason, ClassificationReason::MissingUri);
    }

    #[test]
    fn test_parse_malformed_request_single_line_partial() {
        let (request, state) =
            HttpRequestData::parse(http_token("GET_/foo/bar_HTTP/1.1\rHost:localhost "));
        assert_eq!(request.uri, EMPTY_TOKEN, "{}", to_quoted_ascii(request.uri));
        assert_eq!(
            request.version,
            EMPTY_TOKEN,
            "{}",
            to_quoted_ascii(request.version)
        );
        assert_eq!(
            request.method,
            http_token("GET_/foo/bar_HTTP/1.1\rHost:localhost"),
            "{}",
            to_quoted_ascii(request.version)
        );
        assert_eq!(state.tier, RequestSafetyTier::Ambiguous);
        assert_eq!(state.reason, ClassificationReason::MissingUri);
    }

    #[test]
    fn test_analyze_lfcr() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\n\rContent-Length: 10\r\n\r\n",
        ));
        assert_eq!(
            result.tier,
            RequestSafetyTier::Severe,
            "{:?}",
            result.message
        );
        assert_eq!(
            result.reason,
            ClassificationReason::BadHeader,
            "{:?}",
            result.message
        );
        assert!(result.message.is_some(), "{:?}", result.message);
        assert!(result.message.unwrap().contains("Content-Length"));
    }

    #[test]
    fn test_analyze_multiline_headers() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n another-line\r\n\r\n",
        ));
        assert_eq!(
            result.tier,
            RequestSafetyTier::Ambiguous,
            "{:?}",
            result.message
        );
        assert_eq!(
            result.reason,
            ClassificationReason::MultilineHeader,
            "{:?}",
            result.message
        );
        assert!(
            result.message.as_ref().unwrap().contains("Host"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_allow_multiline_content_type() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nConnection: close\r\nContent-Type: application/json;\r\n plain-text;\r\nUser-Agent:test\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Compliant,);
        assert_eq!(result.reason, ClassificationReason::Compliant,);
        assert!(result.message.is_none(), "{:?}", result.message);
    }

    #[test]
    fn test_analyze_allow_multiline_content_type_other_acceptable() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nConnection: close\r\nContent-Type: application/json;\r\n plain-text;\r\nUser-Agent:\x01test\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Acceptable,);
        assert_eq!(result.reason, ClassificationReason::NonCompliantHeader,);
        assert!(
            result.message.as_ref().unwrap().contains("User-Agent"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_bad_multiline_content_type() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nContent-Type: application/json;\r\n \x00GET /smug HTTP/1.1\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Severe,);
        assert_eq!(result.reason, ClassificationReason::BadHeader,);
        assert!(
            result.message.as_ref().unwrap().contains("Content-Type"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_bad_multiline_mimic_header() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nA: A\r\n Content-Length: 10\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Ambiguous,);
        assert_eq!(result.reason, ClassificationReason::MultilineHeader,);
        assert!(
            result.message.as_ref().unwrap().contains("Content-Length"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_bad_multiline_mimic_header_severe() {
        // an attempt to smuggle CL as a multi-line header value
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nA: A\r\n Content-Length: 10\r\nContent-Length: 100\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Severe,);
        assert_eq!(result.reason, ClassificationReason::MultipleContentLength,);
        assert!(
            result.message.as_ref().unwrap().contains("Content-Length"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_bad_multiline_first_line_multiline() {
        // an attempt to smuggle CL as a multi-line header value
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\n GET /smug HTTP/1.1\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Ambiguous,);
        assert_eq!(result.reason, ClassificationReason::MultilineHeader,);
        assert!(
            result
                .message
                .as_ref()
                .unwrap()
                .contains("GET /smug HTTP/1.1"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_multiline_besides_content_type() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nContent-Type: application/json;\r\n application/word\r\nMulti-Line-Header: a\r\n b\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Ambiguous,);
        assert_eq!(result.reason, ClassificationReason::MultilineHeader,);
        assert!(result.message.is_some(), "{:?}", result.message);
        assert!(
            result
                .message
                .as_ref()
                .unwrap()
                .contains("Multi-Line-Header"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_acceptable_multiline_content_type() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nContent-Type: application/json;\r\n \x01application/java\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Acceptable,);
        assert_eq!(result.reason, ClassificationReason::NonCompliantHeader,);
        assert!(result.message.is_some(), "{:?}", result.message);
    }

    #[test]
    fn test_analyze_no_header_value() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nMy-header\r\nAnother-header:1\r\n\r\n",
        ));
        assert_eq!(result.tier, RequestSafetyTier::Ambiguous,);
        assert_eq!(result.reason, ClassificationReason::MissingHeaderColon,);
        assert!(result.message.is_some(), "{:?}", result.message);
    }

    #[test]
    fn test_analyze_bad_multiline_headers() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n another-line\x00GET /smug HTTP/1.1\r\n\r\n",
        ));
        assert_eq!(
            result.tier,
            RequestSafetyTier::Severe,
            "{:?}",
            result.message
        );
        assert_eq!(
            result.reason,
            ClassificationReason::BadHeader,
            "{:?}",
            result.message
        );
        assert!(result.message.is_some(), "{:?}", result.message);
    }

    #[test]
    fn test_analyze_crafted_smuggling() {
        let result = HttpRequestData::analyze_raw_request(http_token(
            "GET /smug_a HTTP/1.1\r\nHost: testasset\r\nABC: 1.2.3.4\r\n x-ignore:\r\n\x7fGET /smug_b: HTTP/1.1 \r\nAccept-Language: en\r\nConnection: Keep-Alive\r\n\r\n",
        ));
        assert_eq!(
            result.tier,
            RequestSafetyTier::Ambiguous,
            "{:?}",
            result.message
        );
        assert_eq!(
            result.reason,
            ClassificationReason::MultilineHeader,
            "{:?}",
            result.message
        );
        assert!(result.message.is_some(), "{:?}", result.message);
        assert!(
            result.message.as_ref().unwrap().contains("x-ignore"),
            "{:?}",
            result.message
        );
    }

    #[test]
    fn test_analyze_fuzzing_input() {
        // the goal of this test to make sure the parser doesn't fail on non-sense input
        const ORIGINAL_REQUEST: HttpToken =
            http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n\r\n");

        let mut states_counter = HashMap::new();
        let mut analyzed_inputs = HashSet::new();
        // we need enough repetitions to cause different reasons
        const REPS: usize = 10000;
        for i in 0..REPS {
            let mut raw_request = Vec::from(ORIGINAL_REQUEST);
            // just mutate input to produce bad input
            for j in 0..=i / 100 {
                raw_request[(i + j * 3) % ORIGINAL_REQUEST.len()] ^=
                    (i + j) as u8 ^ ((i + j * 2) >> 8) as u8;
            }

            let result = HttpRequestData::analyze_raw_request(raw_request.as_slice());
            states_counter
                .entry((result.tier, result.reason))
                .or_insert(0)
                .add_assign(1);
            analyzed_inputs.insert(to_quoted_ascii(raw_request.as_slice()));
        }
        // making sure all parsing reasons are covered
        // for non-compliant requests
        let reasons = vec![
            (Severe, BadHeader),
            (Severe, BadVersion),
            (Severe, BadMethod),
            (Severe, BadUri),
            (Ambiguous, AmbiguousUri),
            (Ambiguous, MissingUri),
            (Ambiguous, MissingHeaderColon),
            (Acceptable, NonCrLfLineTermination),
            (Acceptable, NonCompliantHeader),
            (Acceptable, NonCompliantVersion),
            (
                RequestSafetyTier::Compliant,
                ClassificationReason::Compliant,
            ),
        ];
        check_state_counter(&mut states_counter, reasons);
        assert_eq!(
            analyzed_inputs.len(),
            REPS,
            "Less than {} cases covered: {}",
            REPS,
            analyzed_inputs.len()
        );
    }

    #[test]
    fn test_walk_through_states() {
        // Replace all delimiters to make sure all parsing states are covered
        let original_request: HttpToken =
            http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n\r\n");

        // replace delimiters to make sure the parser is tolerant to all cases
        let delimiters = &[b' ', b'\r', b'\n', b':'];

        let mut char_mappings: Vec<&[u8]> = Vec::new();
        (0..255).for_each(|_| char_mappings.push(&[]));

        // we'd like to replace each delimiter with another delimiter
        char_mappings[b' ' as usize] = &[b' ', b'\n', b'_', b':', b'\t'];
        char_mappings[b'\n' as usize] = &[b'\n', b' ', b':'];
        char_mappings[b'\r' as usize] = &[b'\r', b'\n', b' '];
        char_mappings[b':' as usize] = &[b':', b' '];

        let delimiter_positions: Vec<usize> = original_request
            .iter()
            .enumerate()
            .filter(|(_, c)| delimiters.contains(*c))
            .map(|(i, _)| i)
            .collect();

        const MAX_STATES: usize = 10;
        assert!(
            delimiter_positions.len() <= MAX_STATES,
            "Too many states {}^{}",
            delimiters.len() as f64,
            delimiter_positions.len() as f64
        );

        // enumerate all states
        let state_sequence: &mut [usize] = &mut [0; MAX_STATES];
        let mut raw_request = Vec::from(original_request);
        let mut parsing_state_counter = HashMap::new();
        loop {
            for (idx, pos) in delimiter_positions.iter().enumerate() {
                let pos_state = state_sequence[idx];
                raw_request[*pos] = char_mappings[original_request[*pos] as usize][pos_state];
            }
            let state = HttpRequestData::analyze_raw_request(raw_request.as_slice());
            parsing_state_counter
                .entry((state.tier, state.reason))
                .or_insert(0)
                .add_assign(1);

            // move to the next state
            let mut i = 0;
            while i < delimiter_positions.len() {
                state_sequence[i] += 1;
                let max_pos =
                    char_mappings[original_request[delimiter_positions[i]] as usize].len();
                if state_sequence[i] == max_pos {
                    state_sequence[i] = 0;
                    i += 1;
                } else {
                    break;
                }
            }
            if i == delimiter_positions.len() {
                break;
            }
        }

        // making sure all parsing reasons are covered
        // for non-compliant requests
        let reasons = vec![
            (Severe, BadUri),
            (Severe, BadHeader),
            (Severe, BadVersion),
            (Severe, BadMethod),
            (Ambiguous, PartialHeaderLine),
            (Ambiguous, MissingLastEmptyLine),
            (Ambiguous, PartialHeaderLine),
            (Ambiguous, MultilineHeader),
            (Ambiguous, MissingUri),
            (Ambiguous, AmbiguousUri),
            (Ambiguous, EmptyHeader),
            (Ambiguous, MissingHeaderColon),
            (Acceptable, NonCrLfLineTermination),
            (Acceptable, NonCompliantVersion),
            (Acceptable, NonCompliantHeader),
            (
                RequestSafetyTier::Compliant,
                ClassificationReason::Compliant,
            ),
        ];

        check_state_counter(&mut parsing_state_counter, reasons);
    }

    fn check_state_counter(
        parsing_state_counter: &mut HashMap<(RequestSafetyTier, ClassificationReason), i32>,
        reasons: Vec<(RequestSafetyTier, ClassificationReason)>,
    ) {
        let mut total_states = 0;
        let mut report = Vec::new();
        for (k, v) in parsing_state_counter.iter() {
            report.push(format!("{:?}.{:?}: {}", &k.0, k.1, *v));
            total_states += *v;
        }
        report.sort();
        report.iter().for_each(|s| println!("{}", *s));
        println!("=======================\r\nTotal states: {}", total_states);

        reasons.iter().for_each(|(tier, reason)| {
            assert!(
                *parsing_state_counter
                    .entry((tier.clone(), *reason))
                    .or_default()
                    > 0,
                "Missing {:?}:{:?}",
                tier,
                reason
            )
        });
    }
}
