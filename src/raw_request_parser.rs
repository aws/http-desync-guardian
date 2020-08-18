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
use crate::http_token_utils::{http_token, is_rfc_tchar, is_rfc_whitespace, HttpToken};

pub const LF: u8 = b'\n';
pub const SP: u8 = b' ';
pub const COLON: u8 = b':';
const CR: u8 = b'\r';
const EMPTY_TOKEN: HttpToken = http_token("");

/// A window view on an HttpToken.
pub struct RequestBuffer<'a> {
    buf: HttpToken<'a>,
    pos: usize,
    end: usize,
}

impl<'a> RequestBuffer<'a> {
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn new(buf: HttpToken<'a>) -> Self {
        Self {
            buf,
            pos: 0,
            end: buf.len(),
        }
    }

    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    fn slice(&self, token_begin: usize, token_end: usize) -> Self {
        Self {
            buf: self.buf,
            pos: token_begin,
            end: token_end,
        }
    }

    /// If there is nothing left to process.
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn is_done(&self) -> bool {
        self.pos >= self.end
    }

    /// If it had less characters than expected.
    /// E.g. an expected delimiter was not there.
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn is_partial(&self) -> bool {
        self.pos > self.end
    }

    /// If the first character an RFC whitespace (SP|HT).
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn starts_with_rfc_whitespace(&self) -> bool {
        debug_assert!(self.pos < self.end);
        is_rfc_whitespace(self.buf[self.pos])
    }

    /// Converts it to an HttpToken.
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn as_http_token(&self) -> HttpToken<'a> {
        if self.pos < self.end {
            &self.buf[self.pos..self.end]
        } else {
            EMPTY_TOKEN
        }
    }

    /// If the line was terminated with CRLF (true) or just LF (false).
    /// Also trims CR if it was there. (LF is already pre-trimmed).
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn trim_last_cr(&mut self) -> bool {
        if self.end > self.pos && self.buf[self.end - 1] == CR {
            self.end -= 1;
            true
        } else {
            false
        }
    }

    /// Take the next token till the delimiter.
    /// The delimiter is not included.
    #[cfg_attr(feature = "coverage", inline(never))]
    #[cfg_attr(not(feature = "coverage"), inline(always))]
    pub fn next_token(&mut self, delimiter: u8) -> Self {
        let mut current = self.pos;
        while current < self.end && self.buf[current] != delimiter {
            current += 1;
        }
        let token_begin = self.pos;
        let token_end = current;

        self.pos = current + 1;

        self.slice(token_begin, token_end)
    }

    /// Take the last token till the delimiter.
    /// The delimiter is not included.
    pub fn last_token(&mut self, delimiter: u8) -> Self {
        let mut current = if self.end > self.pos {
            self.end - 1
        } else {
            self.pos
        };
        // right-trim: ignore non-tchars on the right
        let mut skip_non_tchars = true;
        while self.pos < current && (self.buf[current] != delimiter || skip_non_tchars) {
            skip_non_tchars &= !is_rfc_tchar(self.buf[current]);
            current -= 1;
        }

        let token_begin;
        let token_end;
        if current >= self.pos && current < self.end {
            token_begin = if self.buf[current] == delimiter {
                current + 1
            } else {
                current
            };
            token_end = self.end;
            self.end = token_begin - 1;
        } else {
            // partial token
            token_begin = 1;
            token_end = 0;
        }

        self.slice(token_begin, token_end)
    }
}

#[cfg(test)]
mod tests {
    use crate::http_token_utils::{http_token, to_quoted_ascii, HttpToken};
    use crate::raw_request_parser::{RequestBuffer, EMPTY_TOKEN, LF, SP};

    const GET_REQUEST: HttpToken = http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n\r\n");

    #[test]
    fn test_parse_request_line() {
        let mut buffer = RequestBuffer::new(GET_REQUEST);
        let mut request_line = buffer.next_token(LF);
        assert_eq!(
            http_token("GET /foo/bar HTTP/1.1\r"),
            request_line.as_http_token(),
            "{}",
            to_quoted_ascii(request_line.as_http_token())
        );
        assert!(request_line.trim_last_cr());
        assert_eq!(
            http_token("GET /foo/bar HTTP/1.1"),
            request_line.as_http_token(),
            "{}",
            to_quoted_ascii(request_line.as_http_token())
        );

        let method = request_line.next_token(SP);
        let version = request_line.last_token(SP);
        let uri = request_line;

        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        assert_eq!(
            http_token("/foo/bar"),
            uri.as_http_token(),
            "{}",
            to_quoted_ascii(uri.as_http_token())
        );
        assert_eq!(
            http_token("HTTP/1.1"),
            version.as_http_token(),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
    }

    #[test]
    fn test_parse_line_by_line() {
        let mut buffer = RequestBuffer::new(GET_REQUEST);
        let mut request_line = buffer.next_token(LF);
        assert_eq!(
            http_token("GET /foo/bar HTTP/1.1\r"),
            request_line.as_http_token(),
            "{}",
            to_quoted_ascii(request_line.as_http_token())
        );
        assert!(request_line.trim_last_cr());
        assert_eq!(
            http_token("GET /foo/bar HTTP/1.1"),
            request_line.as_http_token(),
            "{}",
            to_quoted_ascii(request_line.as_http_token())
        );

        let mut header = buffer.next_token(LF);
        assert_eq!(
            http_token("Host: localhost\r"),
            header.as_http_token(),
            "{}",
            to_quoted_ascii(header.as_http_token())
        );
        assert!(header.trim_last_cr());
        assert_eq!(
            http_token("Host: localhost"),
            header.as_http_token(),
            "{}",
            to_quoted_ascii(header.as_http_token())
        );

        let mut empty = buffer.next_token(LF);
        assert_eq!(
            http_token("\r"),
            empty.as_http_token(),
            "{}",
            to_quoted_ascii(empty.as_http_token())
        );
        assert!(empty.trim_last_cr());
        assert_eq!(
            http_token(""),
            empty.as_http_token(),
            "{}",
            to_quoted_ascii(empty.as_http_token())
        );

        assert!(buffer.is_done());
    }

    #[test]
    fn test_parse_non_compliant_request_line() {
        // extra spaces after the version
        let mut buffer = RequestBuffer::new(http_token(
            "GET /foo/bar HTTP/1.1 \t \r\nHost: localhost\r\n\r\n",
        ));
        let mut request_line = buffer.next_token(LF);
        assert!(request_line.trim_last_cr());

        let method = request_line.next_token(SP);
        let version = request_line.last_token(SP);
        let uri = request_line;

        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        assert_eq!(
            http_token("/foo/bar"),
            uri.as_http_token(),
            "{}",
            to_quoted_ascii(uri.as_http_token())
        );
        assert_eq!(
            http_token("HTTP/1.1 \t "),
            version.as_http_token(),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
    }

    #[test]
    fn test_parse_non_tchar_request_line() {
        // non-sensical characters after the version
        let mut buffer = RequestBuffer::new(http_token(
            "GET /foo/bar HTTP/1.1 абра кадабра\r\nHost: localhost\r\n\r\n",
        ));
        let mut request_line = buffer.next_token(LF);
        assert!(request_line.trim_last_cr());

        let method = request_line.next_token(SP);
        let version = request_line.last_token(SP);
        let uri = request_line;

        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        assert_eq!(
            http_token("/foo/bar"),
            uri.as_http_token(),
            "{}",
            to_quoted_ascii(uri.as_http_token())
        );
        assert!(
            version.as_http_token().starts_with(http_token("HTTP/1.1")),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
    }

    #[test]
    fn test_parse_non_compliant_terminator_request_line() {
        // extra spaces after the version
        let mut buffer = RequestBuffer::new(http_token(
            "GET /foo/bar HTTP/1.1 \t \nHost: localhost\r\n\r\n",
        ));
        let mut request_line = buffer.next_token(LF);
        assert!(!request_line.trim_last_cr());

        let method = request_line.next_token(SP);
        let version = request_line.last_token(SP);
        let uri = request_line;

        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        assert_eq!(
            http_token("/foo/bar"),
            uri.as_http_token(),
            "{}",
            to_quoted_ascii(uri.as_http_token())
        );
        assert_eq!(
            http_token("HTTP/1.1 \t "),
            version.as_http_token(),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
    }

    #[test]
    fn test_parse_non_missing_empty_line() {
        // extra spaces after the version
        let mut buffer =
            RequestBuffer::new(http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost\r\n"));
        let mut request_line = buffer.next_token(LF);
        assert!(request_line.trim_last_cr());

        let mut header_line = buffer.next_token(LF);
        assert!(header_line.trim_last_cr());

        assert!(!header_line.is_done());
        assert!(buffer.is_done());
    }

    #[test]
    fn test_parse_missing_uri() {
        // extra spaces after the version
        let mut buffer = RequestBuffer::new(http_token("GET HTTP/1.1"));
        let method = buffer.next_token(SP);
        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        let version = buffer.last_token(SP);
        assert_eq!(
            http_token("HTTP/1.1"),
            version.as_http_token(),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
        assert!(buffer.is_partial());
    }

    #[test]
    fn test_parse_empty_uri() {
        // extra spaces after the version
        let mut buffer = RequestBuffer::new(http_token("GET  HTTP/1.1"));
        let method = buffer.next_token(SP);
        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        let version = buffer.last_token(SP);
        assert_eq!(
            http_token("HTTP/1.1"),
            version.as_http_token(),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
        assert!(buffer.is_done());
    }

    #[test]
    fn test_parse_empty_uri_bad_delimiters() {
        // extra spaces after the version
        let mut buffer = RequestBuffer::new(http_token("GET \tHTTP/1.1"));
        let method = buffer.next_token(SP);
        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        let version = buffer.last_token(SP);
        assert_eq!(
            http_token("\tHTTP/1.1"),
            version.as_http_token(),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
        assert!(buffer.is_partial());
    }

    #[test]
    fn test_parse_partial() {
        // extra spaces after the version
        let mut buffer = RequestBuffer::new(http_token("GET /foo/bar HTTP/1.1\r\nHost: localhost"));
        let mut request_line = buffer.next_token(LF);
        assert!(request_line.trim_last_cr());

        let mut header_line = buffer.next_token(LF);
        assert!(!header_line.trim_last_cr());

        assert!(!header_line.is_done());
        assert!(buffer.is_partial());
    }

    #[test]
    fn test_parse_request_line_http_09() {
        // extra spaces after the version
        let mut buffer = RequestBuffer::new(http_token("GET /foo/bar\r\nHost: localhost\r\n\r\n"));
        let mut request_line = buffer.next_token(LF);
        assert!(request_line.trim_last_cr());

        let method = request_line.next_token(SP);
        let mut version = request_line.last_token(SP);
        let mut uri = request_line;

        assert!(uri.is_partial());

        // there is no version
        uri = version;
        version = RequestBuffer::new(EMPTY_TOKEN);

        assert_eq!(
            http_token("GET"),
            method.as_http_token(),
            "{}",
            to_quoted_ascii(method.as_http_token())
        );
        assert_eq!(
            http_token("/foo/bar"),
            uri.as_http_token(),
            "{}",
            to_quoted_ascii(uri.as_http_token())
        );
        assert_eq!(
            http_token(""),
            version.as_http_token(),
            "{}",
            to_quoted_ascii(version.as_http_token())
        );
    }
}
