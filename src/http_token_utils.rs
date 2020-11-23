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
use crate::http_token_utils::TokenSimilarity::{Distant, Identical, SameLetters};
use crate::MESSAGE_MAX_SIZE;
use std::fmt::Write;

/// No allocation of new tokens is happening.
/// All operations are in-place and read only.
pub type HttpToken<'a> = &'a [u8];

pub const fn http_token(v: &str) -> HttpToken {
    v.as_bytes()
}

// Include generated char tables. See `build.rs`
include!(concat!(env!("OUT_DIR"), "/char_tables.rs"));
pub const TE: HttpToken = http_token("transfer-encoding");
pub const CL: HttpToken = http_token("content-length");
///
/// https://tools.ietf.org/html/rfc7230#page-22
///
/// ```ignore
/// OWS = *( SP / HTAB )
/// header-field = field-name ":" OWS field-value OWS
/// field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
/// field-name = token
/// field-value = *( field-content / obs-fold )
/// field-vchar = VCHAR / obs-text
/// obs-fold = CRLF 1*( SP / HTAB )
/// obs-text = %x80-FF
/// fragment = <fragment, see [RFC3986], Section 3.5>
/// header-field = field-name ":" OWS field-value OWS
/// token = 1*tchar
/// token          = 1*<any CHAR except CTLs or separators>
/// tchar = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "." /
///         "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
///
/// t-codings = "trailers" / ( transfer-coding [ t-ranking ] )
/// t-ranking = OWS ";" OWS "q=" rank
/// transfer-coding = "chunked" / "compress" / "deflate" / "gzip" / transfer-extension
/// transfer-extension = token *( OWS ";" OWS transfer-parameter )
/// transfer-parameter = token BWS "=" BWS ( token / quoted-string )
/// ```

/// URL: https://tools.ietf.org/html/rfc3986#appendix-A
/// ```ignore
/// path          = path-abempty    ; begins with "/" or is empty
///                   / path-absolute   ; begins with "/" but not "//"
///                   / path-noscheme   ; begins with a non-colon segment
///                   / path-rootless   ; begins with a segment
///                   / path-empty      ; zero characters
///
///     path-abempty  = *( "/" segment )
///     path-absolute = "/" [ segment-nz *( "/" segment ) ]
///     path-noscheme = segment-nz-nc *( "/" segment )
///     path-rootless = segment-nz *( "/" segment )
///     path-empty    = 0<pchar>
///
/// Berners-Lee, et al.         Standards Track                    [Page 22]
///
/// RFC 3986                   URI Generic Syntax               January 2005
///
///     segment       = *pchar
///     segment-nz    = 1*pchar
///     segment-nz-nc = 1*( unreserved / pct-encoded / sub-delims / "@" )
///                   ; non-zero-length segment without any colon ":"
///
///     pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
///     sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
///                 / "*" / "+" / "," / ";" / "="
///     pct-encoded = "%" HEXDIG HEXDIG
///     unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
/// ```

const SP: u8 = b' ';
const COLON: u8 = b':';
pub const CHUNKED: HttpToken = http_token("chunked");
const VALID_TE: &[HttpToken] = &[
    CHUNKED,
    http_token("compress"),
    http_token("deflate"),
    http_token("gzip"),
    http_token("identity"),
];

#[derive(PartialOrd, PartialEq, Debug)]
pub enum TokenSimilarity {
    /// If two token are identical, i.e. equal ignoring case.
    /// ```no_run
    /// use http_desync_guardian::http_token_utils::*;
    /// use http_desync_guardian::http_token_utils::TokenSimilarity::*;
    ///
    /// assert_eq!(determine_similarity(http_token("token"), http_token("Token")), Identical);
    /// assert_eq!(determine_similarity(http_token("same-token"), http_token("Same-Token")), Identical);
    /// ```
    Identical,
    /// If two tokens differ only by non-letter characters.
    /// ```no_run
    /// use http_desync_guardian::http_token_utils::*;
    /// use http_desync_guardian::http_token_utils::TokenSimilarity::*;
    ///
    /// assert_eq!(determine_similarity(http_token("token"), http_token("Token\t")), SameLetters);
    /// assert_eq!(determine_similarity(http_token("same-token"), http_token("Same\t-Token")), SameLetters);
    /// ```
    SameLetters,
    /// Otherwise it's `Distant`. E.g. "some-token" and "other-token"
    /// ```no_run
    /// use http_desync_guardian::http_token_utils::*;
    /// use http_desync_guardian::http_token_utils::TokenSimilarity::*;
    ///
    /// assert_eq!(determine_similarity(http_token("token"), http_token("Different-token")), Distant);
    /// assert_eq!(determine_similarity(http_token("same-token"), http_token("Other-token")), Distant);
    /// ```
    Distant,
}

pub fn is_valid_te(value: HttpToken) -> Option<HttpToken> {
    let trimmed = rfc_whitespace_trim(value);
    let mut end: usize = 0;
    while end < trimmed.len() && trimmed[end] != b';' {
        end += 1;
    }
    let te = rfc_whitespace_trim(&trimmed[..end]);
    VALID_TE
        .iter()
        .copied()
        .find(|s| s.eq_ignore_ascii_case(te))
}

#[inline(always)]
pub fn is_valid_uri_char(b: u8) -> bool {
    // disable CTL in URL
    VALID_URI_CHARS[b as usize]
}

#[inline(always)]
pub fn is_space(b: u8) -> bool {
    b == SP
}

#[inline(always)]
pub fn is_colon(b: u8) -> bool {
    b == COLON
}

#[inline(always)]
pub fn find_next_header_symbol(value: HttpToken, current: usize) -> usize {
    let mut i = current;
    while i < value.len() && value[i] <= SP {
        i += 1;
    }
    i
}

#[inline(always)]
pub fn find_next_alphanumeric(value: HttpToken, current: usize) -> usize {
    let mut i = current;
    while i < value.len() && !value[i].is_ascii_alphanumeric() {
        i += 1;
    }
    i
}

#[inline(always)]
pub fn is_rfc_tchar(b: u8) -> bool {
    TCHAR_TABLE[b as usize]
}

#[inline(always)]
pub fn is_valid_header_value_char(b: u8) -> bool {
    HEADER_VALUE_CHARS[b as usize]
}

#[inline(always)]
pub fn is_rfc_vchar(b: u8) -> bool {
    VCHAR[b as usize]
}

#[inline(always)]
pub fn is_rfc_obs_text(b: u8) -> bool {
    b >= 0x80
}

///
/// Determines if a given character is an indication
/// of a parsing error or a crafted malicious request.
/// Includes: `\r`, `\n` and `\0`.
///
#[inline(always)]
pub fn is_bad_http_character(b: u8) -> bool {
    BAD_CHARACTERS[b as usize]
}

pub fn to_quoted_ascii(raw_data: HttpToken) -> String {
    let mut str = String::with_capacity(raw_data.len().min(MESSAGE_MAX_SIZE / 2));
    str.push('"');
    for b in raw_data {
        if str.len() >= MESSAGE_MAX_SIZE / 2 - 4 {
            break;
        }
        match *b {
            b'\r' => str.push_str("\\r"),
            b'\n' => str.push_str("\\n"),
            b'\t' => str.push_str("\\t"),
            b'\\' => str.push_str("\\\\"),
            _ if is_rfc_vchar(*b) => {
                str.push(*b as char);
            }
            _ => {
                write!(str, "\\{:#04x}", *b).expect("Writing to strings is infallible");
            }
        }
    }
    str.push('"');
    str
}

/// We do not want to log header values
/// It only loads violating characters
pub fn obfuscate_value(raw_data: HttpToken) -> String {
    let mut str = String::with_capacity(MESSAGE_MAX_SIZE / 2);
    str.push('"');
    let mut prev_char = 0;
    for b in raw_data {
        if str.len() >= MESSAGE_MAX_SIZE / 2 - 4 {
            break;
        }
        match *b {
            b'\r' => str.push_str("\\r"),
            b'\n' => str.push_str("\\n"),
            b'\t' => str.push_str("\\t"),
            b'\\' => str.push_str("\\\\"),
            b' ' => str.push(' '),
            _ if !is_rfc_vchar(*b) && !is_rfc_obs_text(*b) => {
                write!(str, "\\{:#04x}", *b).expect("Writing to strings is infallible");
            }
            _ if prev_char != b'_' => {
                str.push('_');
            }
            _ => {
                // skip
            }
        }
        prev_char = str.as_bytes()[str.len() - 1];
    }
    str.push('"');
    str
}

#[inline(always)]
pub fn is_rfc_whitespace(b: u8) -> bool {
    RFC_WHITE_SPACE[b as usize]
}

pub fn parse_num(value: HttpToken) -> Result<u64, &str> {
    let trimmed = rfc_whitespace_trim(value);
    let mut result: u64 = 0;
    for c in trimmed.iter() {
        if !c.is_ascii_digit() {
            return Err("Not an integer");
        }
        let digit = (*c - b'0') as u64;

        // check for 64-bits overflow after multiplication
        // with 10 and addition with current digit
        result = result.checked_mul(10).ok_or("64-bits overflow")?;
        result = result.checked_add(digit).ok_or("64-bits overflow")?;
    }
    Ok(result)
}

#[inline]
pub fn rfc_whitespace_trim(value: HttpToken) -> HttpToken {
    if value.is_empty() {
        return value;
    }

    let mut first_non_space = 0;
    let mut last_non_space = value.len();

    while first_non_space < last_non_space && is_rfc_whitespace(value[first_non_space]) {
        first_non_space += 1;
    }

    while first_non_space < last_non_space && is_rfc_whitespace(value[last_non_space - 1]) {
        last_non_space -= 1;
    }

    &value[first_non_space..last_non_space]
}

#[inline]
fn same_char(original_char: u8, header: HttpToken, index: usize) -> (bool, usize) {
    // check if it's the same char, taking into account UTF8 characters
    // that convert to ASCII on to_uppercase transformation, such as:
    // Latin Small Letter Long S https://www.compart.com/en/unicode/U+017f
    // "\0xc5\0xbf" -> "ſ".upper() == "S"
    // Latin Small Letter Dotless I https://www.compart.com/en/unicode/U+0131
    // "\0xc4\0xb1" -> "ı".upper() == "I"
    // These characters were found by scanning all UTF8 with a property
    // of upper/lower case transformation coincide with TE/CL letters.
    let header_char = header[index];
    if original_char == header_char.to_ascii_lowercase() {
        return (true, index + 1);
    } else if header.len() > index + 1 {
        const MATCHES: &[(u8, u8, u8)] = &[(b's', 0xc5, 0xbf), (b'i', 0xc4, 0xb1)];
        if MATCHES
            .iter()
            .any(|p| *p == (original_char, header_char, header[index + 1]))
        {
            return (true, index + 2);
        }
    }
    (false, index + 1)
}

///
/// Determines similarity of two tokens taking into account only alpha-numeric characters.
///
/// # Parameters
/// `important_header` - must be only in lower-case letters and '-'.
/// `header` - any token to check
///
pub fn determine_similarity(important_header: HttpToken, header: HttpToken) -> TokenSimilarity {
    debug_assert!(important_header
        .iter()
        .all(|c| *c == c.to_ascii_lowercase()));
    debug_assert!(important_header
        .iter()
        .all(|c| c.is_ascii_alphabetic() || *c == b'-'));

    if header.len() < important_header.len() {
        return Distant;
    }

    let mut header_index = find_next_alphanumeric(header, 0);
    let mut identical = header_index == 0 && important_header.len() == header.len();
    for c in important_header.iter() {
        if header_index == header.len() {
            return Distant;
        }
        let delimiter = *c == b'-';
        let (same_symbol, new_index) = same_char(*c, header, header_index);
        if !same_symbol {
            if !delimiter {
                break;
            } else {
                identical = false;
            }
        }
        header_index = if delimiter {
            find_next_alphanumeric(header, new_index)
        } else {
            find_next_header_symbol(header, new_index)
        };
    }
    let exhausted_header = header_index == header.len();
    if exhausted_header && identical {
        Identical
    } else if exhausted_header || find_next_alphanumeric(header, header_index) == header.len() {
        SameLetters
    } else {
        Distant
    }
}

#[cfg(test)]
mod tests {
    use crate::http_token_utils::*;
    use crate::MESSAGE_MAX_SIZE;
    use smallvec::alloc::str::from_utf8;

    #[test]
    fn verify_essential_headers_lowercase() {
        // for performance consideration the code assumes all constants are in lower-case
        // this test ensures it's the case
        &[TE, CL].iter().for_each(|h| {
            h.iter().for_each(|b| {
                assert_eq!(b.to_ascii_lowercase(), *b);
            });
        });
    }

    #[test]
    fn verify_te_options_lowercase() {
        // for performance consideration the code assumes all constants are in lower-case
        // this test ensures it's the case
        VALID_TE.iter().for_each(|h| {
            h.iter().for_each(|b| {
                assert_eq!((*b).to_ascii_lowercase(), *b);
            });
        });
    }

    #[test]
    fn test_same_char() {
        assert_eq!((true, 2), same_char(b's', &[0xc5, 0xbf], 0));
        assert_eq!((true, 2), same_char(b'i', &[0xc4, 0xb1], 0));
        assert_eq!((true, 1), same_char(b's', &[b's'], 0));
        assert_eq!((true, 1), same_char(b's', &[b'S'], 0));

        assert_eq!((false, 1), same_char(b's', &[b'a'], 0));
        assert_eq!((false, 1), same_char(b's', &[0xc5], 0));
    }

    #[test]
    fn test_same_char_covers_all_utf8() {
        // Verify that all UTF8 characters, that
        let important_headers = &[
            String::from_utf8(TE.to_vec()).expect("ASCII -> UTF8 is infallible"),
            String::from_utf8(CL.to_vec()).expect("ASCII -> UTF8 is infallible"),
        ];
        let mut chars_matched = 0;
        let mut chars_checked = 0;
        // iterate over all UTF8
        for d in 0x80..=0xFF {
            for c in 0x80..=0xFF {
                let (matched, checked) = check_utf8_character(important_headers, &[c, d]);
                chars_checked += checked;
                chars_matched += matched;
                for b in 0x80..=0xFF {
                    let (matched, checked) = check_utf8_character(important_headers, &[b, c, d]);
                    chars_checked += checked;
                    chars_matched += matched;
                    for a in 0xF0..=0xFF {
                        let (matched, checked) =
                            check_utf8_character(important_headers, &[a, b, c, d]);
                        chars_checked += checked;
                        chars_matched += matched;
                    }
                }
            }
        }
        assert_eq!(
            chars_checked, 3,
            "We know there are three such characters, that convert from UTF8 to ASCII"
        );
        assert_eq!(
            chars_matched, 2,
            "We know there are two of them that should match TE/CL headers"
        );
    }

    fn check_utf8_character(important_headers: &[String], utf8_char: &[u8]) -> (usize, usize) {
        let mut checked = 0;
        let mut matched = 0;

        if let Ok(s) = from_utf8(utf8_char) {
            let upper = s.to_uppercase();
            let lower = s.to_lowercase();
            let to_ascii = upper.len() == 1 || lower.len() == 1;
            if to_ascii {
                checked += 1;

                let contains_upper = upper.len() == 1
                    && important_headers
                        .iter()
                        .any(|header| header.to_ascii_uppercase().contains(upper.as_str()));
                if contains_upper {
                    assert_eq!(
                        same_char(upper.to_ascii_lowercase().as_bytes()[0], utf8_char, 0),
                        (true, utf8_char.len()),
                        "{} is not covered",
                        s
                    );
                    matched += 1;
                }

                let contains_lower = lower.len() == 1
                    && important_headers
                        .iter()
                        .any(|header| header.contains(lower.as_str()));
                if contains_lower {
                    assert_eq!(
                        same_char(lower.as_bytes()[0], utf8_char, 0),
                        (true, utf8_char.len()),
                        "{} is not covered",
                        s
                    );
                    matched += 1;
                }
            }
            if matched == 0 {
                for c in b'a'..=b'z' {
                    assert_eq!(
                        same_char(c, utf8_char, 0),
                        (false, 1),
                        "{} must not match any characters, but it did: {}",
                        s,
                        to_quoted_ascii(&[c])
                    );
                }
            }
        }
        return (matched, checked);
    }

    #[test]
    fn test_same_letters() {
        let test_cases = vec![
            ("t-e", "t-e", TokenSimilarity::Identical),
            ("t-e", "t_e", TokenSimilarity::SameLetters),
            ("t-e", "t_e ", TokenSimilarity::SameLetters),
            ("t-e", "t____e", TokenSimilarity::SameLetters),
            ("t-e", "t----e", TokenSimilarity::SameLetters),
            ("t", "tp", TokenSimilarity::Distant),
            ("t", "t0", TokenSimilarity::Distant),
            ("t", "t_", TokenSimilarity::SameLetters),
            ("t", "p", TokenSimilarity::Distant),
            ("t", "", TokenSimilarity::Distant),
            (
                "transfer-encoding",
                "transfer-encoding1",
                TokenSimilarity::Distant,
            ),
            (
                "transfer-encoding",
                // Latin Small Letter Long S https://www.compart.com/en/unicode/U+017f
                "tran\u{017f}fer-encoding",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                // Latin Small Letter Dotless I https://www.compart.com/en/unicode/U+0131
                "transfer-encod\u{0131}ng",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                "transfer-encoding",
                TokenSimilarity::Identical,
            ),
            (
                "transfer-encoding",
                "Transfer-Encoding",
                TokenSimilarity::Identical,
            ),
            (
                "x-my-custom-important-header",
                "X-My-Custom-Important-Header",
                TokenSimilarity::Identical,
            ),
            (
                "x-my-custom-important-header",
                "X_My_Custom_Important_Header",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                "transfer-encodin",
                TokenSimilarity::Distant,
            ),
            ("transfer", "transfer-encoding", TokenSimilarity::Distant),
            (
                "transfer-encoding",
                "transfer-encoding1",
                TokenSimilarity::Distant,
            ),
            (
                "transfer-encoding",
                "TRANSFER-ENCODING",
                TokenSimilarity::Identical,
            ),
            (
                "transfer-encoding",
                "transfer-\tencoding",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                "\r\ntransfer-\t\te\tn\tc o d i ng\t",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                "transfer_encoding",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                "transfer---encoding",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                "x_transfer_encoding",
                TokenSimilarity::Distant,
            ),
            (
                "transfer-encoding",
                "x_transfer_encodings",
                TokenSimilarity::Distant,
            ),
            ("transfer-encoding", "gibberish", TokenSimilarity::Distant),
            (
                "transfer-encoding",
                "\t\x01\x02transfer-encoding\t\x0f\x0c",
                TokenSimilarity::SameLetters,
            ),
            (
                "transfer-encoding",
                "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t",
                TokenSimilarity::Distant,
            ),
            (
                "transfer-encoding",
                "accept-encoding",
                TokenSimilarity::Distant,
            ),
        ];

        test_cases.iter().for_each(|(e, c, expected_distance)| {
            let important_header = http_token(e);
            let header = http_token(c);
            let actual_distance = determine_similarity(important_header, header);
            assert_eq!(
                actual_distance, *expected_distance,
                "similarity({}, {:?}) != {:?}",
                e, c, *expected_distance
            );
        });
    }

    #[test]
    fn test_utf8_spaces() {
        // https://en.wikipedia.org/wiki/Whitespace_character
        let test_cases = vec![
            "\u{0009}", // character tabulation
            "\u{000A}", // line feed
            "\u{000B}", // line tabulation
            "\u{000C}", // form feed
            "\u{000D}", // carriage return
            "\u{0020}", // space
            "\u{0085}", // next line
            "\u{00A0}", // no-break space
            "\u{1680}", // ogham space mark
            "\u{180E}", // mongolian vowel separator
            "\u{2000}", // en quad
            "\u{2001}", // em quad
            "\u{2002}", // en space
            "\u{2003}", // em space
            "\u{2004}", // three-per-em space
            "\u{2005}", // four-per-em space
            "\u{2006}", // six-per-em space
            "\u{2007}", // figure space
            "\u{2008}", // punctuation space
            "\u{2009}", // thin space
            "\u{200A}", // hair space
            "\u{200B}", // zero width space
            "\u{200C}", // zero width non-joiner
            "\u{200D}", // zero width joiner
            "\u{2028}", // line separator
            "\u{2029}", // paragraph separator
            "\u{202F}", // narrow no-break space
            "\u{205F}", // medium mathematical space
            "\u{2060}", // word joiner
            "\u{3000}", // ideographic space
            "\u{FEFF}", // zero width non-breaking space
        ];

        test_cases.iter().for_each(|e| {
            let important_header = http_token("transfer-encoding");
            let header_name = format!("{}Transfer-Encoding{}", e, e);
            let header = http_token(header_name.as_str());
            let actual_distance = determine_similarity(important_header, header);
            assert_eq!(
                actual_distance,
                TokenSimilarity::SameLetters,
                "similarity({}) != TokenSimilarity::SameLetters",
                to_quoted_ascii(e.as_bytes()),
            );
        });
    }

    #[test]
    fn test_utf8_delimiters() {
        // https://www.fileformat.info/info/unicode/category/Pd/list.htm
        let test_cases = vec![
            "Transfer\u{058A}Encoding",  // armenian hyphen
            "Transfer\u{05BE}Encoding",  // hebrew punctuation maqaf
            "Transfer\u{1400}Encoding",  // canadian syllabics hyphen
            "Transfer\u{1806}Encoding",  // mongolian soft hyphen
            "Transfer\u{2010}Encoding",  // hyphen
            "Transfer\u{2011}Encoding",  // non-breaking hyphen
            "Transfer\u{2012}Encoding",  // figure dash
            "Transfer\u{2013}Encoding",  // en dash
            "Transfer\u{2014}Encoding",  // em dash
            "Transfer\u{2015}Encoding",  // horizontal bar
            "Transfer\u{2E17}Encoding",  // double oblique hyphen
            "Transfer\u{2E1A}Encoding",  // hyphen with diaeresis
            "Transfer\u{2E3A}Encoding",  // two-em dash
            "Transfer\u{2E3B}Encoding",  // three-em dash
            "Transfer\u{2E40}Encoding",  // double hyphen
            "Transfer\u{301C}Encoding",  // wave dash
            "Transfer\u{3030}Encoding",  // wavy dash
            "Transfer\u{30A0}Encoding",  // katakana-hiragana double hyphen
            "Transfer\u{FE31}Encoding",  // presentation form for vertical em dash
            "Transfer\u{FE32}Encoding",  // presentation form for vertical en dash
            "Transfer\u{FE58}Encoding",  // small em dash
            "Transfer\u{FE63}Encoding",  // small hyphen-minus
            "Transfer\u{FF0D}Encoding",  // fullwidth hyphen-minus
            "Transfer\u{10EAD}Encoding", // yezidi hyphenation mark
        ];

        test_cases.iter().for_each(|e| {
            let important_header = http_token("transfer-encoding");
            let header = http_token(e);
            let actual_distance = determine_similarity(important_header, header);
            assert_eq!(
                actual_distance,
                TokenSimilarity::SameLetters,
                "similarity({}) != TokenSimilarity::SameLetters",
                to_quoted_ascii(e.as_bytes()),
            );
        });
    }

    #[test]
    fn test_arbitrary_non_utf8_bytes() {
        let test_cases = vec![
            "Transfer\u{88}Encoding",
            "Transfer\u{88}\u{88}Encoding",
            "Transfer-Encoding\u{99}",
            "Transfer-Encoding\u{99}\u{99}\u{99}",
            "\u{a0}Transfer-Encoding",
            "\u{a0}\u{a0}\u{a0}\u{a0}Transfer-Encoding",
        ];

        test_cases.iter().for_each(|e| {
            let important_header = http_token("transfer-encoding");
            let mut header = vec![];
            e.as_bytes().iter().for_each(|x| {
                // convert UTF8 to a sequence of arbitrary bytes with the 7-bit set
                header.push(match *x {
                    0xc0..=0xcf => 0x99,
                    x => x,
                });
            });
            let actual_distance = determine_similarity(important_header, header.as_slice());
            assert_eq!(
                actual_distance,
                TokenSimilarity::SameLetters,
                "similarity({}) != TokenSimilarity::SameLetters",
                to_quoted_ascii(e.as_bytes()),
            );
        });
    }

    #[test]
    fn test_valid_te() {
        let test_cases = vec![
            ("chunked", "chunked", true),
            ("compress", "compress", true),
            ("deflate", "deflate", true),
            ("gzip", "gzip", true),
            ("identity", "identity", true),
            ("chunked;", "chunked", true),
            ("chunked;extension1;extension2;", "chunked", true),
            (" CHUNKED ", "chunked", true),
            (" chunked", "chunked", true),
            (" chunked\t", "chunked", true),
            (" chunked\t\t;\t\t", "chunked", true),
            ("xchunked", "unreachable", false),
            ("x_chunked", "unreachable", false),
        ];

        test_cases.iter().for_each(|(te, canonical, valid)| {
            let valid_te = is_valid_te(http_token(te));
            match valid_te {
                Some(v) => {
                    assert!(*valid, "Expected {}={}", to_quoted_ascii(v), *valid);
                    assert!(
                        v.eq_ignore_ascii_case(http_token(canonical)),
                        "{} != {}",
                        to_quoted_ascii(v),
                        canonical
                    );
                }
                None => {
                    assert!(!*valid, "Expected {}={}", te, *valid);
                }
            }
        });
    }

    #[test]
    fn test_trim() {
        let test_cases = vec![
            ("   abc \t\t\t", "abc"),
            ("\t \t \t   abc \t\t\t", "abc"),
            ("    \t\t\t", ""),
            ("", ""),
        ];

        test_cases.iter().for_each(|(value, result)| {
            assert_eq!(rfc_whitespace_trim(http_token(value)), http_token(result));
        });
    }

    #[test]
    fn test_parse_num() {
        let test_cases = vec![
            ("0", Ok(0)),
            ("1000", Ok(1000)),
            ("\t\t\t1000  ", Ok(1000)),
            ("123456789", Ok(123456789)),
            ("18446744073709551615", Ok(18446744073709551615)),
            ("18446744073709551616", Err("64-bits overflow")),
            (
                "123456789123456789123456789123456789",
                Err("64-bits overflow"),
            ),
            ("123,123", Err("Not an integer")),
            ("123.123", Err("Not an integer")),
            ("-1", Err("Not an integer")),
        ];
        test_cases.iter().for_each(|(num_str, result)| {
            assert_eq!(parse_num(http_token(num_str)), *result);
        });
    }

    #[test]
    fn test_to_ascii() {
        let test_cases = vec![
            ("abc", "abc"),
            ("abc ", "abc "),
            ("abc\x01", "abc\\0x01"),
            ("abc\\x01", "abc\\\\x01"),
            ("\raaaa\tbbb\nccc", "\\raaaa\\tbbb\\nccc"),
            ("\nabc\u{7f}", "\\nabc\\0x7f"),
            ("\u{0}abc", "\\0x00abc"),
            (
                "\u{01}abc\u{02}abcefd901\u{03}",
                "\\0x01abc\\0x02abcefd901\\0x03",
            ),
        ];
        test_cases.iter().for_each(|(value, result)| {
            assert_eq!(
                to_quoted_ascii(http_token(value)),
                format!("\"{}\"", result)
            );
        });

        let bytes = [0x81, b'a', b'b', b'c', 0x82, b'0', b'1', b'2', 0x83];
        assert_eq!(
            to_quoted_ascii(&bytes),
            format!("\"{}\"", "\\0x81abc\\0x82012\\0x83")
        );
    }

    #[test]
    fn test_obfuscate_value() {
        let test_cases = vec![
            ("A private message", "_ _ _"),
            ("A private message\\r", "_ _ _\\\\_"),
            ("\rSensitive\tuser\ndata", "\\r_\\t_\\n_"),
            ("\nPassword", "\\n_"),
            ("\rPIN", "\\r_"),
            ("\u{0}DL-ID", "\\0x00_"),
            ("\u{01}SSN\u{02}card-number\u{03}", "\\0x01_\\0x02_\\0x03"),
        ];
        test_cases.iter().for_each(|(value, result)| {
            assert_eq!(
                obfuscate_value(http_token(value)),
                format!("\"{}\"", result)
            );
        });
    }

    #[test]
    fn test_to_ascii_large_value() {
        let large_value = std::iter::repeat('\u{1}').take(500).collect::<String>();
        assert!(to_quoted_ascii(http_token(large_value.as_str())).len() < MESSAGE_MAX_SIZE / 2);
    }

    #[test]
    fn test_obfuscate_large_value() {
        let large_value = std::iter::repeat('\u{1}').take(500).collect::<String>();
        assert!(obfuscate_value(http_token(large_value.as_str())).len() < MESSAGE_MAX_SIZE / 2);
    }

    #[test]
    fn test_tchar() {
        let delims = b"-_.!#$%&'*+^`|~";
        for c in 0..=255 {
            assert_eq!(
                is_rfc_tchar(c),
                c.is_ascii_alphanumeric() || delims.contains(&(c as u8)),
                "Didn't work out for {}",
                (c as char)
            );
        }
    }

    #[test]
    fn test_header_value() {
        for c in 0..=255 {
            assert_eq!(
                is_valid_header_value_char(c),
                is_rfc_vchar(c) || is_rfc_obs_text(c) || is_rfc_whitespace(c),
                "Didn't work out for {}",
                (c as char)
            );
        }
    }
}
