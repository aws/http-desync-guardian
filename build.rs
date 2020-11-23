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
use std::env;
use std::fs::File;
use std::io::Write;

const CR: u8 = b'\r';
const LF: u8 = b'\n';
const SP: u8 = b' ';
const HT: u8 = b'\t';
const DEL: u8 = 127;
const NIL: u8 = 0;
const TCHAR: &[u8] = b"-_.!#$%&'*+^`|~";

fn format_char(b: u8) -> String {
    use std::fmt::Write;

    let mut str = String::new();
    match b {
        b'\r' => str.push_str("\\r"),
        b'\n' => str.push_str("\\n"),
        b'\t' => str.push_str("\\t"),
        _ if is_rfc_vchar(b) => {
            str.push(b as char);
        }
        _ => {
            write!(str, "\\{:#04x}", b).expect("Writing to strings is infallible");
        }
    };
    str
}

fn generate_table(name: &str, predicate: fn(u8) -> bool) -> String {
    use std::fmt::Write;

    let mut t = String::new();
    write!(t, "pub static {}: [bool; 256] = [\r\n    ", name).ok();
    for i in 0..=255_u8 {
        write!(t, " {} /* {} */,", (predicate)(i), format_char(i)).ok();
        if i % 4 == 3 {
            write!(t, "\r\n    ").ok();
        }
    }
    write!(t, "];\r\n").ok();
    t
}

fn is_valid_uri_char(b: u8) -> bool {
    // disable CTL in URL
    b > SP && b != DEL
}

fn is_rfc_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || TCHAR.contains(&b)
}

fn is_rfc_vchar(b: u8) -> bool {
    (SP..DEL).contains(&b)
}

fn is_rfc_obs_text(b: u8) -> bool {
    b >= 0x80
}

fn is_rfc_whitespace(b: u8) -> bool {
    b == SP || b == HT
}

fn is_bad_http_character(b: u8) -> bool {
    // these characters are absolutely unacceptable in header names/values
    // it means multi-line headers are not accepted too
    b == CR || b == LF || b == NIL
}

type TableGenerator = fn(u8) -> bool;

fn generate_lookup_tables() {
    use std::fmt::Write;

    let tables: &[(&str, TableGenerator)] = &[
        ("TCHAR_TABLE", |b| is_rfc_tchar(b)),
        ("VCHAR", |b| is_rfc_vchar(b)),
        ("BAD_CHARACTERS", |b| is_bad_http_character(b)),
        ("RFC_WHITE_SPACE", |b| is_rfc_whitespace(b)),
        ("VALID_URI_CHARS", |b| is_valid_uri_char(b)),
        ("HEADER_VALUE_CHARS", |b| {
            is_rfc_vchar(b) || is_rfc_obs_text(b) || is_rfc_whitespace(b)
        }),
    ];

    let mut char_tables = String::new();
    for table in tables {
        write!(char_tables, "{}", generate_table(table.0, table.1))
            .expect("Writing to strings is infallible");
    }
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR variable is not set");
    let mut file =
        File::create(format!("{}/char_tables.rs", out_dir)).expect("Cannot open file for writing");
    file.write_all(char_tables.as_bytes())
        .expect("Cannot write to file");
}

fn main() {
    generate_lookup_tables();
}
