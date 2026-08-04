// Apache-2.0 (public verifier repo)
//! Minimal RFC 8785 (JCS) canonicalization over serde_json::Value.
//!
//! Covers exactly the value shapes that appear in signed structures here:
//! objects (keys sorted by UTF-16 code units), arrays, strings, integers,
//! booleans, null. Canonicalization FAILS (None) instead of panicking on
//! hostile shapes (H5): non-integer numbers, and container nesting past
//! MAX_DEPTH — the guard bails at depth MAX_DEPTH+1, so recursion is bounded
//! long before it could overflow the stack, and a failed canonicalization
//! can never verify (no honest signature covers its output).

use serde_json::Value;

/// Same cap as MAX_JCS_DEPTH in core/canonical.py — the two verifiers must
/// reject identically.
pub(crate) const MAX_DEPTH: i64 = 64;
const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// Fallible canonicalization: None on over-deep nesting, a float, or an
/// integer outside RFC 8785's interoperable IEEE-754 domain. Verification
/// callers must treat None as "does not verify".
pub(crate) fn canonical_checked(v: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    if write_value(v, &mut out, MAX_DEPTH) {
        Some(out)
    } else {
        None
    }
}

fn write_value(v: &Value, out: &mut Vec<u8>, limit: i64) -> bool {
    if limit < 0 {
        return false; // nested deeper than MAX_DEPTH — refuse, don't recurse on
    }
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            let Some(i) = n
                .as_i64()
                .filter(|i| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(i))
            else {
                return false;
            };
            out.extend_from_slice(i.to_string().as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                if !write_value(e, out, limit - 1) {
                    return false;
                }
            }
            out.push(b']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| utf16_cmp(a, b));
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                if !write_value(&m[*k], out, limit - 1) {
                    return false;
                }
            }
            out.push(b'}');
        }
    }
    true
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes())
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes())
            }
        }
    }
    out.push(b'"');
}
