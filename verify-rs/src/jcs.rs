// Apache-2.0 (public verifier repo)
//! Minimal RFC 8785 (JCS) canonicalization over serde_json::Value.
//!
//! Covers exactly the value shapes that appear in signed structures here:
//! objects (keys sorted by UTF-16 code units), arrays, strings, integers,
//! booleans, null. Non-integer numbers do not appear in any structure this
//! verifier canonicalizes (checkpoint bodies, JWKs) — they would panic
//! loudly rather than silently mis-canonicalize.

use serde_json::Value;

pub fn canonical(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(v, &mut out);
    out
}

fn write_value(v: &Value, out: &mut Vec<u8>) {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        Value::Number(n) => {
            // Only integers occur in canonicalized structures here.
            let i = n.as_i64().or_else(|| n.as_u64().map(|u| u as i64));
            match i {
                Some(i) => out.extend_from_slice(i.to_string().as_bytes()),
                None => panic!("JCS: non-integer number in a canonicalized structure"),
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(a) => {
            out.push(b'[');
            for (i, e) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(e, out);
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
                write_value(&m[*k], out);
            }
            out.push(b'}');
        }
    }
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
