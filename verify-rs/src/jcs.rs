// Apache-2.0 (public verifier repo)
//! Minimal RFC 8785 (JCS) canonicalization over serde_json::Value.
//!
//! Covers RFC 8785's JSON value domain, including finite binary64 values
//! rendered with ECMAScript Number::toString. Canonicalization FAILS (None)
//! on hostile numeric shapes or nesting past MAX_DEPTH, long before stack
//! overflow, so a failed canonicalization can never verify.

use serde_json::Value;

/// Same cap as MAX_JCS_DEPTH in core/canonical.py — the two verifiers must
/// reject identically.
pub(crate) const MAX_DEPTH: i64 = 64;
pub(crate) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

fn number_text(number: &serde_json::Number) -> Option<String> {
    if number.is_i64() {
        number.as_i64().filter(|value| (-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(value)).map(|value| value.to_string())
    } else if number.is_u64() {
        number.as_u64().filter(|value| *value <= MAX_SAFE_INTEGER as u64).map(|value| value.to_string())
    } else {
        number.as_f64().filter(|value| value.is_finite()).map(|value| ryu_js::Buffer::new().format_finite(value).to_owned())
    }
}

fn numbers_match(v: &Value, integers_only: bool, limit: i64) -> bool {
    if limit < 0 {
        return false;
    }
    match v {
        Value::Number(number) => (!integers_only || !number.is_f64()) && number_text(number).is_some(),
        Value::Array(items) => items.iter().all(|item| numbers_match(item, integers_only, limit - 1)),
        Value::Object(items) => items.values().all(|item| numbers_match(item, integers_only, limit - 1)),
        _ => true,
    }
}

pub(crate) fn numbers_within_profile(v: &Value) -> bool {
    numbers_match(v, false, MAX_DEPTH)
}

pub(crate) fn canonical_integer_checked(v: &Value) -> Option<Vec<u8>> {
    numbers_match(v, true, MAX_DEPTH).then(|| canonical_checked(v)).flatten()
}

pub(crate) fn promote_jcs_integer_lexemes(v: &mut Value) -> bool {
    match v {
        Value::Number(number) if number.as_i64().is_some_and(|value| !(-MAX_SAFE_INTEGER..=MAX_SAFE_INTEGER).contains(&value)) || number.as_u64().is_some_and(|value| value > MAX_SAFE_INTEGER as u64) => {
            let Some(promoted) = number.as_f64().and_then(serde_json::Number::from_f64) else {
                return false;
            };
            *number = promoted;
            true
        }
        Value::Array(items) => items.iter_mut().all(promote_jcs_integer_lexemes),
        Value::Object(items) => items.values_mut().all(promote_jcs_integer_lexemes),
        _ => true,
    }
}

/// Fallible canonicalization: None on over-deep nesting, a non-finite value,
/// or an integer outside RFC 8785's interoperable IEEE-754 domain.
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
        Value::Null | Value::Bool(_) | Value::String(_) => serde_json::to_writer(out, v).expect("writing JSON to Vec cannot fail"),
        Value::Number(number) => {
            let Some(text) = number_text(number) else { return false };
            out.extend_from_slice(text.as_bytes());
        }
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
                serde_json::to_writer(&mut *out, k).expect("writing JSON to Vec cannot fail");
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
