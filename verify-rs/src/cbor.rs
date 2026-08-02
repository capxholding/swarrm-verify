// Apache-2.0 (public verifier repo)
//! Deterministic CBOR for the certificate profile (SPEC/certificate-v1.md §1).
//!
//! RFC 8949 §4.2.1 Core Deterministic Encoding over the RESTRICTED model:
//! null, bool, signed 64-bit integers, UTF-8 text, byte strings, arrays,
//! maps with TEXT keys only. Definite lengths, no tags, no floats, map keys
//! sorted by the bytewise-lexicographic order of their ENCODED bytes.
//!
//! The item heads are HAND-ENCODED: ciborium (owner-sanctioned codec O·1)
//! does not sort map keys and makes no emission-order promise, so the
//! emitter here owns determinism outright — determinism beats convenience.
//! ciborium is used only to materialize `ciborium::Value` on decode, AFTER
//! an iterative structural pre-scan (explicit stack, no recursion) has
//! enforced the depth/size caps, so hostile bytes can never crash us (H5).
//! Fail-closed: every deviation is `None`/`Err` — never a panic.
//!
//! Mirrors core/cborcanon.py; the shared vectors in tests/golden/cbor/ pin
//! byte-identical output across both engines.

use ciborium::Value;

/// Same nesting cap as MAX_CBOR_DEPTH in core/cborcanon.py and the JCS cap —
/// both engines must reject identically.
pub(crate) const MAX_DEPTH: i64 = 64;
/// Default byte cap: the complete offline pack budget (certificate-v1 §4.1).
/// Callers verifying a bare core pass the tighter 1 MiB cap explicitly.
pub(crate) const MAX_BYTES: usize = 16 * 1024 * 1024;

fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    match arg {
        0..=23 => out.push((major << 5) | arg as u8),
        24..=0xff => out.extend_from_slice(&[(major << 5) | 24, arg as u8]),
        0x100..=0xffff => {
            out.push((major << 5) | 25);
            out.extend_from_slice(&(arg as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push((major << 5) | 26);
            out.extend_from_slice(&(arg as u32).to_be_bytes());
        }
        _ => {
            out.push((major << 5) | 27);
            out.extend_from_slice(&arg.to_be_bytes());
        }
    }
}

fn write_text(out: &mut Vec<u8>, s: &str) {
    write_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

fn write_int(out: &mut Vec<u8>, i: i128) -> bool {
    // Restricted model: signed 64-bit only (rejects the u64 > i64::MAX range).
    if i < i64::MIN as i128 || i > i64::MAX as i128 {
        return false;
    }
    if i >= 0 {
        write_head(out, 0, i as u64);
    } else {
        write_head(out, 1, (-1 - i) as u64);
    }
    true
}

fn write_value(v: &Value, out: &mut Vec<u8>, limit: i64) -> bool {
    if limit < 0 {
        return false; // deeper than MAX_DEPTH — refuse, don't recurse on
    }
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(b) => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Integer(i) => return write_int(out, i128::from(*i)),
        Value::Text(s) => write_text(out, s),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Array(a) => {
            write_head(out, 4, a.len() as u64);
            for item in a {
                if !write_value(item, out, limit - 1) {
                    return false;
                }
            }
        }
        Value::Map(m) => return write_map(m, out, limit),
        _ => return false, // floats, tags, other simple values
    }
    true
}

fn write_map(m: &[(Value, Value)], out: &mut Vec<u8>, limit: i64) -> bool {
    // Sort by ENCODED key bytes; equal encoded keys are duplicates — reject.
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(m.len());
    for (k, v) in m {
        let Value::Text(key) = k else { return false };
        let mut kb = Vec::new();
        write_text(&mut kb, key);
        let mut vb = Vec::new();
        if !write_value(v, &mut vb, limit - 1) {
            return false;
        }
        pairs.push((kb, vb));
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    if pairs.windows(2).any(|w| w[0].0 == w[1].0) {
        return false;
    }
    write_head(out, 5, pairs.len() as u64);
    for (kb, vb) in &pairs {
        out.extend_from_slice(kb);
        out.extend_from_slice(vb);
    }
    true
}

/// Canonical bytes for a `ciborium::Value` within the restricted model;
/// `None` on floats, tags, non-text or duplicate map keys, out-of-range
/// integers, or over-deep nesting. Never panics.
pub(crate) fn canonical_cbor(v: &Value) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    write_value(v, &mut out, MAX_DEPTH).then_some(out)
}

fn json_to_cbor(v: &serde_json::Value, limit: i64) -> Option<Value> {
    if limit < 0 {
        return None;
    }
    Some(match v {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => Value::Integer(n.as_i64()?.into()), // floats/u64>i64: None
        serde_json::Value::String(s) => Value::Text(s.clone()),
        serde_json::Value::Array(a) => {
            let items: Option<Vec<Value>> = a.iter().map(|x| json_to_cbor(x, limit - 1)).collect();
            Value::Array(items?)
        }
        serde_json::Value::Object(m) => Value::Map(
            m.iter()
                .map(|(k, x)| Some((Value::Text(k.clone()), json_to_cbor(x, limit - 1)?)))
                .collect::<Option<Vec<_>>>()?,
        ),
    })
}

/// Canonical bytes for a JSON-compatible structure (the bundle/verdict-input
/// shapes) — the same object always yields the same bytes as core/cborcanon.py.
pub(crate) fn canonical_from_json(v: &serde_json::Value) -> Option<Vec<u8>> {
    canonical_cbor(&json_to_cbor(v, MAX_DEPTH)?)
}

/// Parse one item head at `i` → (major, argument, next offset). Rejects tags,
/// floats, simple values other than false/true/null, indefinite/reserved info.
fn read_head(data: &[u8], i: usize) -> Option<(u8, u64, usize)> {
    let byte = *data.get(i)?;
    let (major, info) = (byte >> 5, byte & 0x1f);
    let i = i + 1;
    if major == 6 {
        return None; // tag
    }
    if major == 7 {
        return matches!(info, 20 | 21 | 22).then_some((major, 0, i)); // false/true/null only
    }
    if info < 24 {
        return Some((major, u64::from(info), i));
    }
    if info > 27 {
        return None; // 28-30 reserved, 31 indefinite
    }
    let width = 1usize << (info - 24);
    let raw = data.get(i..i + width)?;
    let mut arg = 0u64;
    for b in raw {
        arg = (arg << 8) | u64::from(*b);
    }
    Some((major, arg, i + width))
}

/// Iterative structural scan of ONE item; returns its end offset. Explicit
/// stack of remaining-member counts — hostile nesting never touches the call
/// stack; every claimed length must fit in the buffer, bounding allocations.
fn scan(data: &[u8], max_depth: usize) -> Option<usize> {
    let mut stack: Vec<u64> = Vec::new();
    let mut i = 0usize;
    loop {
        let (major, arg, next) = read_head(data, i)?;
        i = next;
        match major {
            2 | 3 => {
                // string payload must fit
                if arg > (data.len() - i) as u64 {
                    return None;
                }
                i += arg as usize;
            }
            4 | 5 => {
                let count = if major == 4 { arg } else { arg.checked_mul(2)? };
                if count > (data.len() - i) as u64 {
                    return None; // every member needs >= 1 byte
                }
                if count > 0 {
                    if stack.len() >= max_depth {
                        return None;
                    }
                    stack.push(count);
                    continue;
                }
            }
            _ => {}
        }
        while let Some(top) = stack.last_mut() {
            *top -= 1;
            if *top > 0 {
                break;
            }
            stack.pop();
        }
        if stack.is_empty() {
            return Some(i);
        }
    }
}

/// Decode canonical-profile bytes into a `ciborium::Value`, or `None`.
/// Never panics on hostile input. Accepts EXACTLY the bytes `canonical_cbor`
/// would emit for the result: the pre-scan rejects tags/floats/indefinite/
/// over-depth/trailing garbage before ciborium runs (bounded recursion), and
/// the re-encode compare rejects duplicate or unsorted keys, out-of-range
/// integers and non-minimal heads.
pub(crate) fn decode_cbor(data: &[u8], max_depth: usize, max_bytes: usize) -> Option<Value> {
    if data.len() > max_bytes || scan(data, max_depth)? != data.len() {
        return None;
    }
    let value: Value = ciborium::de::from_reader(data).ok()?;
    (canonical_cbor(&value)? == data).then_some(value)
}
