// Apache-2.0 (public verifier repo)
//! Shared deterministic-CBOR wire primitives for every verifier profile.
//!
//! This module owns item-head encoding, the bounded iterative scan, and the
//! profile-parameterized value emitter (B39.2). The emission rules — minimal
//! hand-encoded heads, map keys sorted by their encoded bytes, duplicate keys
//! rejected, bounded depth, fail-closed on anything outside the model — are
//! identical for certificates, COSE envelopes and B28 CWTs; only the admitted
//! value set differs, so each module declares a [`Profile`] and the bytes stay
//! pinned by the shared golden vectors. This mirrors `core/cborcanon.py`,
//! where one Python codec serves the same profiles via `allow_integer_keys`.

use ciborium::Value;

/// The value-model choices that distinguish the deterministic profiles.
#[derive(Clone, Copy)]
pub(crate) struct Profile {
    /// Maps may carry signed 64-bit integer keys as well as text keys
    /// (COSE/CWT header and claim maps); the certificate profile admits
    /// text keys only.
    pub(crate) int_keys: bool,
    /// The model includes booleans; COSE envelope framing does not.
    pub(crate) bools: bool,
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

fn write_text(out: &mut Vec<u8>, s: &str) {
    write_head(out, 3, s.len() as u64);
    out.extend_from_slice(s.as_bytes());
}

/// Emit one value under the profile's model; `false` on floats, tags,
/// out-of-profile simple values, out-of-range integers, bad map keys, or
/// nesting deeper than `limit` admits. Never panics.
pub(crate) fn write_value(v: &Value, out: &mut Vec<u8>, limit: i64, p: &Profile) -> bool {
    if limit < 0 {
        return false; // deeper than the caller's cap — refuse, don't recurse on
    }
    match v {
        Value::Null => out.push(0xf6),
        Value::Bool(b) if p.bools => out.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Integer(i) => return write_int(out, i128::from(*i)),
        Value::Text(s) => write_text(out, s),
        Value::Bytes(b) => {
            write_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Array(a) => {
            write_head(out, 4, a.len() as u64);
            for item in a {
                if !write_value(item, out, limit - 1, p) {
                    return false;
                }
            }
        }
        Value::Map(m) => return write_map(m, out, limit, p),
        _ => return false, // floats, tags, profile-excluded simple values
    }
    true
}

fn write_key(k: &Value, out: &mut Vec<u8>, p: &Profile) -> bool {
    match k {
        Value::Integer(i) if p.int_keys => write_int(out, i128::from(*i)),
        Value::Text(s) => {
            write_text(out, s);
            true
        }
        _ => false,
    }
}

fn write_map(m: &[(Value, Value)], out: &mut Vec<u8>, limit: i64, p: &Profile) -> bool {
    // Sort by ENCODED key bytes; equal encoded keys are duplicates — reject.
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(m.len());
    for (k, v) in m {
        let (mut kb, mut vb) = (Vec::new(), Vec::new());
        if !write_key(k, &mut kb, p) || !write_value(v, &mut vb, limit - 1, p) {
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

/// Canonical bytes for `v` under the profile, or `None` outside the model.
pub(crate) fn canonical_bytes(v: &Value, limit: i64, p: &Profile) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    write_value(v, &mut out, limit, p).then_some(out)
}

/// Emit a minimal CBOR item head. COSE, certificates, and Counterparty Assurance reuse this exact
/// primitive so their deterministic encodings cannot drift on width selection.
pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, arg: u64) {
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

/// Parse one item head at `i` -> (major, argument, next offset). Rejects tags,
/// floats, simple values other than false/true/null, indefinite/reserved info.
pub(crate) fn read_head(data: &[u8], i: usize) -> Option<(u8, u64, usize)> {
    let byte = *data.get(i)?;
    let (major, info) = (byte >> 5, byte & 0x1f);
    let i = i + 1;
    if major == 6 {
        return None; // tag
    }
    if major == 7 {
        return matches!(info, 20..=22).then_some((major, 0, i)); // false/true/null only
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
    for byte in raw {
        arg = (arg << 8) | u64::from(*byte);
    }
    Some((major, arg, i + width))
}

/// Iterative structural scan of one item. An explicit stack bounds hostile
/// nesting; every claimed length must fit in the buffer before materialization.
fn scan_string(data: &[u8], i: &mut usize, arg: u64) -> Option<()> {
    let remaining = data.len().checked_sub(*i)?;
    (arg <= remaining as u64).then_some(())?;
    *i += arg as usize;
    Some(())
}

fn scan_container(data: &[u8], i: usize, major: u8, arg: u64, stack: &mut Vec<u64>, max_depth: usize) -> Option<bool> {
    let count = if major == 4 { arg } else { arg.checked_mul(2)? };
    if count > (data.len() - i) as u64 {
        return None; // every member needs >= 1 byte
    }
    if count == 0 {
        return Some(false);
    }
    if stack.len() >= max_depth {
        return None;
    }
    stack.push(count);
    Some(true)
}

fn scan_item(data: &[u8], i: &mut usize, major: u8, arg: u64, stack: &mut Vec<u64>, max_depth: usize) -> Option<bool> {
    match major {
        2 | 3 => scan_string(data, i, arg).map(|()| false),
        4 | 5 => scan_container(data, *i, major, arg, stack, max_depth),
        _ => Some(false),
    }
}

fn complete_item(stack: &mut Vec<u64>) -> bool {
    while let Some(top) = stack.last_mut() {
        *top -= 1;
        if *top > 0 {
            return false;
        }
        stack.pop();
    }
    true
}

pub(crate) fn structural_scan(data: &[u8], max_depth: usize, max_items: usize) -> Option<usize> {
    let mut stack: Vec<u64> = Vec::new();
    let mut i = 0usize;
    let mut items = 0usize;
    loop {
        items = items.checked_add(1)?;
        if items > max_items {
            return None;
        }
        let (major, arg, next) = read_head(data, i)?;
        i = next;
        if scan_item(data, &mut i, major, arg, &mut stack, max_depth)? {
            continue;
        }
        if complete_item(&mut stack) {
            return Some(i);
        }
    }
}
