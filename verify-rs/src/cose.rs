// Apache-2.0 (public verifier repo)
//! COSE_Sign1 (RFC 9052) — the deterministic hand adapter for SCITT (B25 W1).
//!
//! The Rust twin of `core/cose.py`. A COSE_Sign1 is the CBOR array (tag 18)
//! `[protected: bstr, unprotected: map, payload: bstr / null, signature: bstr]`
//! under the B24 deterministic profile (scitt-action-profile-v1 §1). The
//! SIGNED bytes — the `Sig_structure` — flow through the sanctioned canonical
//! emitter in `crate::cbor`, so Ed25519 covers exactly the canonical CBOR the
//! rest of the stack emits. Only the envelope framing and the COSE header maps
//! carry INTEGER labels, which `crate::cbor` (text keys only) cannot express,
//! so those few pieces are hand-encoded here with the SAME rules — minimal
//! heads, no tags/floats, map keys sorted by their encoded bytes — that
//! `src/cbor.rs` and `core/cborcanon.py` already pin. Byte-identical to Python;
//! the shared vectors in `tests/golden/cose/` are the gate.
//!
//! Fail-closed: `verify_sign1` returns `None` on hostile input, never panics.
//! No new dependency (ed25519-dalek and ciborium are already in the graph);
//! `build_sign1` is exercised only by the canonical-byte test.

use ciborium::value::Integer;
use ciborium::Value;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;

const TAG_SIGN1: u8 = 0xD2; // CBOR tag 18 wrapping the COSE_Sign1 array
const STATEMENT_CTY: &str = "application/vnd.swarrm.action-certificate+cbor";
const BUILD_DEPTH: i64 = 32;

// ---- minimal deterministic CBOR for the COSE envelope (int + text keys) ----

fn head(out: &mut Vec<u8>, major: u8, arg: u64) {
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

fn enc_int(out: &mut Vec<u8>, i: i128) -> bool {
    if i < i64::MIN as i128 || i > i64::MAX as i128 {
        return false;
    }
    if i >= 0 {
        head(out, 0, i as u64);
    } else {
        head(out, 1, (-1 - i) as u64);
    }
    true
}

fn enc(v: &Value, out: &mut Vec<u8>, limit: i64) -> bool {
    if limit < 0 {
        return false;
    }
    match v {
        Value::Null => out.push(0xf6),
        Value::Integer(i) => return enc_int(out, i128::from(*i)),
        Value::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Bytes(b) => {
            head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Array(a) => {
            head(out, 4, a.len() as u64);
            for item in a {
                if !enc(item, out, limit - 1) {
                    return false;
                }
            }
        }
        Value::Map(m) => return enc_map(m, out, limit),
        _ => return false, // floats, tags, bool, other simple values
    }
    true
}

fn enc_key(k: &Value, out: &mut Vec<u8>) -> bool {
    match k {
        Value::Integer(i) => enc_int(out, i128::from(*i)),
        Value::Text(s) => {
            head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
            true
        }
        _ => false,
    }
}

fn enc_map(m: &[(Value, Value)], out: &mut Vec<u8>, limit: i64) -> bool {
    let mut pairs: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(m.len());
    for (k, v) in m {
        let mut kb = Vec::new();
        let mut vb = Vec::new();
        if !enc_key(k, &mut kb) || !enc(v, &mut vb, limit - 1) {
            return false;
        }
        pairs.push((kb, vb));
    }
    pairs.sort_by(|a, b| a.0.cmp(&b.0));
    if pairs.windows(2).any(|w| w[0].0 == w[1].0) {
        return false;
    }
    head(out, 5, pairs.len() as u64);
    for (kb, vb) in &pairs {
        out.extend_from_slice(kb);
        out.extend_from_slice(vb);
    }
    true
}

fn read_head(data: &[u8], i: usize) -> Option<(u8, u64, usize)> {
    let byte = *data.get(i)?;
    let (major, info) = (byte >> 5, byte & 0x1f);
    let i = i + 1;
    if major == 6 {
        return None; // tag
    }
    if major == 7 {
        return (info == 22).then_some((major, 0, i)); // null only
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

fn dec_item(data: &[u8], i: usize, depth: i64) -> Option<(Value, usize)> {
    if depth < 0 {
        return None;
    }
    let (major, arg, i) = read_head(data, i)?;
    match major {
        0 => Some((Value::Integer(i64::try_from(arg).ok()?.into()), i)),
        1 => Some((Value::Integer((-1 - i64::try_from(arg).ok()?).into()), i)),
        2 | 3 => {
            let end = i.checked_add(usize::try_from(arg).ok()?)?;
            let raw = data.get(i..end)?;
            let v = if major == 3 {
                Value::Text(std::str::from_utf8(raw).ok()?.to_owned())
            } else {
                Value::Bytes(raw.to_vec())
            };
            Some((v, end))
        }
        4 => dec_seq(data, i, arg, depth, false),
        5 => dec_seq(data, i, arg, depth, true),
        _ => Some((Value::Null, i)), // major 7: null (read_head admits nothing else)
    }
}

fn dec_seq(data: &[u8], mut i: usize, count: u64, depth: i64, is_map: bool) -> Option<(Value, usize)> {
    let mut items: Vec<Value> = Vec::new();
    let mut pairs: Vec<(Value, Value)> = Vec::new();
    for _ in 0..count {
        let (key, ni) = dec_item(data, i, depth - 1)?;
        i = ni;
        if !is_map {
            items.push(key);
            continue;
        }
        if !matches!(key, Value::Integer(_) | Value::Text(_)) {
            return None;
        }
        let (value, nj) = dec_item(data, i, depth - 1)?;
        i = nj;
        pairs.push((key, value));
    }
    let v = if is_map { Value::Map(pairs) } else { Value::Array(items) };
    Some((v, i))
}

fn decode_canonical(data: &[u8], max_depth: usize) -> Option<Value> {
    let (v, end) = dec_item(data, 0, max_depth as i64)?;
    let mut re = Vec::new();
    if end != data.len() || !enc(&v, &mut re, max_depth as i64) || re != data {
        return None;
    }
    Some(v)
}

// ---- COSE_Sign1 ----

fn sig_structure(protected_bytes: &[u8], payload: Option<&[u8]>) -> Option<Vec<u8>> {
    let body = payload.unwrap_or(&[]);
    let s = Value::Array(vec![
        Value::Text("Signature1".to_owned()),
        Value::Bytes(protected_bytes.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(body.to_vec()),
    ]);
    crate::cbor::canonical_cbor(&s)
}

/// Deterministic COSE_Sign1 bytes signed by the Ed25519 `seed` (alg -8).
pub(crate) fn build_sign1(
    protected: &Value,
    unprotected: &Value,
    payload: Option<&[u8]>,
    seed: &[u8; 32],
) -> Option<Vec<u8>> {
    let mut protected_bytes = Vec::new();
    if !enc(protected, &mut protected_bytes, BUILD_DEPTH) {
        return None;
    }
    let sig_input = sig_structure(&protected_bytes, payload)?;
    let signature = SigningKey::from_bytes(seed).sign(&sig_input).to_bytes().to_vec();
    let array = Value::Array(vec![
        Value::Bytes(protected_bytes),
        unprotected.clone(),
        payload.map_or(Value::Null, |b| Value::Bytes(b.to_vec())),
        Value::Bytes(signature),
    ]);
    let mut out = vec![TAG_SIGN1];
    enc(&array, &mut out, BUILD_DEPTH).then_some(out)
}

/// A verified COSE_Sign1's decoded pieces (kid resolved from protected label 4).
#[allow(dead_code)] // fields consumed by later B25 weeks and the W1 test
pub(crate) struct Sign1 {
    pub(crate) protected: Value,
    pub(crate) unprotected: Value,
    pub(crate) payload: Option<Vec<u8>>,
    pub(crate) kid: String,
}

fn kid_of(protected: &Value) -> Option<String> {
    let Value::Map(entries) = protected else { return None };
    for (k, v) in entries {
        if matches!(k, Value::Integer(i) if i128::from(*i) == 4) {
            if let Value::Bytes(b) = v {
                return std::str::from_utf8(b).ok().map(str::to_owned);
            }
        }
    }
    None
}

fn unpack(array: Value) -> Option<(Vec<u8>, Value, Option<Vec<u8>>, Vec<u8>)> {
    let Value::Array(mut items) = array else { return None };
    if items.len() != 4 {
        return None;
    }
    let signature = match items.pop()? {
        Value::Bytes(b) => b,
        _ => return None,
    };
    let payload = match items.pop()? {
        Value::Null => None,
        Value::Bytes(b) => Some(b),
        _ => return None,
    };
    let unprotected = items.pop()?;
    if !matches!(unprotected, Value::Map(_)) {
        return None;
    }
    let protected_bytes = match items.pop()? {
        Value::Bytes(b) => b,
        _ => return None,
    };
    Some((protected_bytes, unprotected, payload, signature))
}

/// Verify a COSE_Sign1 (caps before crypto); `None` on ANY failure — hostile
/// bytes fail closed, never panic. `keys` maps kid → raw 32-byte Ed25519 key.
pub(crate) fn verify_sign1(
    cose: &[u8],
    keys: &BTreeMap<String, [u8; 32]>,
    max_bytes: usize,
    max_depth: usize,
) -> Option<Sign1> {
    if cose.len() > max_bytes || cose.first() != Some(&TAG_SIGN1) {
        return None;
    }
    let (protected_bytes, unprotected, payload, signature) =
        unpack(decode_canonical(&cose[1..], max_depth)?)?;
    let protected = decode_canonical(&protected_bytes, max_depth)?;
    let kid = kid_of(&protected)?;
    let public_raw = keys.get(&kid)?;
    let sig_input = sig_structure(&protected_bytes, payload.as_deref())?;
    if !crate::ed25519_verify(public_raw, &sig_input, &signature) {
        return None;
    }
    Some(Sign1 { protected, unprotected, payload, kid })
}

/// Issuer Signed Statement protected header (profile §2).
#[allow(dead_code)] // header builders used by later B25 weeks and the W1 test
pub(crate) fn statement_protected(kid: &str, iss: &str, sub: &str) -> Value {
    let int = |n: i64| Value::Integer(Integer::from(n));
    Value::Map(vec![
        (int(1), int(-8)),
        (int(3), Value::Text(STATEMENT_CTY.to_owned())),
        (int(4), Value::Bytes(kid.as_bytes().to_vec())),
        (
            int(15),
            Value::Map(vec![
                (int(1), Value::Text(iss.to_owned())),
                (int(2), Value::Text(sub.to_owned())),
            ]),
        ),
    ])
}

/// TS Receipt protected header (profile §4); 395:1 = RFC9162_SHA256.
#[allow(dead_code)]
pub(crate) fn receipt_protected(kid: &str) -> Value {
    let int = |n: i64| Value::Integer(Integer::from(n));
    Value::Map(vec![
        (int(1), int(-8)),
        (int(4), Value::Bytes(kid.as_bytes().to_vec())),
        (int(395), int(1)),
    ])
}
