// Apache-2.0 (public verifier repo)
//! COSE_Sign1 (RFC 9052) — the deterministic hand adapter for SCITT.
//!
//! The Rust twin of `core/cose.py`. A COSE_Sign1 is the CBOR array (tag 18)
//! `[protected: bstr, unprotected: map, payload: bstr / null, signature: bstr]`
//! under the certificate deterministic profile (scitt-action-profile-v1 §1). The
//! SIGNED bytes — the `Sig_structure` — flow through the sanctioned canonical
//! emitter in `crate::cbor`, so Ed25519 covers exactly the canonical CBOR the
//! rest of the stack emits. Only the envelope framing and the COSE header maps
//! carry INTEGER labels, which the certificate profile cannot express, so this
//! module pins the shared `cbor_wire` emitter to the COSE model instead —
//! integer keys admitted, booleans excluded, the same minimal heads and
//! encoded-byte key order `core/cborcanon.py` pins. Byte-identical to Python;
//! the shared vectors in `tests/golden/cose/` are the gate.
//!
//! Fail-closed: `verify_sign1` returns `None` on hostile input, never panics.
//! No new dependency (ed25519-dalek and ciborium are already in the graph);
//! `build_sign1` is exercised only by the canonical-byte test.

use ciborium::Value;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeMap;

use crate::cbor_wire::{canonical_bytes, structural_scan, write_value, Profile};

const TAG_SIGN1: u8 = 0xD2; // CBOR tag 18 wrapping the COSE_Sign1 array
const BUILD_DEPTH: i64 = 32;

/// COSE's envelope model: integer or text map keys; no booleans.
const COSE_PROFILE: Profile = Profile { int_keys: true, bools: false };

/// Decode envelope bytes that are EXACTLY what the shared emitter would emit
/// under the COSE profile; `None` otherwise, never a panic. The bounded
/// pre-scan rejects tags/floats/indefinite forms, over-deep nesting and
/// trailing bytes before ciborium materializes anything, and the re-encode
/// compare rejects unsorted or duplicate keys, non-minimal heads and every
/// value outside the model (booleans included). The item cap can never bind
/// below the callers' 64 KiB byte caps: every CBOR item costs at least one
/// byte, so `items <= len(data) <= max_bytes < MAX_ITEMS`.
fn decode_canonical(data: &[u8], max_depth: usize) -> Option<Value> {
    if structural_scan(data, max_depth, crate::cbor::MAX_ITEMS)? != data.len() {
        return None;
    }
    let v: Value = ciborium::de::from_reader(data).ok()?;
    (canonical_bytes(&v, max_depth as i64, &COSE_PROFILE)? == data).then_some(v)
}

// ---- COSE_Sign1 ----

fn sig_structure(protected_bytes: &[u8], payload: Option<&[u8]>) -> Option<Vec<u8>> {
    let body = payload.unwrap_or(&[]);
    let s = Value::Array(vec![Value::Text("Signature1".to_owned()), Value::Bytes(protected_bytes.to_vec()), Value::Bytes(Vec::new()), Value::Bytes(body.to_vec())]);
    crate::cbor::canonical_cbor(&s)
}

/// Deterministic COSE_Sign1 bytes signed by the Ed25519 `seed` (alg -8).
pub(crate) fn build_sign1(protected: &Value, unprotected: &Value, payload: Option<&[u8]>, seed: &[u8; 32]) -> Option<Vec<u8>> {
    let protected_bytes = canonical_bytes(protected, BUILD_DEPTH, &COSE_PROFILE)?;
    let sig_input = sig_structure(&protected_bytes, payload)?;
    let signature = SigningKey::from_bytes(seed).sign(&sig_input).to_bytes().to_vec();
    let array = Value::Array(vec![Value::Bytes(protected_bytes), unprotected.clone(), payload.map_or(Value::Null, |b| Value::Bytes(b.to_vec())), Value::Bytes(signature)]);
    let mut out = vec![TAG_SIGN1];
    write_value(&array, &mut out, BUILD_DEPTH, &COSE_PROFILE).then_some(out)
}

/// A verified COSE_Sign1's decoded pieces (kid resolved from protected label 4).
#[allow(dead_code)] // fields consumed by later SCITT stages and the W1 test
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

type Sign1Parts = (Vec<u8>, Value, Option<Vec<u8>>, Vec<u8>); // (protected bytes, unprotected, payload, signature)

fn unpack(array: Value) -> Option<Sign1Parts> {
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
pub(crate) fn verify_sign1(cose: &[u8], keys: &BTreeMap<String, [u8; 32]>, max_bytes: usize, max_depth: usize) -> Option<Sign1> {
    if cose.len() > max_bytes || cose.first() != Some(&TAG_SIGN1) {
        return None;
    }
    let (protected_bytes, unprotected, payload, signature) = unpack(decode_canonical(&cose[1..], max_depth)?)?;
    let protected = decode_canonical(&protected_bytes, max_depth)?;
    let kid = kid_of(&protected)?;
    let public_raw = keys.get(&kid)?;
    let sig_input = sig_structure(&protected_bytes, payload.as_deref())?;
    if !crate::ed25519_verify(public_raw, &sig_input, &signature) {
        return None;
    }
    Some(Sign1 { protected, unprotected, payload, kid })
}
