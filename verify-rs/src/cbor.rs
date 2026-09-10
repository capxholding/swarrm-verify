// Apache-2.0 (public verifier repo)
//! Deterministic CBOR for the certificate profile (SPEC/certificate-v1.md §1).
//!
//! RFC 8949 §4.2.1 Core Deterministic Encoding over the RESTRICTED model:
//! null, bool, signed 64-bit integers, UTF-8 text, byte strings, arrays,
//! maps with TEXT keys only. Definite lengths, no tags, no floats, map keys
//! sorted by the bytewise-lexicographic order of their ENCODED bytes.
//!
//! The item heads are HAND-ENCODED: ciborium (owner-sanctioned codec O·1)
//! does not sort map keys and makes no emission-order promise, so the shared
//! emitter in `cbor_wire` owns determinism outright — this module pins it to
//! the certificate profile (text keys only, booleans admitted). ciborium is
//! used only to materialize `ciborium::Value` on decode, AFTER an iterative
//! structural pre-scan (explicit stack, no recursion) has enforced the
//! depth/size caps, so hostile bytes can never crash us (H5).
//! Fail-closed: every deviation is `None`/`Err` — never a panic.
//!
//! Mirrors core/cborcanon.py; the shared vectors in tests/golden/cbor/ pin
//! byte-identical output across both engines.

use ciborium::Value;

use crate::cbor_wire::{canonical_bytes, structural_scan, Profile};

/// Same nesting cap as MAX_CBOR_DEPTH in core/cborcanon.py and the JCS cap —
/// both engines must reject identically.
pub(crate) const MAX_DEPTH: i64 = 64;
/// Default byte cap: the complete offline pack budget (certificate-v1 §4.1).
/// Callers verifying a bare core pass the tighter 1 MiB cap explicitly.
pub(crate) const MAX_BYTES: usize = 16 * 1024 * 1024;
/// Bound aggregate materialization, not only nesting and encoded bytes.
pub(crate) const MAX_ITEMS: usize = 100_000;

/// The certificate profile's value model (SPEC/certificate-v1.md §1).
const CERT_PROFILE: Profile = Profile { int_keys: false, bools: true };

/// Canonical bytes for a `ciborium::Value` within the restricted model;
/// `None` on floats, tags, non-text or duplicate map keys, out-of-range
/// integers, or over-deep nesting. Never panics.
pub(crate) fn canonical_cbor(v: &Value) -> Option<Vec<u8>> {
    canonical_bytes(v, MAX_DEPTH, &CERT_PROFILE)
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
        serde_json::Value::Object(m) => Value::Map(m.iter().map(|(k, x)| Some((Value::Text(k.clone()), json_to_cbor(x, limit - 1)?))).collect::<Option<Vec<_>>>()?),
    })
}

/// Canonical bytes for a JSON-compatible structure (the bundle/verdict-input
/// shapes) — the same object always yields the same bytes as core/cborcanon.py.
pub(crate) fn canonical_from_json(v: &serde_json::Value) -> Option<Vec<u8>> {
    canonical_cbor(&json_to_cbor(v, MAX_DEPTH)?)
}

/// Decode canonical-profile bytes into a `ciborium::Value`, or `None`.
/// Never panics on hostile input. Accepts EXACTLY the bytes `canonical_cbor`
/// would emit for the result: the pre-scan rejects tags/floats/indefinite/
/// over-depth/trailing garbage before ciborium runs (bounded recursion), and
/// the re-encode compare rejects duplicate or unsorted keys, out-of-range
/// integers and non-minimal heads.
pub(crate) fn decode_cbor(data: &[u8], max_depth: usize, max_bytes: usize) -> Option<Value> {
    if data.len() > max_bytes || structural_scan(data, max_depth, MAX_ITEMS)? != data.len() {
        return None;
    }
    let value: Value = ciborium::de::from_reader(data).ok()?;
    (canonical_cbor(&value)? == data).then_some(value)
}
