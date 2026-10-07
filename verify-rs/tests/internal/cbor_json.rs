// Apache-2.0 (public verifier repo)
//! JSON → canonical-CBOR construction, for TESTS only.
//!
//! A verifier decodes CBOR; it never builds CBOR from JSON. These two helpers
//! exist so the codec gate and the certificate-binding test can construct
//! inputs from JSON vectors, so they live on the test side of the wall rather
//! than inside `src/` where they counted against the verifier union budget.
//! Behaviour is byte-identical to the code they were moved from:
//! the same object always yields the same bytes as `core/cborcanon.py`.

use crate::cbor::{canonical_cbor, MAX_DEPTH};
use ciborium::Value;

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
