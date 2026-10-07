// Apache-2.0 (public verifier repo)
//! Deterministic COSE_Sign1 CONSTRUCTION, for TESTS only.
//!
//! The shipped crate verifies COSE_Sign1; it holds no private key and signs
//! nothing. This builder exists so the canonical-byte gate and the SCITT
//! golden test can produce signed input, so it lives on the test side of the
//! wall rather than inside `src/`, where it was the crate's only Ed25519
//! signing primitive and counted against the verifier union budget.
//!
//! Byte-identical to the code it was moved from: it reuses `cose`'s own
//! `COSE_PROFILE`, `TAG_SIGN1` and `sig_structure` rather than restating them,
//! so the emitter under test cannot drift from the verifier's model.

use crate::cbor_wire::{canonical_bytes, write_value};
use crate::cose::{sig_structure, COSE_PROFILE, TAG_SIGN1};
use ciborium::Value;
use ed25519_dalek::{Signer, SigningKey};

const BUILD_DEPTH: i64 = 32;

/// Deterministic COSE_Sign1 bytes signed by the Ed25519 `seed` (alg -8).
pub(crate) fn build_sign1(protected: &Value, unprotected: &Value, payload: Option<&[u8]>, seed: &[u8; 32]) -> Option<Vec<u8>> {
    let protected_bytes = canonical_bytes(protected, BUILD_DEPTH, &COSE_PROFILE)?;
    let sig_input = sig_structure(&protected_bytes, payload)?;
    let signature = SigningKey::from_bytes(seed).sign(&sig_input).to_bytes().to_vec();
    let array = Value::Array(vec![Value::Bytes(protected_bytes), unprotected.clone(), payload.map_or(Value::Null, |b| Value::Bytes(b.to_vec())), Value::Bytes(signature)]);
    let mut out = vec![TAG_SIGN1];
    write_value(&array, &mut out, BUILD_DEPTH, &COSE_PROFILE).then_some(out)
}
