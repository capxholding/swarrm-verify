// Apache-2.0 (public verifier repo)
//! Independently-supplied trust anchors — mirror of `verify/trust.py`.
//!
//! **A favourable verdict may never derive
//! from an input the subject supplies.** Every externally-grounded dimension
//! used to be computed from a producer boolean (`verified: true`,
//! `node_signed: true`, `attester_independent: true`), so a subject could award
//! itself ASYMMETRIC / INDEPENDENT / OBSERVED / CLOSED / PROVEN_* / REGISTERED
//! by asserting them. Same defect as a bundle carrying its own TSA chain.
//!
//! Two layers, both required:
//! 1. the anchors arrive **out of band** — `derive_vector_with_trust` takes the
//!    context as a separate argument, so the evidence document cannot supply
//!    it, and with `None` every such dimension renders its weak value;
//! 2. the proofs are **actually checked** — a signature over domain-separated
//!    JCS bytes, verified under a key the relying party named.

use crate::jcs;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Every key category a derivation may appeal to. A category absent from the
/// supplied context means this relying party named no root there, so every
/// dimension grounded in it renders weak — never a favourable default.
pub(crate) const KEY_CATEGORIES: [&str; 10] = ["source_keys", "mac_keys", "evaluator_keys", "node_keys", "node_roots", "temporal_keys", "population_keys", "accountability_keys", "scitt_ts_keys", "log_keys"];

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    STANDARD.decode(s).ok()
}

/// A key or signature given as hex or base64 (hex first, mirroring Python).
fn decode_material(v: Option<&Value>) -> Option<Vec<u8>> {
    let s = v?.as_str()?;
    if s.is_empty() {
        return None;
    }
    crate::scitt::hex_to_bytes(s).or_else(|| decode_b64(s))
}

/// The public key this relying party named for `name`, or None (the safe
/// answer: no anchor -> no favourable value).
pub(crate) fn key_for(trust: Option<&Value>, category: &str, name: Option<&str>) -> Option<Vec<u8>> {
    if !KEY_CATEGORIES.contains(&category) {
        return None;
    }
    let table = trust?.get(category)?.as_object()?;
    decode_material(table.get(name?))
}

/// Domain-separated JCS bytes — the exact material signed. Every
/// `signature`/`*_sig` field is stripped, so a signature is never part of what
/// it signs, and the domain stops a proof made for one purpose being replayed
/// as proof of another.
pub(crate) fn signed_bytes(domain: &str, payload: &Value) -> Option<Vec<u8>> {
    let mut stripped = Map::new();
    for (k, v) in payload.as_object()? {
        if k != "signature" && !k.ends_with("_sig") {
            stripped.insert(k.clone(), v.clone());
        }
    }
    let mut out = b"evd/v1/".to_vec();
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(&jcs::canonical_checked(&Value::Object(stripped))?);
    Some(out)
}

/// Parse the signature and its domain-separated material once for both proofs.
fn signed_proof(payload: &Value, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    payload.is_object().then_some(())?;
    Some((decode_material(payload.get("signature"))?, signed_bytes(domain, payload)?))
}

/// True iff `payload`'s signature verifies under the named trusted key. Total:
/// any missing anchor, missing signature or malformed input is false. This is
/// the ONLY route to a favourable externally-grounded value.
pub(crate) fn verified(trust: Option<&Value>, category: &str, name: Option<&str>, domain: &str, payload: &Value) -> bool {
    let Some(pub_bytes) = key_for(trust, category, name) else { return false };
    let Ok(pubkey): Result<[u8; 32], _> = pub_bytes.try_into() else { return false };
    let Some((sig, msg)) = signed_proof(payload, domain) else { return false };
    crate::ed25519_verify(&pubkey, &msg, &sig)
}

/// HMAC-SHA256, hand-rolled so no new crate enters the trust path (§0.2·3).
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A shared-secret MAC: possession by SOME holder, so the vocabulary caps it at
/// `SHARED_SECRET`. Verified anyway — an unverified MAC is evidence of nothing.
pub(crate) fn mac_verified(trust: Option<&Value>, name: Option<&str>, domain: &str, payload: &Value) -> bool {
    let Some(secret) = key_for(trust, "mac_keys", name) else { return false };
    let Some((mac, msg)) = signed_proof(payload, domain) else { return false };
    ct_eq(&hmac_sha256(&secret, &msg), &mac)
}
