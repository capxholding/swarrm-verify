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
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub(crate) const SOURCE_WEBHOOK_SIGNATURE_CONTEXT: &str = "evd/source-webhook-body-jcs/v1";
pub(crate) const MAX_SOURCE_PROOF_MATERIAL_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_SOURCE_PROOF_TOTAL_BYTES: usize = 8 * 1024 * 1024;

/// Every key category a derivation may appeal to. A category absent from the
/// supplied context means this relying party named no root there, so every
/// dimension grounded in it renders weak — never a favourable default.
pub(crate) const KEY_CATEGORIES: [&str; 10] = ["source_keys", "mac_keys", "evaluator_keys", "node_keys", "node_roots", "temporal_keys", "population_keys", "accountability_keys", "scitt_ts_keys", "log_keys"];

fn decode_b64(s: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let raw = STANDARD.decode(s).ok()?;
    (STANDARD.encode(&raw) == s).then_some(raw)
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

struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("bounded integer-only JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, _value: f64) -> Result<Value, E> {
        Err(E::custom("floating-point source-proof material is forbidden"))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut out = Vec::new();
        while let Some(value) = sequence.next_element_seed(StrictValue)? {
            out.push(value);
        }
        Ok(Value::Array(out))
    }

    fn visit_map<A>(self, mut mapping: A) -> Result<Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut out = Map::new();
        while let Some(key) = mapping.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate source-proof material field"));
            }
            out.insert(key, mapping.next_value_seed(StrictValue)?);
        }
        Ok(Value::Object(out))
    }
}

fn source_material_depth_ok(raw: &[u8], maximum: usize) -> bool {
    let (mut depth, mut in_string, mut escaped) = (0usize, false, false);
    for byte in raw {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match *byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > maximum {
                    return false;
                }
            }
            b'}' | b']' => {
                let Some(next) = depth.checked_sub(1) else { return false };
                depth = next;
            }
            _ => {}
        }
    }
    !in_string && depth == 0
}

fn strict_json(raw: &[u8]) -> Option<Value> {
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictValue.deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    Some(value)
}

/// Verify the exact material accepted by SignedWebhookConnector: the disclosed
/// raw envelope is digest-bound, strict parsed, then its body is JCS encoded.
pub(crate) fn source_webhook_verified(trust: Option<&Value>, name: Option<&str>, algorithm_family: Option<&str>, payload: &Value) -> bool {
    let Some((signature, message)) = source_webhook_statement(name, payload) else { return false };
    match (payload.get("proof_type").and_then(Value::as_str), algorithm_family) {
        (Some("asymmetric_signature"), Some("ed25519")) => source_webhook_ed25519(trust, name, &signature, &message),
        (Some("mac"), Some("hmac-sha256")) => source_webhook_mac(trust, name, &signature, &message),
        _ => false,
    }
}

fn source_webhook_material(payload: &Value) -> Option<Vec<u8>> {
    if payload.get("signature_context").and_then(Value::as_str) != Some(SOURCE_WEBHOOK_SIGNATURE_CONTEXT) {
        return None;
    }
    let material = payload.get("material").and_then(Value::as_str).and_then(decode_b64)?;
    if material.is_empty() || material.len() > MAX_SOURCE_PROOF_MATERIAL_BYTES || !source_material_depth_ok(&material, 16) {
        return None;
    }
    if payload.get("material_digest").and_then(Value::as_str) != Some(crate::hex(&Sha256::digest(&material)).as_str()) {
        return None;
    }
    Some(material)
}

fn source_envelope_closed(envelope: &Map<String, Value>, name: Option<&str>) -> bool {
    envelope.len() == 3 && ["body", "kid", "signature"].iter().all(|key| envelope.contains_key(*key)) && envelope.get("body").is_some_and(Value::is_object) && envelope.get("kid").and_then(Value::as_str) == name
}

fn source_webhook_statement(name: Option<&str>, payload: &Value) -> Option<(String, Vec<u8>)> {
    let material = source_webhook_material(payload)?;
    let delivery = strict_json(&material)?;
    let envelope = delivery.as_object()?;
    source_envelope_closed(envelope, name).then_some(())?;
    let signature = envelope.get("signature")?.as_str()?.to_owned();
    let message = jcs::canonical_checked(&envelope["body"])?;
    Some((signature, message))
}

fn source_webhook_ed25519(trust: Option<&Value>, name: Option<&str>, signature: &str, message: &[u8]) -> bool {
    let Some(public) = key_for(trust, "source_keys", name) else { return false };
    let Ok(public): Result<[u8; 32], _> = public.try_into() else { return false };
    let Some(signature) = decode_b64(signature) else { return false };
    crate::ed25519_verify(&public, message, &signature)
}

fn source_webhook_mac(trust: Option<&Value>, name: Option<&str>, signature: &str, message: &[u8]) -> bool {
    let Some(secret) = key_for(trust, "mac_keys", name) else { return false };
    let Some(mac) = crate::scitt::hex_to_bytes(signature) else { return false };
    mac.len() == 32 && crate::hex(&mac) == signature && ct_eq(&hmac_sha256(&secret, message), &mac)
}
