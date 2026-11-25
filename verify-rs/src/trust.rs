// Apache-2.0 (public verifier repo)
//! Out-of-band trust anchors and proof checks, mirrored by `verify/trust.py`.
//! Producer-supplied flags never create a favorable externally grounded value.

use crate::jcs;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

pub(crate) const SOURCE_WEBHOOK_SIGNATURE_CONTEXT: &str = "evd/source-webhook-body-jcs/v1";
pub(crate) const MAX_SOURCE_PROOF_MATERIAL_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_SOURCE_PROOF_TOTAL_BYTES: usize = 8 * 1024 * 1024;
pub(crate) const TSA_POLICY_SCHEMA: &str = "evd/tsa-verification-policy/v1";
const TSA_LIFECYCLE_POLICY_SCHEMA: &str = "evd/tsa-verification-policy/v2";
const TSA_RENEWAL_POLICY_SCHEMA: &str = "evd/tsa-verification-policy/v3";
const TSA_REVOCATION_SCHEMA: &str = "evd/tsa-revocation-evidence/v1";
const TSA_RENEWAL_SCHEMA: &str = "evd/tsa-renewal-chain/v1";
const MAX_JSON_NUMBER_TOKEN_BYTES: usize = 128;

/// Every key category a derivation may appeal to; absence always renders weak.
pub(crate) const KEY_CATEGORIES: [&str; 12] = ["source_keys", "mac_keys", "evaluator_keys", "node_keys", "node_roots", "temporal_keys", "population_keys", "accountability_keys", "scitt_ts_keys", "log_keys", "recorder_keys", "tsa_roots"];

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

/// The public key this relying party named for `name`, or None.
pub(crate) fn key_for(trust: Option<&Value>, category: &str, name: Option<&str>) -> Option<Vec<u8>> {
    if !KEY_CATEGORIES.contains(&category) {
        return None;
    }
    let table = trust?.get(category)?.as_object()?;
    decode_material(table.get(name?))
}

/// Concatenated PEM roots for E2 time; malformed values can only render weak.
pub(crate) fn tsa_roots_pem(trust: Option<&Value>) -> Option<String> {
    let table = trust?.get("tsa_roots")?.as_object()?;
    let pems: Vec<&str> = table.values().filter_map(Value::as_str).filter(|s| !s.trim().is_empty()).collect();
    (!pems.is_empty()).then(|| pems.join("\n"))
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum TsaPolicy {
    Absent,
    EssCertIdV2,
    OfflineLifecycle,
    OfflineRenewal,
    Malformed,
}

pub(crate) fn tsa_policy(trust: Option<&Value>) -> TsaPolicy {
    let Some(policy) = trust.and_then(|v| v.get("tsa_policy")) else { return TsaPolicy::Absent };
    let Some(policy) = policy.as_object() else { return TsaPolicy::Malformed };
    let policy = Value::Object(policy.clone());
    if policy == serde_json::json!({"schema": TSA_POLICY_SCHEMA, "signing_certificate": "esscertid-v2-required"}) {
        TsaPolicy::EssCertIdV2
    } else if policy == serde_json::json!({"schema": TSA_LIFECYCLE_POLICY_SCHEMA, "signing_certificate": "esscertid-v2-required", "revocation": "offline-crl-or-ocsp-required"}) {
        TsaPolicy::OfflineLifecycle
    } else if policy == serde_json::json!({"schema": TSA_RENEWAL_POLICY_SCHEMA, "signing_certificate": "esscertid-v2-required", "revocation": "offline-crl-or-ocsp-required", "renewal": "archive-timestamp-chain-required"}) {
        TsaPolicy::OfflineRenewal
    } else {
        TsaPolicy::Malformed
    }
}

#[derive(Clone, Copy)]
pub(crate) enum TsaStatusKind {
    Crl,
    Ocsp,
}

fn status_record(value: &Value) -> Option<(TsaStatusKind, Vec<u8>)> {
    let record = value.as_object()?;
    let shape = (record.len(), record.get("schema")?.as_str()?);
    if shape != (3, TSA_REVOCATION_SCHEMA) {
        return None;
    }
    let kind = match record.get("type")?.as_str()? {
        "crl" => TsaStatusKind::Crl,
        "ocsp" => TsaStatusKind::Ocsp,
        _ => return None,
    };
    let raw = decode_b64(record.get("der_b64")?.as_str()?)?;
    (!raw.is_empty() && raw.len() <= 1024 * 1024).then_some((kind, raw))
}

pub(crate) fn tsa_revocation_record(trust: Option<&Value>, signer_der: &[u8]) -> Option<(TsaStatusKind, Vec<u8>)> {
    let table = trust?.get("tsa_revocation")?.as_object()?;
    if table.is_empty() || table.len() > 16 {
        return None;
    }
    let wanted = crate::hex(&Sha256::digest(signer_der));
    let mut selected = None;
    for (fingerprint, value) in table {
        if fingerprint.len() != 64 || fingerprint != &fingerprint.to_ascii_lowercase() || crate::scitt::hex_to_bytes(fingerprint).is_none() {
            return None;
        }
        let record = status_record(value)?;
        if fingerprint == &wanted {
            selected = Some(record);
        }
    }
    selected
}

fn renewal_item(value: &Value) -> Option<(Vec<u8>, String)> {
    let item = value.as_object().filter(|item| item.len() == 2)?;
    let token = item.get("token_der_b64").and_then(Value::as_str).and_then(decode_b64).filter(|raw| !raw.is_empty() && raw.len() <= 1024 * 1024)?;
    let chain = item.get("cert_chain_pem").and_then(Value::as_str).filter(|text| !text.is_empty() && text.len() <= 1024 * 1024)?;
    Some((token, chain.to_owned()))
}

fn renewal_record(value: &Value) -> Option<Vec<(Vec<u8>, String)>> {
    let record = value.as_object()?;
    if record.len() != 2 || record.get("schema")?.as_str()? != TSA_RENEWAL_SCHEMA {
        return None;
    }
    let values = record.get("renewals")?.as_array()?;
    if values.is_empty() || values.len() > 8 {
        return None;
    }
    let parsed: Vec<_> = values.iter().map(renewal_item).collect::<Option<_>>()?;
    let total = parsed.iter().try_fold(0usize, |n, (token, chain)| n.checked_add(token.len() + chain.len()))?;
    (total <= 8 * 1024 * 1024).then_some(parsed)
}

pub(crate) fn tsa_renewal_chain(trust: Option<&Value>, original_token: &[u8]) -> Option<Vec<(Vec<u8>, String)>> {
    let table = trust?.get("tsa_renewal")?.as_object()?;
    if table.is_empty() || table.len() > 16 {
        return None;
    }
    let wanted = crate::hex(&Sha256::digest(original_token));
    let mut selected = None;
    for (fingerprint, value) in table {
        let valid = fingerprint.len() == 64 && fingerprint == &fingerprint.to_ascii_lowercase() && crate::scitt::hex_to_bytes(fingerprint).is_some();
        let parsed = renewal_record(value)?;
        if !valid {
            return None;
        }
        if fingerprint == &wanted {
            selected = Some(parsed);
        }
    }
    selected
}

/// Domain-separated JCS bytes with signature members stripped.
pub(crate) fn signed_bytes(domain: &str, payload: &Value) -> Option<Vec<u8>> {
    let mut stripped = Map::new();
    for (k, v) in payload.as_object()? {
        if k != "signature" && !k.ends_with("_sig") {
            stripped.insert(k.clone(), v.clone());
        }
    }
    let stripped = Value::Object(stripped);
    let mut out = b"evd/v1/".to_vec();
    out.extend_from_slice(domain.as_bytes());
    out.push(0);
    out.extend_from_slice(&jcs::canonical_integer_checked(&stripped)?);
    Some(out)
}

/// Parse the signature and its domain-separated material once for both proofs.
fn signed_proof(payload: &Value, domain: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    payload.is_object().then_some(())?;
    Some((decode_material(payload.get("signature"))?, signed_bytes(domain, payload)?))
}

/// Verify under the named trusted key; missing or malformed inputs are false.
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

/// A verified shared-secret MAC proves possession only.
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
        formatter.write_str("bounded duplicate-free JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        if !(-jcs::MAX_SAFE_INTEGER..=jcs::MAX_SAFE_INTEGER).contains(&value) {
            return Err(E::custom("integer is outside the interoperable exact domain"));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        if value > jcs::MAX_SAFE_INTEGER as u64 {
            return Err(E::custom("integer is outside the interoperable exact domain"));
        }
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(value).map(Value::Number).ok_or_else(|| E::custom("JSON number is not finite"))
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

fn json_number_token_ok(token: &[u8]) -> bool {
    token.len() <= MAX_JSON_NUMBER_TOKEN_BYTES && (token.iter().any(|byte| matches!(byte, b'.' | b'E' | b'e')) || std::str::from_utf8(token.strip_prefix(b"-").unwrap_or(token)).ok().and_then(|value| value.parse::<u64>().ok()).is_some_and(|value| value <= jcs::MAX_SAFE_INTEGER as u64))
}

fn json_numbers_lexically_bounded(raw: &[u8]) -> bool {
    let (mut in_string, mut escaped, mut number_start) = (false, false, None);
    for (index, byte) in raw.iter().enumerate() {
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
        if let Some(start) = number_start {
            if matches!(*byte, b'+' | b'-' | b'.' | b'E' | b'e' | b'0'..=b'9') {
                continue;
            }
            if !json_number_token_ok(&raw[start..index]) {
                return false;
            }
            number_start = None;
        }
        match *byte {
            b'"' => in_string = true,
            b'-' | b'0'..=b'9' => number_start = Some(index),
            _ => {}
        }
    }
    !in_string && number_start.is_none_or(|start| json_number_token_ok(&raw[start..]))
}

pub(crate) fn strict_json(raw: &[u8]) -> Option<Value> {
    json_numbers_lexically_bounded(raw).then_some(())?;
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = StrictValue.deserialize(&mut deserializer).ok()?;
    deserializer.end().ok()?;
    (!crate::depth_exceeds(&value, jcs::MAX_DEPTH)).then_some(value)
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
    if material.is_empty() || material.len() > MAX_SOURCE_PROOF_MATERIAL_BYTES {
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
    if crate::depth_exceeds(&delivery, 16) {
        return None;
    }
    let envelope = delivery.as_object()?;
    source_envelope_closed(envelope, name).then_some(())?;
    let signature = envelope.get("signature")?.as_str()?.to_owned();
    let message = jcs::canonical_integer_checked(&envelope["body"])?;
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
