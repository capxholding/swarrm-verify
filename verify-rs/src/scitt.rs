// Apache-2.0 (public verifier repo)
//! SCITT receipt verification (scitt-action-profile-v1 §6) — verifier-DERIVED.
//!
//! The Rust twin of `verify/scitt.py`. `verify_scitt_receipt` runs the profile
//! §6 checks over an issuer Signed Statement (§2) and a TS Receipt (§4) and
//! returns `scitt_receipt_valid` as a single AND. The certificate verifier
//! calls it and OVERRIDES any producer-supplied flag, so a producer can NEVER
//! self-assert REGISTERED: a forged receipt, a stale checkpoint, a substituted
//! statement or a mismatched `certificate_id` each fail §6 → the flag is false.
//!
//! Fail-closed (H5): hostile bytes never panic — any deviation returns `false`.
//! Byte-identical to Python; the checks flow through `crate::cose`,
//! `crate::merkle` and the `crate::jcs` checkpoint hash the rest of the stack
//! already emits.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ciborium::Value;
use serde_json::{json, Value as Json};
use std::collections::BTreeMap;

const MAX_BYTES: usize = 65536; // §6.1: each COSE_Sign1 <= 64 KiB
const MAX_DEPTH: usize = 16; // §6.1: CBOR depth <= 16
const MAX_AUDIT_PATH: usize = 64; // scitt-v1.cddl caps trailer

const CHECKPOINT_SCHEMA: &str = "evd/checkpoint/v1";
const CHECKPOINT_TYPE: &str = "application/vnd.evd.checkpoint.v1+json";
const PACK_SCHEMA: &str = "evd/scitt-pack/v1";
const POLICY_SCHEMA: &str = "evd/registration-policy/v1";
const POLICY_PROFILE: &str = "scitt-action-profile-v1";
const STATEMENT_CTY: &str = "application/vnd.swarrm.action-certificate+cbor";
const SCOPE_DIGEST_CLAIM: &str = "evd_scope_digest";
const PACK_FIELDS: [&str; 7] = ["schema", "certificate_id", "signed_statement", "receipt", "checkpoint", "registration_policy", "ts_jwks"];
const PACK_OPTIONAL_FIELDS: [&str; 2] = ["anchor_record", "tst_record"];
const POLICY_FIELDS: [&str; 7] = ["schema", "policy_version", "ts_origin", "accepted_profiles", "max_statement_bytes", "ts_keys", "signature"];
const CHECKPOINT_FIELDS: [&str; 6] = ["schema", "origin", "tree_size", "root_hash", "ts", "prev_hash"];

fn object_fields<'a>(value: &'a Json, required: &[&str], optional: &[&str]) -> Option<&'a serde_json::Map<String, Json>> {
    let object = value.as_object()?;
    required.iter().all(|name| object.contains_key(*name)).then_some(())?;
    object.keys().all(|name| required.contains(&name.as_str()) || optional.contains(&name.as_str())).then_some(object)
}

fn strict_b64(value: &str) -> Option<Vec<u8>> {
    let raw = B64.decode(value).ok()?;
    (B64.encode(&raw) == value).then_some(raw)
}

fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = format!("DSSEv1 {} {} {} ", payload_type.len(), payload_type, payload.len()).into_bytes();
    out.extend_from_slice(payload);
    out
}

/// Hex string → bytes; None on non-ASCII, odd length, or a bad nibble. The one
/// hex decode for the whole verifier — the certificate layer's pack decode, the
/// trust anchors and the bundle layer's roots/proofs/nonce all read through it,
/// so no caller can drift into a laxer rule (H5: no panic on hostile input).
pub(crate) fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    // is_ascii first: byte-slicing a multi-byte char boundary would panic,
    // and hex is ASCII by definition anyway (H5: no panic on hostile input)
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok()).collect()
}

fn imap(v: &Value, key: i128) -> Option<&Value> {
    let Value::Map(m) = v else { return None };
    m.iter().find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key)).map(|(_, x)| x)
}

fn tmap<'a>(body: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(m) = body else { return None };
    m.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, x)| x)
}

fn btext<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    tmap(body, key).and_then(as_text)
}

fn as_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

fn as_int(v: &Value) -> Option<i128> {
    match v {
        Value::Integer(i) => Some(i128::from(*i)),
        _ => None,
    }
}

fn as_text(v: &Value) -> Option<&str> {
    match v {
        Value::Text(t) => Some(t),
        _ => None,
    }
}

fn map_len(v: &Value) -> Option<usize> {
    match v {
        Value::Map(m) => Some(m.len()),
        _ => None,
    }
}

fn hex32(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn statement_profile(stmt: &crate::cose::Sign1, cid: &[u8], certificate_id: &str) -> bool {
    if stmt.payload.as_deref() != Some(cid) || cid.len() != 32 || !hex32(certificate_id) {
        return false;
    }
    if map_len(&stmt.unprotected) != Some(0) || map_len(&stmt.protected) != Some(4) {
        return false;
    }
    if imap(&stmt.protected, 1).and_then(as_int) != Some(-8) || imap(&stmt.protected, 3).and_then(as_text) != Some(STATEMENT_CTY) {
        return false;
    }
    let Some(claims) = imap(&stmt.protected, 15) else { return false };
    let scope = tmap(claims, SCOPE_DIGEST_CLAIM).and_then(as_text);
    let expected_claims = if scope.is_some() { 3 } else { 2 };
    map_len(claims) == Some(expected_claims) && imap(claims, 1).and_then(as_text).is_some_and(|s| !s.is_empty()) && imap(claims, 2).and_then(as_text) == Some(certificate_id) && scope.is_none_or(hex32)
}

/// §4: the TS Receipt protected header is exactly `{1: -8, 4: <TS kid>, 395: 1}`,
/// where label `395` is the VDS and `395:1` = the `RFC9162_SHA256` structure.
fn receipt_profile(receipt: &crate::cose::Sign1) -> bool {
    map_len(&receipt.protected) == Some(3) && imap(&receipt.protected, 1).and_then(as_int) == Some(-8) && imap(&receipt.protected, 395).and_then(as_int) == Some(1) && receipt.payload.as_ref().is_some_and(|p| p.len() == 32)
}

/// §6.5: recompute the checkpoint body_hash from unprotected -2 exactly as
/// `core.checkpoint.Checkpoint.from_dict(...).body_hash()` → (body_hash hex, root).
///
/// Extra keys are now REFUSED rather than dropped. Rebuilding the body from six
/// known fields meant arbitrary unsigned content could ride inside a
/// "signed" checkpoint while the recomputed hash still matched, and Python's
/// `Checkpoint.from_dict` was corrected to reject such a body — leaving this as
/// the more permissive engine on the same bytes.
fn checkpoint_body(body: &Value) -> Option<(Json, &str, u64)> {
    // Exactly six members, all present and well-typed. Extracted from
    // `checkpoint` to keep that function inside the §0.2·3a complexity ceiling.
    if btext(body, "schema")? != CHECKPOINT_SCHEMA || map_len(body) != Some(6) {
        return None; // a member the signature does not cover is not "signed"
    }
    let root_hex = btext(body, "root_hash")?;
    let tree_size = as_uint(tmap(body, "tree_size")?)?;
    let obj = json!({
        "schema": CHECKPOINT_SCHEMA,
        "origin": btext(body, "origin")?,
        "tree_size": tree_size,
        "root_hash": root_hex,
        "ts": btext(body, "ts")?,
        "prev_hash": btext(body, "prev_hash")?,
    });
    Some((obj, root_hex, tree_size))
}

fn checkpoint(unprotected: &Value) -> Option<(Json, String, Vec<u8>, u64)> {
    let (obj, root_hex, tree_size) = checkpoint_body(imap(unprotected, -2)?)?;
    let canon = crate::jcs::canonical_checked(&obj)?;
    Some((obj, crate::hex(&crate::sha256(&canon)), hex_to_bytes(root_hex)?, tree_size))
}

fn checkpoint_json_body(body: &Json) -> bool {
    object_fields(body, &CHECKPOINT_FIELDS, &[]).is_some() && body.get("schema").and_then(Json::as_str) == Some(CHECKPOINT_SCHEMA) && body.get("origin").and_then(Json::as_str).is_some() && body.get("tree_size").and_then(Json::as_u64).is_some() && body.get("root_hash").and_then(Json::as_str).is_some() && body.get("ts").and_then(Json::as_str).is_some() && body.get("prev_hash").and_then(Json::as_str).is_some()
}

/// Verify the exact three-field SignedCheckpoint under locally-authorized TS
/// keys. The checkpoint body is closed before canonicalization, so no unsigned
/// member can ride beside the six fields the other verifier reconstructs.
pub(crate) fn verify_signed_checkpoint(checkpoint: &Json, keys: &BTreeMap<String, [u8; 32]>, expected_origin: Option<&str>) -> bool {
    if object_fields(checkpoint, &["body", "kid", "sig"], &[]).is_none() {
        return false;
    }
    let Some(body) = checkpoint.get("body").filter(|body| checkpoint_json_body(body)) else { return false };
    if expected_origin.is_some_and(|origin| body.get("origin").and_then(Json::as_str) != Some(origin)) {
        return false;
    }
    let Some(key) = checkpoint.get("kid").and_then(Json::as_str).and_then(|kid| keys.get(kid)) else { return false };
    let Some(signature) = checkpoint.get("sig").and_then(Json::as_str).and_then(strict_b64) else { return false };
    let Some(canonical) = crate::jcs::canonical_checked(body) else { return false };
    crate::ed25519_verify(key, &pae(CHECKPOINT_TYPE, &canonical), &signature)
}

fn policy_shape(policy: &Json, statement_bytes: usize) -> bool {
    let maximum = policy.get("max_statement_bytes").and_then(Json::as_u64);
    object_fields(policy, &POLICY_FIELDS, &[]).is_some() && policy.get("schema").and_then(Json::as_str) == Some(POLICY_SCHEMA) && policy.get("accepted_profiles") == Some(&json!([POLICY_PROFILE])) && maximum.is_some_and(|limit| statement_bytes as u64 <= limit && limit <= MAX_BYTES as u64) && policy.get("policy_version").and_then(Json::as_str).is_some_and(|value| !value.is_empty()) && policy.get("ts_origin").and_then(Json::as_str).is_some_and(|value| !value.is_empty())
}

fn policy_signature_valid(policy: &Json, trusted_roots: &BTreeMap<String, [u8; 32]>) -> bool {
    let Some(signature) = policy.get("signature").and_then(Json::as_str).and_then(strict_b64) else { return false };
    let Some(mut unsigned) = policy.as_object().cloned() else { return false };
    unsigned.remove("signature");
    let Some(canonical) = crate::jcs::canonical_checked(&Json::Object(unsigned)) else { return false };
    trusted_roots.values().any(|root| crate::ed25519_verify(root, &canonical, &signature))
}

fn policy_key(entry: &Json) -> Option<(&Json, String, [u8; 32])> {
    object_fields(entry, &["kid", "jwk"], &[])?;
    let jwk = entry.get("jwk")?;
    object_fields(jwk, &["alg", "crv", "kid", "kty", "use", "x"], &[])?;
    let (raw, derived) = crate::key_from_jwk(jwk)?;
    (entry.get("kid").and_then(Json::as_str) == Some(&derived) && jwk.get("kid").and_then(Json::as_str) == Some(&derived)).then_some((jwk, derived, raw))
}

fn carried_ts_jwks(pack: &Json, expected: usize) -> Option<&Vec<Json>> {
    let jwks = pack.get("ts_jwks")?;
    let carried = object_fields(jwks, &["keys"], &[])?.get("keys")?.as_array()?;
    (carried.len() == expected).then_some(carried)
}

fn insert_policy_key(keys: &mut BTreeMap<String, [u8; 32]>, entry: &Json, carried_jwk: &Json) -> Option<()> {
    let (jwk, kid, raw) = policy_key(entry)?;
    (carried_jwk == jwk && keys.insert(kid, raw).is_none()).then_some(())
}

fn policy_ts_keys(policy: &Json, pack: &Json) -> Option<BTreeMap<String, [u8; 32]>> {
    let entries = policy.get("ts_keys")?.as_array()?;
    (1..=64).contains(&entries.len()).then_some(())?;
    let carried = carried_ts_jwks(pack, entries.len())?;
    let mut keys = BTreeMap::new();
    for (entry, carried_jwk) in entries.iter().zip(carried) {
        insert_policy_key(&mut keys, entry, carried_jwk)?;
    }
    Some(keys)
}

/// Validate every signed piece of a carried SCITT pack and return only the TS
/// keys authorized by a policy signed by an out-of-band local root. Pack JWKs
/// are evidence to compare with that policy, never roots of trust themselves.
pub(crate) fn verified_scitt_pack_keys(pack: &Json, trusted_roots: &BTreeMap<String, [u8; 32]>, signed_statement: &[u8]) -> Option<BTreeMap<String, [u8; 32]>> {
    let object = object_fields(pack, &PACK_FIELDS, &PACK_OPTIONAL_FIELDS)?;
    (object.get("schema").and_then(Json::as_str) == Some(PACK_SCHEMA)).then_some(())?;
    let policy = object.get("registration_policy")?;
    (policy_shape(policy, signed_statement.len()) && policy_signature_valid(policy, trusted_roots)).then_some(())?;
    let keys = policy_ts_keys(policy, pack)?;
    let origin = policy.get("ts_origin")?.as_str()?;
    verify_signed_checkpoint(object.get("checkpoint")?, &keys, Some(origin)).then_some(keys)
}

/// §6.6: the RFC 6962 inclusion proof at unprotected 396 → {-1: [size, idx, path]}.
fn inclusion(unprotected: &Value) -> Option<(u64, u64, Vec<[u8; 32]>)> {
    let triple = imap(imap(unprotected, 396)?, -1)?;
    let Value::Array(a) = triple else { return None };
    if a.len() != 3 {
        return None;
    }
    let (tree_size, leaf_index) = (as_uint(&a[0])?, as_uint(&a[1])?);
    let Value::Array(raw) = &a[2] else { return None };
    if raw.len() > MAX_AUDIT_PATH {
        return None;
    }
    let mut path = Vec::with_capacity(raw.len());
    for h in raw {
        let Value::Bytes(b) = h else { return None };
        path.push(<[u8; 32]>::try_from(b.as_slice()).ok()?);
    }
    Some((tree_size, leaf_index, path))
}

fn receipt_checkpoint(rcpt: &crate::cose::Sign1, ts_keys: &BTreeMap<String, [u8; 32]>, expected_checkpoint: Option<&Json>) -> Option<(Vec<u8>, u64)> {
    let (inner, body_hash, root, tree_size) = checkpoint(&rcpt.unprotected)?;
    (rcpt.payload.as_deref().map(crate::hex) == Some(body_hash)).then_some(())?;
    if let Some(outer) = expected_checkpoint {
        (outer.get("body") == Some(&inner) && verify_signed_checkpoint(outer, ts_keys, None)).then_some(())?;
    }
    Some((root, tree_size))
}

fn verify_scitt_receipt_inner(signed_statement: &[u8], receipt: &[u8], ts_keys: &BTreeMap<String, [u8; 32]>, issuer_keys: &BTreeMap<String, [u8; 32]>, certificate_id: &str, expected_checkpoint: Option<&Json>) -> bool {
    if !hex32(certificate_id) {
        return false;
    }
    let Some(cid) = hex_to_bytes(certificate_id) else { return false };
    // §6.2 issuer signature; the payload is exactly the 32-byte certificate_id
    let Some(stmt) = crate::cose::verify_sign1(signed_statement, issuer_keys, MAX_BYTES, MAX_DEPTH) else { return false };
    if !statement_profile(&stmt, &cid, certificate_id) {
        return false;
    }
    // §6.3 statement digest → §6.4 TS signature over the receipt
    let statement_digest = crate::sha256(signed_statement);
    let Some(rcpt) = crate::cose::verify_sign1(receipt, ts_keys, MAX_BYTES, MAX_DEPTH) else { return false };
    if !receipt_profile(&rcpt) {
        return false;
    }
    // §6.5 recompute checkpoint body_hash; it must equal the receipt payload
    let Some((root, checkpoint_size)) = receipt_checkpoint(&rcpt, ts_keys, expected_checkpoint) else { return false };
    // §6.6 RFC 9162 inclusion of statement_digest to checkpoint.root. This
    // engine's `merkle::verify_inclusion` takes the ALREADY-HASHED RFC 6962
    // leaf (SHA-256(0x00 ‖ statement_digest)), where Python's takes the leaf
    // data and hashes it — compute the leaf hash here so both agree.
    let Some((tree_size, leaf_index, path)) = inclusion(&rcpt.unprotected) else { return false };
    if tree_size != checkpoint_size || leaf_index >= tree_size {
        return false;
    }
    let leaf = crate::sha256(&[&[0x00u8], &statement_digest[..]].concat());
    crate::merkle::verify_inclusion(&leaf, leaf_index, tree_size, &path, &root)
}

/// Derive `scitt_receipt_valid` for a raw statement+receipt pair (§6). This
/// intentionally keeps the historical raw API: callers with no pack metadata
/// still test the COSE and inclusion proof, while the certificate path adds the
/// signed-policy and exact outer-checkpoint requirements below.
#[allow(dead_code)] // raw verifier is exercised directly by the shared golden crate
pub(crate) fn verify_scitt_receipt(signed_statement: &[u8], receipt: &[u8], ts_keys: &BTreeMap<String, [u8; 32]>, issuer_keys: &BTreeMap<String, [u8; 32]>, certificate_id: &str) -> bool {
    verify_scitt_receipt_inner(signed_statement, receipt, ts_keys, issuer_keys, certificate_id, None)
}

pub(crate) fn verify_scitt_receipt_with_checkpoint(signed_statement: &[u8], receipt: &[u8], ts_keys: &BTreeMap<String, [u8; 32]>, issuer_keys: &BTreeMap<String, [u8; 32]>, certificate_id: &str, expected_checkpoint: &Json) -> bool {
    verify_scitt_receipt_inner(signed_statement, receipt, ts_keys, issuer_keys, certificate_id, Some(expected_checkpoint))
}
