// Apache-2.0 (public verifier repo)
//! Independent, offline Rust verifier for evd/bundle/v1; parity is established
//! by the shared golden suite, not shared implementation code.

pub mod action;
pub mod b28;
#[allow(dead_code)] // Test-only canonical JSON adapter.
mod cbor;
mod cbor_wire;
pub mod certificate; // `verify_certificate_cbor` also serves the WASM export.
#[allow(dead_code)] // COSE adapter used by SCITT and golden tests.
mod cose;
mod dispute;
pub(crate) mod jcs;
mod merkle;
mod scitt;
pub mod trust; // independently-supplied anchors: a subject may not supply its own
pub mod tsa;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use scitt::hex_to_bytes;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const RECEIPT_TYPE: &str = "application/vnd.evd.receipt.v1+json";
const RECEIPT_SCHEMA: &str = "evd/receipt/v1";
const RECEIPT_MAX_PARENTS: usize = 32;
const CHECKPOINT_TYPE: &str = "application/vnd.evd.checkpoint.v1+json";
const EXPORT_MANIFEST_TYPE: &str = "application/vnd.evd.export-manifest.v1+json";
const DISCLOSURE_SCHEMA: &str = "evd/disclosure/v1";
const SPARSE_CHECKPOINT_CHAIN_PROFILE: &str = "evd/checkpoint-chain/sparse-proof-v1";
const DOMAIN_PREFIX: &str = "evd/v1/";

// Resource caps match verify/verifier.py and precede cryptographic work.
#[allow(dead_code)] // enforced at byte entry points (verify_bundle_json/wasm)
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;
const MAX_INCLUSION_PROOF_LEN: usize = 64;
const MAX_CHECKPOINT_CHAIN_LEN: usize = 100_000;
const MAX_SIGNATURES_PER_ENVELOPE: usize = 9;
const MAX_ATTESTATION_RECORDS: usize = 256;

// Maximum receipt skew after its first signed covering checkpoint.
const RECEIPT_CHECKPOINT_SKEW_S: i64 = 300;

pub(crate) fn depth_exceeds(v: &Value, limit: i64) -> bool {
    // Bounded recursion exits at the first over-depth branch.
    if limit < 0 {
        return true;
    }
    match v {
        Value::Array(a) => a.iter().any(|x| depth_exceeds(x, limit - 1)),
        Value::Object(m) => m.values().any(|x| depth_exceeds(x, limit - 1)),
        _ => false,
    }
}

fn entry_within_caps(e: &Value) -> bool {
    if let Some(proof) = e.get("inclusion_proof").and_then(|v| v.as_array()) {
        if proof.len() > MAX_INCLUSION_PROOF_LEN {
            return false;
        }
    }
    let sigs = e.get("envelope").and_then(|v| v.get("signatures")).and_then(|v| v.as_array());
    if let Some(sigs) = sigs {
        if sigs.len() > MAX_SIGNATURES_PER_ENVELOPE {
            return false;
        }
    }
    true
}

/// Apply Python-parity resource caps before cryptographic work.
fn within_caps(bundle: &Value) -> bool {
    if let Some(entries) = bundle.get("entries").and_then(|v| v.as_array()) {
        if entries.len() > MAX_ENTRIES {
            return false;
        }
        if !entries.iter().all(entry_within_caps) {
            return false;
        }
    }
    if let Some(chain) = bundle.get("checkpoint_chain").and_then(|v| v.as_array()) {
        if chain.len() > MAX_CHECKPOINT_CHAIN_LEN {
            return false;
        }
    }
    jcs::numbers_within_profile(bundle)
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"DSSEv1 ");
    m.extend_from_slice(payload_type.len().to_string().as_bytes());
    m.push(b' ');
    m.extend_from_slice(payload_type.as_bytes());
    m.push(b' ');
    m.extend_from_slice(payload.len().to_string().as_bytes());
    m.push(b' ');
    m.extend_from_slice(payload);
    m
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.len() % 4 == 1 || !s.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')) {
        return None;
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).ok()
}

fn jwk_raw_key(jwk: &Value) -> Option<[u8; 32]> {
    if jwk.get("kty")?.as_str()? != "OKP" || jwk.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    let raw = b64url_decode(jwk.get("x")?.as_str()?)?;
    if raw.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    Some(k)
}

/// Extract raw Ed25519 public key from a JWK, validating the kid binding.
pub(crate) fn key_from_jwk(jwk: &Value) -> Option<([u8; 32], String)> {
    let k = jwk_raw_key(jwk)?;
    // kid = base64url(sha256(raw))[:16]
    let full = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(&k));
    let kid = full.chars().take(16).collect::<String>();
    // SPEC/bundle-v1.md §3.1 rejects aliases and type-confused carried kids.
    match jwk.get("kid") {
        None | Some(Value::Null) => {}
        Some(Value::String(claimed)) if *claimed == kid => {}
        Some(_) => return None,
    }
    Some((k, kid))
}

pub(crate) fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else { return false };
    if sig.len() != 64 {
        return false;
    }
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    vk.verify(msg, &Signature::from_bytes(&s)).is_ok()
}

fn envelope_message(env: &Value) -> Option<Vec<u8>> {
    Some(pae(env.get("payloadType")?.as_str()?, &payload_of(env)?))
}

/// Closed signature fields; absent alg retains the historical EdDSA meaning.
fn signature_valid(sig: &Value, message: &[u8], pubkey: &[u8; 32]) -> bool {
    let Some(o) = sig.as_object() else { return false };
    o.contains_key("keyid") && o.iter().all(|(n, v)| matches!(n.as_str(), "keyid" | "sig" | "alg") && v.is_string()) && o.get("alg").is_none_or(|v| v.as_str() == Some("EdDSA")) && sig.get("sig").and_then(Value::as_str).and_then(|raw| B64.decode(raw).ok()).is_some_and(|raw| ed25519_verify(pubkey, message, &raw))
}

pub(crate) fn env_signed_by(env: &Value, kid: &str, pubkey: &[u8; 32]) -> bool {
    let Some(message) = envelope_message(env) else { return false };
    env.get("signatures").and_then(Value::as_array).is_some_and(|sigs| sigs.iter().any(|sig| sig.get("keyid").and_then(Value::as_str) == Some(kid) && signature_valid(sig, &message, pubkey)))
}

fn payload_of(env: &Value) -> Option<Vec<u8>> {
    B64.decode(env.get("payload")?.as_str()?).ok()
}

pub(crate) fn receipt_hash_hex(env: &Value) -> Option<String> {
    // receipt_hash = sha256 of the decoded DSSE payload bytes (receipt-v1)
    Some(hex(&sha256(&payload_of(env)?)))
}

pub(crate) fn body_of(env: &Value) -> Option<Value> {
    let body = canonical_body(&payload_of(env)?)?;
    receipt_body_valid(&body, None).then_some(body)
}

fn canonical_body(raw: &[u8]) -> Option<Value> {
    let mut body = serde_json::from_slice(raw).ok()?;
    jcs::promote_jcs_integer_lexemes(&mut body).then_some(())?;
    (jcs::canonical_checked(&body)?.as_slice() == raw).then_some(body)
}

fn namespaced_action(value: &str) -> bool {
    let mut parts = value.split(['.', '_', '-']);
    parts.clone().count() > 1 && parts.all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()))
}

fn lower_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn safe_identity_text(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn disclosure_text(value: &str) -> bool {
    !value.is_empty() && value.chars().all(|c| !matches!(c as u32, 0..=0x1f | 0x7f..=0x9f))
}

fn receipt_body_valid(body: &Value, expected_tenant: Option<&str>) -> bool {
    const REQUIRED: [&str; 11] = ["schema", "tenant_id", "agent_id", "seq", "action_type", "commitments", "context", "parents", "ts_client", "ts_server", "idempotency_key"];
    let Some(object) = body.as_object() else { return false };
    let optional = ["alg", "session_id", "session_inferred"];
    if REQUIRED.iter().any(|field| !object.contains_key(*field)) || object.keys().any(|field| !REQUIRED.contains(&field.as_str()) && !optional.contains(&field.as_str())) {
        return false;
    }
    let text = |field| body.get(field).and_then(Value::as_str).filter(|value| safe_identity_text(value));
    let (Some(tenant), Some(_agent), Some(action), Some(_idem)) = (text("tenant_id"), text("agent_id"), text("action_type"), text("idempotency_key")) else { return false };
    if text("schema") != Some(RECEIPT_SCHEMA) || expected_tenant.is_some_and(|expected| tenant != expected) || !namespaced_action(action) || body.get("seq").and_then(Value::as_u64).is_none_or(|seq| seq == 0 || seq > jcs::MAX_SAFE_INTEGER as u64) {
        return false;
    }
    let commitments = body.get("commitments").and_then(Value::as_object).is_some_and(|items| items.iter().all(|(name, value)| !name.is_empty() && value.as_str().is_some_and(lower_sha256)));
    let parents = body.get("parents").and_then(Value::as_array).is_some_and(|items| {
        let values: Option<Vec<&str>> = items.iter().map(Value::as_str).collect();
        values.is_some_and(|values| values.len() <= RECEIPT_MAX_PARENTS && values.iter().all(|digest| lower_sha256(digest)) && values.iter().collect::<BTreeSet<_>>().len() == values.len())
    });
    let session = match (body.get("session_id"), body.get("session_inferred")) {
        (None, None) => true,
        (Some(id), Some(inferred)) => id.as_str().is_some_and(safe_identity_text) && inferred.is_boolean(),
        _ => false,
    };
    commitments && body.get("context").is_some_and(Value::is_object) && parents && body.get("ts_client").and_then(Value::as_str).is_some_and(canonical_utc) && body.get("ts_server").and_then(Value::as_str).is_some_and(canonical_utc) && session && body.get("alg").is_none_or(|alg| alg.as_str() == Some("EdDSA"))
}

fn tenant_from_origin(origin: &str) -> Option<&str> {
    safe_identity_text(origin).then(|| origin.rsplit('/').next()).flatten().filter(|tenant| !tenant.is_empty())
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0, |n, c| c.is_ascii_digit().then(|| n * 10 + u32::from(*c - b'0')))
}

pub(crate) fn canonical_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if !(b.len() == 20 || (22..=27).contains(&b.len())) || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || *b.last().unwrap() != b'Z' || (b.len() > 20 && (b[19] != b'.' || decimal(&b[20..b.len() - 1]).is_none())) {
        return false;
    }
    let (Some(y), Some(m), Some(d), Some(h), Some(n), Some(sec)) = (decimal(&b[..4]), decimal(&b[5..7]), decimal(&b[8..10]), decimal(&b[11..13]), decimal(&b[14..16]), decimal(&b[17..19])) else { return false };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [0, 31, 28 + u32::from(leap), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    y > 0 && (1..=12).contains(&m) && d > 0 && d <= days[m as usize] && h < 24 && n < 60 && sec < 60
}

/// Canonical UTC to epoch microseconds for arithmetic checkpoint comparisons.
fn utc_epoch_micros(ts: &str) -> Option<i64> {
    if !canonical_utc(ts) {
        return None;
    }
    let num = |a: usize, z: usize| ts[a..z].parse::<i64>().ok();
    let (y, m, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, s) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    let micros = if ts.len() > 20 { format!("{:0<6}", &ts[20..ts.len() - 1]).parse::<i64>().ok()? } else { 0 };
    // days-from-civil (Hinnant): canonical_utc validated the calendar (y >= 1),
    // so era arithmetic never sees a negative year.
    let years = if m <= 2 { y - 1 } else { y };
    let era = years / 400;
    let yoe = years - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86_400 + h * 3_600 + mi * 60 + s) * 1_000_000 + micros)
}

fn forbidden_managed_edge_cosign(body: &Value, env: &Value) -> bool {
    let multi = env.get("signatures").and_then(Value::as_array).is_some_and(|s| s.len() > 1);
    let agent = body.get("agent_id").and_then(Value::as_str).unwrap_or("");
    let action = body.get("action_type").and_then(Value::as_str).unwrap_or("");
    multi && (agent.starts_with('_') || ["evd.key.", "authority.", "source.", "action.", "lineage.", "node.", "evd.finding.", "evd.gap.", "evd.coverage.", "registration."].iter().any(|prefix| action.starts_with(prefix)))
}

struct KeyState {
    introduced: (u64, i64),
    revoked_at: Option<(u64, String)>,
    non_issuer: bool,
    recorder: bool,
    /// Created with the constrained SCITT-issuer role; rotation never transfers it.
    scitt: bool,
}

/// The trust root of the key-log replay: all keys and their immutable state.
#[derive(Default)]
pub(crate) struct KeyLog {
    pub(crate) keys: BTreeMap<String, [u8; 32]>,
    state: BTreeMap<String, KeyState>,
    pub(crate) ok: bool,
}

#[derive(Default)]
struct BundleFacts {
    ok: bool,
    complete: Option<bool>,
    recorder_attested: Vec<u64>,
    trusted_tst_checkpoints: Vec<String>,
    chain_sizes: BTreeMap<String, u64>,
    /// Elided intervals no continuity assertion covers. Absence of assertions never gates; a hole in a cover that WAS asserted is a detected discontinuity, and the Rust engine must render it identically to the Python one.
    continuity_gaps: usize,
    continuity_present: bool,
    continuity_ok: bool,
    /// Mirror of `BundleReport.origin_attested`, settled only for a verified bundle.
    origin_attested: Option<bool>,
}

fn collect_key_entries(entries: &[Value]) -> Vec<(u64, &Value, Value)> {
    // collect key entries (agent_id=_system, action evd.key.*) with leaf index
    let mut key_entries: Vec<(u64, &Value, Value)> = Vec::new();
    for e in entries {
        if let Some(body) = body_of(&e["envelope"]) {
            let is_sys = body.get("agent_id").and_then(|v| v.as_str()) == Some("_system");
            let is_key = body.get("action_type").and_then(|v| v.as_str()).map(|a| a.starts_with("evd.key.")).unwrap_or(false);
            if is_sys && is_key {
                let idx = e.get("leaf_index").and_then(|v| v.as_u64()).unwrap_or(0);
                key_entries.push((idx, &e["envelope"], body));
            }
        }
    }
    key_entries.sort_by_key(|t| t.0);
    key_entries
}

fn key_entries_well_formed(key_entries: &[(u64, &Value, Value)]) -> bool {
    if key_entries.is_empty() {
        return false;
    }
    if key_entries[0].0 != 0 || key_entries[0].2.get("action_type").and_then(|v| v.as_str()) != Some("evd.key.created") {
        return false;
    }
    // dense _system sequence
    let seqs: Vec<i64> = key_entries.iter().map(|t| t.2.get("seq").and_then(|v| v.as_i64()).unwrap_or(-1)).collect();
    for (i, s) in seqs.iter().enumerate() {
        if *s != (i as i64) + 1 {
            return false;
        }
    }
    true
}

pub(crate) fn key_active(kl: &KeyLog, kid: &str, at: &str, observed_size: u64) -> bool {
    let Some(state) = kl.state.get(kid) else { return false };
    let Some(at) = utc_epoch_micros(at) else { return false };
    state.introduced.0 < observed_size && state.introduced.1 <= at && state.revoked_at.as_ref().is_none_or(|(leaf, ts)| observed_size <= *leaf && utc_epoch_micros(ts).is_some_and(|revoked| at <= revoked))
}

/// A valid signature by a key active at ts, optionally restricted to issuers.
fn signed_by_active_key(env: &Value, kl: &KeyLog, ts: &str, observed_size: u64, issuer_only: bool) -> bool {
    env.get("signatures").and_then(Value::as_array).is_some_and(|ss| {
        ss.iter().any(|s| {
            let kid = s.get("keyid").and_then(Value::as_str).unwrap_or("");
            (!issuer_only || !kl.state.get(kid).is_some_and(|state| state.non_issuer)) && key_active(kl, kid, ts, observed_size) && env_signed_by(env, kid, &kl.keys[kid])
        })
    })
}

fn key_role_ok(pos: usize, action: &str, ctx: &Value) -> bool {
    match ctx.get("role") {
        None | Some(Value::Null) => true,
        Some(Value::String(role)) => pos > 0 && action == "evd.key.created" && matches!(role.as_str(), "recorder" | "scitt-issuer"),
        _ => false,
    }
}

#[allow(clippy::too_many_arguments, reason = "one fully parsed key-log transition")]
fn apply_key_created(kl: &mut KeyLog, pos: usize, leaf: u64, env: &Value, ctx: &Value, ts: &str, effective: i64, kid: String, material: [u8; 32]) -> bool {
    let role = ctx.get("role").and_then(Value::as_str);
    if kl.keys.contains_key(&kid) {
        return false;
    }
    let issuer_sponsored = if pos == 0 {
        if !env_signed_by(env, &kid, &material) {
            return false;
        }
        true
    } else {
        // sponsored: some active key signed it
        if !signed_by_active_key(env, kl, ts, leaf, false) {
            return false;
        }
        signed_by_active_key(env, kl, ts, leaf, true)
    };
    if role.is_some() && !issuer_sponsored {
        return false;
    }
    kl.keys.insert(kid.clone(), material);
    kl.state.insert(kid, KeyState { introduced: (leaf, effective), revoked_at: None, non_issuer: role.is_some() || !issuer_sponsored, recorder: role == Some("recorder"), scitt: role == Some("scitt-issuer") });
    true
}

#[allow(clippy::too_many_arguments, reason = "one fully parsed key-log transition")]
fn apply_key_rotated(kl: &mut KeyLog, leaf: u64, env: &Value, ctx: &Value, jwk: &Value, ts: &str, effective: i64, kid: String, material: [u8; 32]) -> bool {
    let prev_kid = ctx.get("prev_kid").and_then(|v| v.as_str()).unwrap_or("");
    let continuity = ctx.get("continuity_sig").and_then(|v| v.as_str());
    if prev_kid.is_empty() || continuity.is_none() || kl.keys.contains_key(&kid) {
        return false;
    }
    if !key_active(kl, prev_kid, ts, leaf) {
        return false;
    }
    if !env_signed_by(env, prev_kid, &kl.keys[prev_kid]) {
        return false;
    }
    // continuity: prev key signed canonical(jwk)
    // over-deep / non-integer jwk cannot verify
    let Some(jwk_canon) = jcs::canonical_checked(jwk) else {
        return false;
    };
    let Ok(cont) = B64.decode(continuity.unwrap()) else {
        return false;
    };
    if !ed25519_verify(&kl.keys[prev_kid], &jwk_canon, &cont) {
        return false;
    }
    let non_issuer = kl.state.get(prev_kid).is_some_and(|state| state.non_issuer);
    kl.keys.insert(kid.clone(), material);
    kl.state.insert(kid, KeyState { introduced: (leaf, effective), revoked_at: None, non_issuer, recorder: false, scitt: false });
    true
}

fn apply_key_revoked(kl: &mut KeyLog, leaf: u64, env: &Value, ctx: &Value, ts: &str, kid: String) -> bool {
    if !kl.keys.contains_key(&kid) || kl.state.get(&kid).is_none_or(|state| state.revoked_at.is_some()) {
        return false;
    }
    if !signed_by_active_key(env, kl, ts, leaf, false) {
        return false;
    }
    let eff = ctx.get("effective_ts").and_then(|v| v.as_str()).unwrap_or("");
    if !canonical_utc(eff) {
        return false;
    }
    kl.state.get_mut(&kid).unwrap().revoked_at = Some((leaf, eff.to_string()));
    true
}

pub(crate) fn replay_key_log(entries: &[Value]) -> KeyLog {
    let mut kl = KeyLog::default();
    let key_entries = collect_key_entries(entries);
    if !key_entries_well_formed(&key_entries) {
        return kl;
    }

    for (pos, (leaf, env, body)) in key_entries.iter().enumerate() {
        let action = body.get("action_type").and_then(|v| v.as_str()).unwrap_or("");
        let ctx = body.get("context").cloned().unwrap_or(Value::Null);
        if !key_role_ok(pos, action, &ctx) {
            return kl;
        }
        let jwk = ctx.get("jwk").cloned().unwrap_or(Value::Null);
        let ts = body.get("ts_server").and_then(|v| v.as_str()).unwrap_or("");
        let Some(effective) = ctx.get("effective_ts").and_then(Value::as_str).and_then(utc_epoch_micros) else { return kl };
        if !canonical_utc(ts) {
            return kl;
        }
        let Some((material, kid)) = key_from_jwk(&jwk) else { return kl };
        let applied = match action {
            "evd.key.created" => apply_key_created(&mut kl, pos, *leaf, env, &ctx, ts, effective, kid, material),
            "evd.key.rotated" => apply_key_rotated(&mut kl, *leaf, env, &ctx, &jwk, ts, effective, kid, material),
            "evd.key.revoked" => apply_key_revoked(&mut kl, *leaf, env, &ctx, ts, kid),
            _ => return kl,
        };
        if !applied {
            return kl;
        }
    }
    kl.ok = true;
    kl
}

pub(crate) fn checkpoint_body_hash(cp: &Value) -> Option<String> {
    let body = cp.get("body")?;
    Some(hex(&sha256(&jcs::canonical_checked(body)?)))
}

/// Count asserted continuity holes in a sparse chain; dense chains elide nothing.
pub(crate) fn continuity_gaps(chain: &[Value], assertions: &[Value]) -> usize {
    let covered: Vec<(String, String)> = assertions
        .iter()
        .filter(|a| continuity_self_consistent(a))
        .filter_map(|a| {
            let b = a.get("body")?;
            Some((b.get("from_hash")?.as_str()?.to_string(), b.get("to_hash")?.as_str()?.to_string()))
        })
        .collect();
    chain
        .windows(2)
        .filter(|pair| {
            let (Some(first), Some(second)) = (checkpoint_body_hash(&pair[0]), checkpoint_body_hash(&pair[1])) else { return true };
            if pair[1].get("body").and_then(|b| b.get("prev_hash")).and_then(Value::as_str) == Some(first.as_str()) {
                return false;
            }
            !covered.iter().any(|(f, t)| *f == first && *t == second)
        })
        .count()
}

/// Python-parity continuity result: (present, readable, uncovered gaps).
fn assess_continuity(bundle: &Value, chain: &[Value], kl: &KeyLog) -> (bool, bool, usize) {
    let Some(raw) = bundle.get("continuity").filter(|v| !v.is_null()) else { return (false, true, continuity_gaps(chain, &[])) };
    let Some(items) = raw.as_array() else { return (false, false, 0) };
    if !items.iter().all(|item| continuity_admissible(item, kl, bundle.get("origin")) && continuity_authority(item, bundle, chain, kl)) {
        return (!items.is_empty(), false, 0);
    }
    let gaps = continuity_gaps(chain, items);
    (!items.is_empty(), items.is_empty() || gaps == 0, gaps)
}

/// Strict Python-parity wire checks; v2 also binds the authority checkpoint.
fn continuity_admissible(item: &Value, kl: &KeyLog, origin: Option<&Value>) -> bool {
    const MEMBERS: [&str; 7] = ["schema", "origin", "from_hash", "to_hash", "from_tree_size", "to_tree_size", "appended"];
    let (Some(outer), Some(body)) = (item.as_object(), item.get("body").and_then(Value::as_object)) else { return false };
    let issuer_bound = body.get("schema").and_then(Value::as_str) == Some("evd/continuity/v2");
    let authority_shape = !issuer_bound || continuity_authority_hash(body.get("authority_checkpoint_hash"));
    let shaped = authority_shape && outer.len() == 3 && body.len() == (if issuer_bound { 8 } else { 7 }) && MEMBERS.iter().all(|m| body.contains_key(*m)) && ["from_tree_size", "to_tree_size", "appended"].iter().all(|m| body[*m].is_u64()) && ["origin", "from_hash", "to_hash"].iter().all(|m| body[*m].as_str().is_some_and(|t| !t.is_empty()));
    let (Some(key), Some(sig)) = (item.get("kid").and_then(Value::as_str).and_then(|kid| kl.keys.get(kid)), item.get("sig").and_then(Value::as_str).and_then(|s| B64.decode(s).ok())) else { return false };
    shaped && body.get("origin") == origin && continuity_self_consistent(item) && jcs::canonical_checked(&item["body"]).is_some_and(|canon| ed25519_verify(key, &canon, &sig))
}

fn continuity_authority_hash(value: Option<&Value>) -> bool {
    value.and_then(Value::as_str).is_some_and(|s| s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
}

/// V2 binds an exact retained interval to the target checkpoint's issuer.
/// V1 keeps its historical known-log-key interpretation.
fn continuity_authority(item: &Value, bundle: &Value, chain: &[Value], kl: &KeyLog) -> bool {
    let b = &item["body"];
    if b["schema"] == "evd/continuity/v1" {
        return true;
    }
    let (Some(hash), Some(kid), Some(first), Some(last)) = (b["authority_checkpoint_hash"].as_str(), item["kid"].as_str(), b["from_hash"].as_str(), b["to_hash"].as_str()) else { return false };
    let find = |hash: &str| chain.iter().position(|cp| checkpoint_body_hash(cp).as_deref() == Some(hash));
    let (Some(authority), Some(start), Some(end)) = (find(hash), find(first), find(last)) else { return false };
    let cp = &chain[authority];
    let (Some(ts), Some(size)) = (cp["body"]["ts"].as_str(), cp["body"]["tree_size"].as_u64()) else { return false };
    cp == &bundle["target_checkpoint"] && cp["kid"].as_str() == Some(kid) && !kl.state.get(kid).is_some_and(|s| s.non_issuer) && key_active(kl, kid, ts, size) && start < end && chain[start]["body"]["tree_size"] == b["from_tree_size"] && chain[end]["body"]["tree_size"] == b["to_tree_size"]
}

/// Assertion endpoints must agree with their retained interval.
pub(crate) fn continuity_self_consistent(assertion: &Value) -> bool {
    let Some(b) = assertion.get("body") else { return false };
    let (Some(from), Some(to), Some(appended)) = (b.get("from_tree_size").and_then(Value::as_i64), b.get("to_tree_size").and_then(Value::as_i64), b.get("appended").and_then(Value::as_i64)) else { return false };
    let (Some(fh), Some(th)) = (b.get("from_hash").and_then(Value::as_str), b.get("to_hash").and_then(Value::as_str)) else { return false };
    (b["schema"] == "evd/continuity/v1" || b["schema"] == "evd/continuity/v2" && continuity_authority_hash(b.get("authority_checkpoint_hash"))) && from >= 0 && to >= from && appended == to - from && fh != th
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// A Merkle proof is exclusively a sequence of 32-byte hashes.
fn proof_hashes(v: Option<&Value>) -> Option<Vec<[u8; 32]>> {
    match v {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|x| x.as_str().and_then(hex_to_bytes).and_then(|b| b.try_into().ok())).collect(),
        Some(_) => None,
    }
}

fn verify_checkpoint_sig(cp: &Value, keys: &BTreeMap<String, [u8; 32]>) -> bool {
    // Close checkpoint members here; alg alone is optional and defaults to EdDSA.
    const CHECKPOINT_MEMBERS: [&str; 7] = ["schema", "origin", "tree_size", "root_hash", "ts", "prev_hash", "alg"];
    let Some(kid) = cp.get("kid").and_then(|v| v.as_str()) else { return false };
    let Some(pubkey) = keys.get(kid) else { return false };
    let Some(body) = cp.get("body") else { return false };
    let Some(object) = body.as_object() else { return false };
    if object.keys().any(|k| !CHECKPOINT_MEMBERS.contains(&k.as_str())) || body.get("alg").is_some_and(|alg| alg.as_str() != Some("EdDSA")) {
        return false;
    }
    let Some(sig_b64) = cp.get("sig").and_then(|v| v.as_str()) else { return false };
    let Ok(sig) = B64.decode(sig_b64) else {
        return false;
    };
    // over-deep / non-integer body cannot verify
    let Some(canon) = jcs::canonical_checked(body) else {
        return false;
    };
    let msg = pae(CHECKPOINT_TYPE, &canon);
    ed25519_verify(pubkey, &msg, &sig)
}

/// Require bidirectional equality between active log keys and JWKS kids.
fn check_jwks_match_log(bundle: &Value, kl: &KeyLog) -> bool {
    let jwks = match bundle.get("jwks").and_then(|v| v.get("keys")).and_then(|v| v.as_array()) {
        Some(k) if !k.is_empty() => k,
        _ => return false,
    };
    let mut listed: BTreeSet<String> = BTreeSet::new();
    for jwk in jwks {
        match key_from_jwk(jwk) {
            Some((mat, kid)) => match kl.keys.get(&kid) {
                Some(logmat) if *logmat == mat => {
                    listed.insert(kid);
                }
                _ => {
                    return false;
                }
            },
            None => {
                return false;
            }
        }
    }
    kl.state.iter().all(|(kid, state)| state.revoked_at.is_some() || listed.contains(kid))
}

fn check_target_checkpoint(target: &Value, kl: &KeyLog) -> bool {
    if !verify_checkpoint_sig(target, &kl.keys) {
        return false;
    }
    let target_ts = target.get("body").and_then(|b| b.get("ts")).and_then(|v| v.as_str()).unwrap_or("");
    let target_size = target.get("body").and_then(|b| b.get("tree_size")).and_then(Value::as_u64).unwrap_or(0);
    let target_kid = target.get("kid").and_then(|v| v.as_str()).unwrap_or("");
    !kl.state.get(target_kid).is_some_and(|state| state.non_issuer) && key_active(kl, target_kid, target_ts, target_size)
}

fn check_chain_consistency(prev: &Value, cp: &Value, entry: &Value, prev_size: u64, cur_size: u64) -> bool {
    let Some(proof) = proof_hashes(entry.get("consistency_from_prev")) else { return false };
    let prev_root = prev.get("body").and_then(|b| b.get("root_hash")).and_then(|v| v.as_str()).unwrap_or("");
    let cur_root = cp.get("body").and_then(|b| b.get("root_hash")).and_then(|v| v.as_str()).unwrap_or("");
    let (pr, cr) = match (hex_to_bytes(prev_root), hex_to_bytes(cur_root)) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    merkle::verify_consistency(prev_size, cur_size, &pr, &cr, &proof)
}

fn check_chain_link(prev: &Value, cp: &Value, entry: &Value, sparse: bool) -> bool {
    let Some(prev_bh) = checkpoint_body_hash(prev) else { return false };
    let cur_prev = cp.get("body").and_then(|b| b.get("prev_hash")).and_then(|v| v.as_str()).unwrap_or("");
    if (sparse && cur_prev.is_empty()) || (!sparse && cur_prev != prev_bh) {
        return false;
    }
    let prev_size = prev.get("body").and_then(|b| b.get("tree_size")).and_then(|v| v.as_u64()).unwrap_or(0);
    let cur_size = cp.get("body").and_then(|b| b.get("tree_size")).and_then(|v| v.as_u64()).unwrap_or(0);
    if cur_size < prev_size {
        return false;
    }
    let prev_origin = prev.get("body").and_then(|b| b.get("origin")).and_then(|v| v.as_str());
    let cur_origin = cp.get("body").and_then(|b| b.get("origin")).and_then(|v| v.as_str());
    if prev_origin != cur_origin {
        return false;
    }
    // consistency proof (when prev tree non-empty)
    if prev_size > 0 && !check_chain_consistency(prev, cp, entry, prev_size, cur_size) {
        return false;
    }
    true
}

fn check_checkpoint_chain(chain: &[Value], chain_entries: &[Value], kl: &KeyLog, sparse: bool) -> bool {
    // A presented chain is the complete history, never an arbitrary suffix.
    // Its first signed checkpoint must therefore be the genesis checkpoint.
    if chain.first().and_then(|cp| cp.get("body")).and_then(|body| body.get("prev_hash")).and_then(|v| v.as_str()) != Some("") {
        return false;
    }
    for (i, cp) in chain.iter().enumerate() {
        if !verify_checkpoint_sig(cp, &kl.keys) {
            return false;
        }
        let ts = cp.get("body").and_then(|b| b.get("ts")).and_then(|v| v.as_str()).unwrap_or("");
        let size = cp.get("body").and_then(|b| b.get("tree_size")).and_then(Value::as_u64).unwrap_or(0);
        let kid = cp.get("kid").and_then(|v| v.as_str()).unwrap_or("");
        if kl.state.get(kid).is_some_and(|state| state.non_issuer) || !key_active(kl, kid, ts, size) {
            return false;
        }
        if i > 0 && !check_chain_link(&chain[i - 1], cp, &chain_entries[i], sparse) {
            return false;
        }
    }
    true
}

fn check_bundle_origin(bundle: &Value, target: &Value, chain: &[Value]) -> bool {
    // Unsigned `bundle.origin` must name both the signed target and complete history.
    let Some(origin) = bundle.get("origin").and_then(|v| v.as_str()) else { return false };
    let target_origin = target.get("body").and_then(|body| body.get("origin")).and_then(|v| v.as_str());
    target_origin == Some(origin) && chain.iter().all(|cp| cp.get("body").and_then(|body| body.get("origin")).and_then(|v| v.as_str()) == Some(origin))
}

fn chain_head_matches(chain: &[Value], target: &Value) -> bool {
    // an unhashable checkpoint on EITHER side is a mismatch, never a pass
    let (Some(head), Some(want)) = (checkpoint_body_hash(chain.last().unwrap()), checkpoint_body_hash(target)) else { return false };
    head == want
}

fn check_entry_sigs(env: &Value, sigs: &[Value], body: &Value, leaf: u64, kl: &KeyLog) -> bool {
    // Verify every signature's own bytes; duplicate key IDs receive no shortcut.
    let Some(message) = envelope_message(env) else { return false };
    for s in sigs {
        let kid = s.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
        let Some(pubkey) = kl.keys.get(kid) else { return false };
        let genesis = leaf == 0 && body.get("action_type").and_then(Value::as_str) == Some("evd.key.created") && body.get("context").and_then(|ctx| ctx.get("jwk")).and_then(|jwk| jwk.get("kid")).and_then(Value::as_str) == Some(kid);
        let ts_server = body.get("ts_server").and_then(Value::as_str).unwrap_or("");
        if !signature_valid(s, &message, pubkey) || !(genesis || key_active(kl, kid, ts_server, leaf)) {
            return false;
        }
    }
    true
}

fn check_entry_inclusion(e: &Value, payload: &[u8], size: u64, root: &[u8]) -> bool {
    // recomputed receipt hash, then the RFC 6962 leaf hash (0x00 prefix)
    let rh = sha256(payload);
    let mut leaf_data = vec![0x00u8];
    leaf_data.extend_from_slice(&rh);
    let leaf_hash = sha256(&leaf_data);
    let leaf_index = e.get("leaf_index").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
    let Some(proof) = proof_hashes(e.get("inclusion_proof")) else { return false };
    merkle::verify_inclusion(&leaf_hash, leaf_index, size, &proof, root)
}

/// Close envelope members exactly as core/receipt_wire.py does.
fn envelope_members_closed(env: &Value) -> bool {
    env.as_object().is_some_and(|members| members.len() == 3 && ["payload", "payloadType", "signatures"].iter().all(|k| members.contains_key(*k)))
}

fn check_entry(e: &Value, kl: &KeyLog, size: u64, root: &[u8], covers: &[(u64, i64)], expected_tenant: &str) -> bool {
    let env = &e["envelope"];
    if !envelope_members_closed(env) {
        return false;
    }
    let Some(payload) = payload_of(env) else { return false };
    let Some(body) = canonical_body(&payload) else { return false };
    // schema
    if !receipt_body_valid(&body, Some(expected_tenant)) {
        return false;
    }
    // every signature valid + key valid at ts_server; receipt_body_valid has
    // already admitted both timestamps under the shared canonical UTC profile.
    let ts_server = body.get("ts_server").and_then(|v| v.as_str()).unwrap_or("");
    // Bound ts_server against the first signed checkpoint covering this leaf.
    let leaf = e.get("leaf_index").and_then(Value::as_u64).unwrap_or(u64::MAX);
    let first_cover = covers.partition_point(|(covered, _)| *covered <= leaf);
    if let Some((_, deadline)) = covers.get(first_cover) {
        if utc_epoch_micros(ts_server).is_none_or(|admitted| admitted > *deadline) {
            return false;
        }
    }
    let sigs = match env.get("signatures").and_then(|v| v.as_array()) {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    if env.get("payloadType").and_then(|v| v.as_str()) != Some(RECEIPT_TYPE) {
        return false;
    }
    if !check_entry_sigs(env, sigs, &body, leaf, kl) {
        return false;
    }
    check_entry_inclusion(e, &payload, size, root)
}

/// Verify the optional export manifest's claim about the carried receipt set.
fn manifest_target_time(body: &Value, bundle: &Value, target: &Value, kid: &str) -> Option<String> {
    if body.get("schema").and_then(|v| v.as_str()) != Some("evd/export-manifest/v1") {
        return None;
    }
    let origin = body.get("origin").and_then(|v| v.as_str());
    if origin.is_none() || origin != bundle.get("origin").and_then(|v| v.as_str()) || origin != target.get("body").and_then(|b| b.get("origin")).and_then(|v| v.as_str()) {
        return None;
    }
    match (body.get("target_checkpoint_hash").and_then(|v| v.as_str()), checkpoint_body_hash(target)) {
        (Some(claimed), Some(actual)) if claimed == actual => {}
        _ => return None,
    }
    let ts = body.get("ts").and_then(|v| v.as_str())?;
    if target.get("body").and_then(|v| v.get("ts")).and_then(Value::as_str) != Some(ts) || target.get("kid").and_then(Value::as_str) != Some(kid) {
        return None;
    }
    Some(ts.to_string())
}

/// A present manifest needs the target issuer and exact carried-receipt equality.
fn check_export_manifest(bundle: &Value, entries: &[Value], target: &Value, kl: &KeyLog) -> Option<bool> {
    let raw = bundle.get("export_manifest").filter(|v| !v.is_null())?;
    let (Some(body), Some(kid), Some(sig_b64)) = (raw.get("body").filter(|b| b.is_object()), raw.get("kid").and_then(|v| v.as_str()), raw.get("sig").and_then(|v| v.as_str())) else { return Some(false) };
    let Some(ts) = manifest_target_time(body, bundle, target, kid) else { return Some(false) };
    let Some(pubkey) = kl.keys.get(kid) else { return Some(false) };
    let size = target.get("body").and_then(|body| body.get("tree_size")).and_then(Value::as_u64).unwrap_or(0);
    if kl.state.get(kid).is_some_and(|state| state.non_issuer) || !key_active(kl, kid, &ts, size) {
        return Some(false);
    }
    let Some(canon) = jcs::canonical_checked(body) else { return Some(false) };
    let Ok(sig) = B64.decode(sig_b64) else { return Some(false) };
    if !ed25519_verify(pubkey, &pae(EXPORT_MANIFEST_TYPE, &canon), &sig) {
        return Some(false);
    }
    let Some(listed) = body.get("receipt_hashes").and_then(|v| v.as_array()) else { return Some(false) };
    if listed.len() > MAX_ENTRIES {
        return Some(false);
    }
    let claimed: Option<BTreeSet<String>> = listed.iter().map(|h| h.as_str().map(str::to_string)).collect();
    let Some(claimed) = claimed else { return Some(false) };
    let carried: BTreeSet<String> = entries.iter().filter_map(|e| e.get("envelope").and_then(receipt_hash_hex)).collect();
    Some(claimed == carried)
}

/// Validate entries, completeness and per-agent sequence uniqueness.
fn check_entry_set(bundle: &Value, entries: &[Value], target: &Value, chain: &[Value], kl: &KeyLog, trust: Option<&Value>, facts: &mut BundleFacts) -> bool {
    // Preserve manifest tri-state even when another entry-set check fails.
    facts.complete = check_export_manifest(bundle, entries, target, kl);
    check_entries(entries, target, chain, kl, trust, facts) && facts.complete != Some(false) && check_seq_uniqueness(entries)
}

/// Per-checkpoint latest admissible receipt time; malformed chains refuse.
fn checkpoint_cover_deadlines(chain: &[Value]) -> Option<Vec<(u64, i64)>> {
    chain
        .iter()
        .map(|cp| {
            let body = cp.get("body")?;
            let size = body.get("tree_size")?.as_u64()?;
            let ts = body.get("ts")?.as_str()?;
            Some((size, utc_epoch_micros(ts)? + RECEIPT_CHECKPOINT_SKEW_S * 1_000_000))
        })
        .collect()
}

fn check_entries(entries: &[Value], target: &Value, chain: &[Value], kl: &KeyLog, trust: Option<&Value>, facts: &mut BundleFacts) -> bool {
    let size = target.get("body").and_then(|b| b.get("tree_size")).and_then(|v| v.as_u64()).unwrap_or(0);
    let root_hex = target.get("body").and_then(|b| b.get("root_hash")).and_then(|v| v.as_str()).unwrap_or("");
    let Some(root) = hex_to_bytes(root_hex) else { return false };
    let Some(covers) = checkpoint_cover_deadlines(chain) else { return false };
    let Some(expected_tenant) = target.get("body").and_then(|body| body.get("origin")).and_then(Value::as_str).and_then(tenant_from_origin) else { return false };
    for e in entries {
        if !check_entry(e, kl, size, &root, &covers, expected_tenant) {
            return false;
        }
        if entry_recorder_attested(&e["envelope"], kl, trust) {
            let Some(leaf) = e.get("leaf_index").and_then(Value::as_u64) else { return false };
            facts.recorder_attested.push(leaf);
        }
    }
    true
}

fn check_seq_uniqueness(entries: &[Value]) -> bool {
    // (agent_id, seq) -> the receipt_hash first seen there. A DIFFERENT
    // hash colliding on the same pair is forgery; the same hash repeated
    // is harmless redundancy.
    let mut pairs: BTreeMap<(String, i64), String> = BTreeMap::new();
    for e in entries {
        if let Some(body) = e.get("envelope").and_then(body_of) {
            let aid = body.get("agent_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let seq = body.get("seq").and_then(|v| v.as_i64()).unwrap_or(-1);
            let rh = match e.get("envelope").and_then(receipt_hash_hex) {
                Some(h) => h,
                None => continue,
            };
            match pairs.get(&(aid.clone(), seq)) {
                Some(prev) if *prev != rh => return false, // distinct dup
                Some(_) => {}                              // same receipt, fine
                None => {
                    pairs.insert((aid, seq), rh);
                }
            }
        }
    }
    true
}

pub(crate) fn is_internal_agent(a: &str) -> bool {
    matches!(a, "_system" | "_grants" | "_reports" | "_detect" | "_idem" | "_authority" | "_node" | "_register")
    // Relationship counters are never exempt receipt agent IDs.
}

type LineageItem = (String, String, i64, Value); // (action_type, receipt_hash, seq, context)

fn collect_lineage(entries: &[Value]) -> Option<BTreeMap<String, Vec<LineageItem>>> {
    // one Vec of the above per acting agent
    let mut by_agent: BTreeMap<String, Vec<LineageItem>> = BTreeMap::new();
    for e in entries {
        if let Some(body) = e.get("envelope").and_then(body_of) {
            let agent = body.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
            if agent.is_empty() || is_internal_agent(agent) {
                continue; // ONLY known internal bookkeeping agents are exempt
            }
            let at = body.get("action_type").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let seq = body.get("seq").and_then(|v| v.as_i64()).unwrap_or(-1);
            let rh = e.get("envelope").and_then(receipt_hash_hex)?;
            let ctx = body.get("context").cloned().unwrap_or(Value::Null);
            by_agent.entry(agent.to_string()).or_default().push((at, rh, seq, ctx));
        }
    }
    Some(by_agent)
}

fn check_lineage_orphan(items: &[LineageItem], valid: &BTreeSet<String>) -> bool {
    // no establishment: revision_id must still match a present revision
    for (_, _, _, ctx) in items {
        if let Some(rv) = ctx.get("revision_id").and_then(|v| v.as_str()) {
            if !valid.is_empty() && !valid.contains(rv) {
                return false; // forged revision
            }
        }
    }
    true
}

fn check_lineage_established(items: &[LineageItem], valid: &BTreeSet<String>, birth_at: &str, birth_hash: &str, birth_seq: i64) -> bool {
    // `born` requires seq 1; `adopted` may begin at its first observed seq.
    if birth_at == "lineage.born" && birth_seq != 1 {
        return false;
    }
    for (_, _, _, ctx) in items {
        if let Some(bt) = ctx.get("birthtag_id").and_then(|v| v.as_str()) {
            if bt != birth_hash {
                return false; // forged lineage
            }
        }
        if let Some(rv) = ctx.get("revision_id").and_then(|v| v.as_str()) {
            if !valid.contains(rv) {
                return false; // forged revision
            }
        }
    }
    true
}

fn check_agent_lineage(items: &[(String, String, i64, Value)]) -> bool {
    let est: Vec<&(String, String, i64, Value)> = items.iter().filter(|(at, _, _, _)| at == "lineage.born" || at == "lineage.adopted").collect();
    if est.len() > 1 {
        return false; // duplicate establishment — forged or split history
    }
    // valid revision targets: present establishment + revision receipts
    let mut valid: BTreeSet<String> = BTreeSet::new();
    for (at, rh, _, _) in items {
        if at == "lineage.revised" || at == "lineage.born" || at == "lineage.adopted" {
            valid.insert(rh.clone());
        }
    }
    match est.first() {
        None => check_lineage_orphan(items, &valid),
        Some((birth_at, birth_hash, birth_seq, _)) => check_lineage_established(items, &valid, birth_at, birth_hash, *birth_seq),
    }
}

fn check_lineage(entries: &[Value]) -> bool {
    let Some(by_agent) = collect_lineage(entries) else { return false };
    for (_agent, items) in by_agent {
        if !check_agent_lineage(&items) {
            return false;
        }
    }
    true
}

/// Carried anchor/TST time must be canonical and not predate its checkpoint.
fn record_not_before_checkpoint(rec: &Value, field: &str, signed_ts: &str) -> bool {
    let claimed = rec.get(field).and_then(Value::as_str).and_then(utc_epoch_micros);
    matches!((claimed, utc_epoch_micros(signed_ts)), (Some(claimed), Some(signed)) if claimed >= signed)
}

type CheckpointFacts = BTreeMap<String, (String, u64)>;

fn bound_record_ok(rec: &Value, required: &[&str], time_field: &str, checkpoints: &CheckpointFacts) -> bool {
    let Some(obj) = rec.as_object() else { return false };
    if required.iter().any(|f| !obj.contains_key(*f)) {
        return false;
    }
    let bh = rec.get("checkpoint_body_hash").and_then(|v| v.as_str()).unwrap_or("");
    let Some((signed, _size)) = checkpoints.get(bh) else {
        return false;
    }; // not a checkpoint in this chain
    record_not_before_checkpoint(rec, time_field, signed)
}

fn check_bound_records(records: &Value, required: &[&str], time_field: &str, checkpoints: &CheckpointFacts) -> bool {
    let Some(arr) = records.as_array() else { return false };
    let digests: BTreeSet<_> = arr.iter().filter_map(|r| r.get("checkpoint_body_hash").and_then(Value::as_str)).collect();
    if arr.len() > MAX_ATTESTATION_RECORDS || digests.len() != arr.len() {
        return false;
    }
    arr.iter().all(|rec| bound_record_ok(rec, required, time_field, checkpoints))
}

fn check_tst_records(records: &Value, checkpoints: &CheckpointFacts, roots: Option<&str>, policy: trust::TsaPolicy, trust_context: Option<&Value>, facts: &mut BundleFacts) -> bool {
    if !check_bound_records(records, &["checkpoint_body_hash", "token_der_b64", "tsa_url", "gen_time", "cert_chain_pem", "qualified"], "gen_time", checkpoints) {
        return false;
    }
    let Some(items) = records.as_array() else { return false };
    for record in items {
        let (Some(body_hash), Some(token_b64), Some(displayed), Some(chain)) = (record.get("checkpoint_body_hash").and_then(Value::as_str), record.get("token_der_b64").and_then(Value::as_str), record.get("gen_time").and_then(Value::as_str), record.get("cert_chain_pem").and_then(Value::as_str)) else { return false };
        let Ok(token) = B64.decode(token_b64) else { return false };
        if policy == trust::TsaPolicy::Malformed {
            return false;
        }
        let Some((actual, trusted)) = crate::tsa::verified_tst(&token, body_hash, chain, roots, policy, trust_context) else { return false };
        if actual.to_date_time().to_string() != displayed {
            return false;
        }
        if policy == trust::TsaPolicy::OfflineRenewal {
            let Some(renewals) = trust::tsa_renewal_chain(trust_context, &token) else { return false };
            if !trusted || !crate::tsa::verify_renewal_chain(&token, chain, &actual, &renewals, roots, trust_context) {
                return false;
            }
        }
        if trusted {
            facts.trusted_tst_checkpoints.push(body_hash.to_string());
        }
    }
    true
}

fn check_attestation_records(bundle: &Value, checkpoints: &CheckpointFacts, trust: Option<&Value>, facts: &mut BundleFacts) -> bool {
    // 7. Optional RFC 3161 records need full validation and exact genTime.
    if let Some(tsts) = bundle.get("tst_records").filter(|v| !v.is_null()) {
        let roots = trust::tsa_roots_pem(trust);
        let policy = trust::tsa_policy(trust);
        if !check_tst_records(tsts, checkpoints, roots.as_deref(), policy, trust, facts) {
            return false;
        }
    }

    // 8. anchor records (if present): each must bind to a chain checkpoint
    if let Some(anchors) = bundle.get("anchor_records").filter(|v| !v.is_null()) {
        if !check_bound_records(anchors, &["checkpoint_body_hash", "chain_id", "tx_hash", "block_number", "block_ts", "contract"], "block_ts", checkpoints) {
            return false;
        }
    }
    true
}

fn checkpoint_facts(chain: &[Value]) -> Option<CheckpointFacts> {
    chain
        .iter()
        .map(|checkpoint| {
            let body = checkpoint.get("body")?;
            Some((checkpoint_body_hash(checkpoint)?, (body.get("ts")?.as_str()?.to_string(), body.get("tree_size")?.as_u64()?)))
        })
        .collect()
}

fn check_checkpoints_and_entries(bundle: &Value, entries: &[Value], kl: &KeyLog, trust: Option<&Value>, facts: &mut BundleFacts) -> bool {
    // 2. target checkpoint
    let Some(target) = bundle.get("target_checkpoint") else { return false };

    // 3. chain: signatures, linkage, monotonic, same origin, consistency
    let Some(chain_entries) = bundle.get("checkpoint_chain").and_then(|v| v.as_array()) else { return false };
    // Malformed links refuse; filtering could create a false history.
    let chain: Vec<Value> = match chain_entries.iter().map(|entry| entry.get("checkpoint").cloned()).collect() {
        Some(chain) => chain,
        None => return false,
    };
    if chain.is_empty() {
        return false;
    }
    // Set completeness at Python's matching structural boundary.
    if !check_entry_set(bundle, entries, target, &chain, kl, trust, facts) {
        return false;
    }
    if !check_target_checkpoint(target, kl) {
        return false;
    }
    let sparse = match bundle.get("checkpoint_chain_profile") {
        None => false,
        Some(Value::String(profile)) if profile == SPARSE_CHECKPOINT_CHAIN_PROFILE => true,
        _ => return false,
    };
    if !check_checkpoint_chain(&chain, chain_entries, kl, sparse) {
        return false;
    }
    if !check_bundle_origin(bundle, target, &chain) {
        return false;
    }

    // 4. target == chain head
    if !chain_head_matches(&chain, target) {
        return false;
    }

    // 6. lineage: absence is allowed; forgery is fatal.
    if !check_lineage(entries) {
        return false;
    }

    let Some(checkpoints) = checkpoint_facts(&chain) else { return false };
    if !check_attestation_records(bundle, &checkpoints, trust, facts) {
        return false;
    }
    facts.chain_sizes = checkpoints.into_iter().map(|(hash, (_ts, size))| (hash, size)).collect();
    (facts.continuity_present, facts.continuity_ok, facts.continuity_gaps) = assess_continuity(bundle, &chain, kl);
    true
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    Some(v.get(key)?.as_str()?.to_string())
}

type DisclosureFields = (String, String, String, Vec<u8>, Vec<u8>); // (receipt_hash, field, domain, nonce, payload)

const DISCLOSURE_FIELD_DOMAINS: &[(&str, &[&str])] = &[
    ("payload", &["evd/v1/payload"]),
    ("prompt", &["evd/v1/prompt", "evd/v1/llm.prompt"]),
    ("output", &["evd/v1/output", "evd/v1/llm.output"]),
    ("tool.args", &["evd/v1/tool.args"]),
    ("tool.result", &["evd/v1/tool.result"]),
    ("message", &["evd/v1/interaction.message"]),
    ("policy_input", &["evd/v1/policy.input"]),
    ("policy_output", &["evd/v1/policy.output"]),
    ("approver_id", &["evd/v1/approver_id"]),
    ("justification", &["evd/v1/justification"]),
    ("escalation_target_id", &["evd/v1/escalation_target"]),
    ("config", &["evd/v1/agent.config", "evd/v1/lineage/config"]),
    ("query", &["evd/v1/query"]),
    ("trigger_content", &["evd/v1/guardrail.trigger"]),
    ("amount_exact", &["evd/v1/payment.amount"]),
    ("counterparty_id", &["evd/v1/payment.counterparty"]),
    ("mandate_ref", &["evd/v1/payment.mandate"]),
    ("system_prompt", &["evd/v1/lineage/system_prompt"]),
    ("tool_manifest", &["evd/v1/lineage/tool_manifest"]),
    ("mandate_document", &["evd/v1/lineage/mandate_document"]),
    ("created_by_id", &["evd/v1/lineage/created_by_id"]),
    ("enrolment_evidence", &["evd/v1/authority/enrolment_evidence"]),
    ("source_manifest", &["evd/v1/authority/source_manifest"]),
    ("inputs", &["evd/v1/authority/inputs"]),
    ("context_doc", &["evd/v1/authority/context_doc"]),
    ("request", &["evd/v1/authority/request"]),
    ("batch", &["evd/v1/node/batch"]),
    ("attestation", &["evd/v1/node/attestation"]),
    ("statement", &["evd/v1/node/triage"]),
    ("doc", &["evd/v1/node/coverage"]),
];

fn disclosure_domain(field: &str, domain: &str) -> bool {
    if !disclosure_text(field) || !disclosure_text(domain) || !domain.starts_with(DOMAIN_PREFIX) {
        return false;
    }
    let fixed = DISCLOSURE_FIELD_DOMAINS.iter().find(|(name, _)| *name == field).is_some_and(|(_, domains)| domains.contains(&domain));
    fixed || domain == format!("evd/v1/x/{field}")
}

fn disclosure_nonce(pkg: &Value) -> Option<Vec<u8>> {
    let nonce = hex_to_bytes(&str_field(pkg, "nonce_hex")?)?;
    (nonce.len() >= 16).then_some(nonce)
}

fn disclosure_payload(pkg: &Value) -> Option<Vec<u8>> {
    let text = str_field(pkg, "payload_b64")?;
    let payload = B64.decode(&text).ok()?;
    (B64.encode(&payload) == text).then_some(payload)
}

fn disclosure_fields(pkg: &Value) -> Option<DisclosureFields> {
    if pkg.as_object()?.len() != 6 || str_field(pkg, "schema").as_deref() != Some(DISCLOSURE_SCHEMA) {
        return None;
    }
    let rh = str_field(pkg, "receipt_hash")?;
    if !lower_sha256(&rh) {
        return None;
    }
    let field = str_field(pkg, "field")?;
    let domain = str_field(pkg, "domain")?;
    if !disclosure_domain(&field, &domain) {
        return None;
    }
    Some((rh, field, domain, disclosure_nonce(pkg)?, disclosure_payload(pkg)?))
}

fn disclosure_commitment(domain: &str, payload: &[u8], nonce: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0x00u8]);
    h.update(nonce);
    h.update([0x00u8]);
    h.update(payload);
    hex(&h.finalize())
}

fn disclosure_committed_value(raw: &[u8], field: &str) -> Option<String> {
    let body = canonical_body(raw)?;
    body.get("commitments")?.get(field)?.as_str().map(String::from)
}

/// Verify an evd/disclosure/v1 package against an ALREADY-verified bundle:
/// the named receipt's committed `field` must equal
/// SHA-256(domain || 0x00 || nonce || 0x00 || payload). Mirrors
/// verify/disclosure.py — weak or malformed input is false, never a panic;
/// this does not re-verify the bundle itself.
fn verify_disclosure(pkg: &Value, bundle: &Value) -> bool {
    let Some((rh, field, domain, nonce, payload)) = disclosure_fields(pkg) else { return false };
    let Some(entries) = bundle.get("entries").and_then(|v| v.as_array()) else { return false };
    for e in entries {
        let raw = match e.get("envelope").and_then(payload_of) {
            Some(r) => r,
            None => continue,
        };
        if hex(&sha256(&raw)) != rh {
            continue;
        }
        let Some(expected) = disclosure_committed_value(&raw, &field) else { return false };
        return disclosure_commitment(&domain, &payload, &nonce) == expected;
    }
    false
}

/// Strict JSON boundary shared by native Rust and WASM disclosure verification.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn verify_disclosure_json(package_json: &[u8], bundle_json: &[u8]) -> bool {
    if package_json.len() > MAX_BUNDLE_BYTES || bundle_json.len() > MAX_BUNDLE_BYTES {
        return false;
    }
    let (Some(pkg), Some(bundle)) = (trust::strict_json(package_json), trust::strict_json(bundle_json)) else {
        return false;
    };
    verify_disclosure(&pkg, &bundle)
}

/// E3 requires a verified non-issuer recorder co-signature under local trust.
fn entry_recorder_attested(env: &Value, kl: &KeyLog, trust: Option<&Value>) -> bool {
    let Some(sigs) = env.get("signatures").and_then(Value::as_array) else { return false };
    if sigs.len() < 2 || sigs.iter().all(|s| kl.state.get(s.get("keyid").and_then(Value::as_str).unwrap_or("")).is_some_and(|state| state.non_issuer)) {
        return false; // single signature, or no issuer beside the recorder
    }
    sigs.iter().any(|sig| {
        let kid = sig.get("keyid").and_then(Value::as_str).unwrap_or("");
        if !kl.state.get(kid).is_some_and(|state| state.recorder) {
            return false;
        }
        let Some(pub_bytes) = trust::key_for(trust, "recorder_keys", Some(kid)) else { return false };
        let Ok(pubkey): Result<[u8; 32], _> = pub_bytes.try_into() else { return false };
        kl.keys.get(kid) == Some(&pubkey)
    })
}

/// Verify once; local trust can award evidence levels but never validate a bad bundle.
///
/// ```
/// let report = swarrm_verify::verify_bundle(&serde_json::json!({}), None);
/// assert_eq!(report["ok"], false);
/// ```
pub fn verify_bundle(bundle: &Value, trust: Option<&Value>) -> Value {
    let facts = verify_bundle_facts(bundle, trust);
    serde_json::json!({"ok": facts.ok, "recorder_attested": facts.recorder_attested, "trusted_tst_checkpoints": facts.trusted_tst_checkpoints, "chain_sizes": facts.chain_sizes, "continuity_gaps": facts.continuity_gaps, "continuity_present": facts.continuity_present, "continuity_ok": facts.continuity_ok})
}

/// Verify the complete dispute package and its recomputed statements offline.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn verify_dispute_json(package_json: &[u8]) -> String {
    let result = dispute::verify_json(package_json);
    let (verdict, reconciliation, package_digest) = match result {
        Some((facts, digest)) => ("VERIFIED", facts, Some(digest)),
        None => ("NOT_VERIFIED", Value::Null, None),
    };
    serde_json::json!({"schema": "evd/dispute-verification-result/v1", "verdict": verdict,
        "reconciliation": reconciliation, "package_digest": package_digest})
    .to_string()
}

fn acknowledgement_coverage(ack: &Value, bundle: &Value, facts: &BundleFacts) -> Option<&'static str> {
    if ack["origin"] != bundle["origin"] {
        return Some("other-origin");
    }
    Some(match (facts.chain_sizes.get(ack["from_hash"].as_str()?), facts.chain_sizes.get(ack["to_hash"].as_str()?)) {
        (Some(start), Some(end)) if start < end => "covered",
        (Some(_), Some(_)) => "malformed",
        _ => "conflict",
    })
}

/// Compare a verified counterparty CWT with a separately verified bundle.
/// Context is local canonical CBOR (keys and time), never selected by evidence.
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub fn verify_acknowledgement_json(envelope: &[u8], context: &[u8], bundle_json: &[u8]) -> String {
    let accepted = (|| {
        if bundle_json.len() > MAX_BUNDLE_BYTES {
            return None;
        }
        let bundle = trust::strict_json(bundle_json)?;
        let facts = verify_bundle_facts(&bundle, None);
        if !facts.ok {
            return None;
        }
        let ack = b28::verified_acknowledgement(envelope, context)?;
        let coverage = acknowledgement_coverage(&ack, &bundle, &facts)?;
        Some((ack, coverage, hex(&sha256(&jcs::canonical_checked(&bundle)?))))
    })();
    let (verdict, acknowledgement, coverage, bundle_digest) = match accepted {
        Some((ack, cover, digest)) => ("VERIFIED", ack, Some(cover), Some(digest)),
        None => ("NOT_VERIFIED", Value::Null, None, None),
    };
    serde_json::json!({
        "schema": "evd/acknowledgement-assessment/v1", "verdict": verdict,
        "acknowledgement": acknowledgement, "coverage": coverage,
        "bundle_digest": bundle_digest,
        "context_digest": (verdict == "VERIFIED").then(|| hex(&sha256(context))),
        "envelope_digest": (verdict == "VERIFIED").then(|| hex(&sha256(envelope))),
    })
    .to_string()
}

/// (VERIFIED, export-completeness tri-state). The certificate layer computed
/// the second value and threw it away, so a certificate consumer read a bare
/// "VERIFIED" over a bundle whose entries may have been deleted after export
/// while a bundle consumer read "VERIFIED (completeness unproven)". `None` —
/// no manifest carried, or the run never reached the manifest — is NOT
/// failure, and nothing in either engine gates on it.
pub(crate) fn verify_bundle_report(bundle: &Value, trust: Option<&Value>) -> (bool, Option<bool>, Option<bool>) {
    let facts = verify_bundle_facts(bundle, trust);
    (facts.ok, facts.complete, facts.origin_attested)
}

/// verify/verifier.py::_origin_attested: None when the relying party named no
/// key for this origin, else whether THAT key signed the target checkpoint —
/// possession, never mere membership, since a log may enrol anyone's public key.
fn origin_attested(bundle: &Value, kl: &KeyLog, trust: Option<&Value>) -> Option<bool> {
    let expected = trust::key_for(trust, "log_keys", bundle.get("origin").and_then(Value::as_str))?;
    let kid = bundle["target_checkpoint"].get("kid").and_then(Value::as_str).unwrap_or("");
    Some(kl.keys.get(kid).is_some_and(|key| key.as_slice() == expected.as_slice()))
}

fn verify_bundle_facts(bundle: &Value, trust: Option<&Value>) -> BundleFacts {
    let mut facts = BundleFacts::default();
    if bundle.get("schema").and_then(|v| v.as_str()) != Some("evd/bundle/v1") {
        return facts;
    }
    // Enforce resource caps during parsing; over-cap input is NOT VERIFIED.
    if !within_caps(bundle) {
        return facts;
    }
    let entries: Vec<Value> = bundle.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if entries.is_empty() {
        return facts;
    }
    if entries.iter().any(|e| {
        let env = &e["envelope"];
        body_of(env).is_some_and(|body| forbidden_managed_edge_cosign(&body, env))
    }) {
        return facts;
    }

    // 0. key log replay
    let kl = replay_key_log(&entries);
    if !kl.ok {
        return facts;
    }

    // 1. jwks agrees with the log
    if !check_jwks_match_log(bundle, &kl) {
        return facts;
    }

    facts.ok = check_checkpoints_and_entries(bundle, &entries, &kl, trust, &mut facts);
    if facts.ok {
        facts.origin_attested = origin_attested(bundle, &kl, trust);
    } else {
        facts.recorder_attested.clear();
        facts.trusted_tst_checkpoints.clear();
        facts.chain_sizes.clear();
    }
    facts
}

#[cfg(any(test, feature = "wasm"))]
const BROWSER_BUNDLE_RESULT_SCHEMA: &str = "evd/browser-bundle-verification-result/v3";

#[cfg(any(test, feature = "wasm"))]
fn browser_bundle_result(verdict: &str, bundle_digest: Option<String>, error: Option<&str>, facts: Option<&BundleFacts>) -> String {
    serde_json::json!({
        "schema": BROWSER_BUNDLE_RESULT_SCHEMA,
        "verdict": verdict,
        "bundle_digest": bundle_digest,
        "error": error,
        "continuity": facts.map(|f| serde_json::json!({
            "present": f.continuity_present, "ok": f.continuity_ok, "gaps": f.continuity_gaps,
        })),
    })
    .to_string()
}

#[cfg(any(test, feature = "wasm"))]
fn browser_bundle_verification_result(json: &[u8], trust_json: Option<&[u8]>) -> String {
    if json.len() > MAX_BUNDLE_BYTES || trust_json.is_some_and(|raw| raw.len() > MAX_BUNDLE_BYTES) {
        return browser_bundle_result("NOT_VERIFIED", None, None, None);
    }
    let Some(bundle) = trust::strict_json(json) else {
        return browser_bundle_result("ERROR", None, Some("INVALID_JSON"), None);
    };
    let trust = trust_json.and_then(trust::strict_json);
    if trust_json.is_some() && trust.is_none() {
        return browser_bundle_result("ERROR", None, Some("INVALID_TRUST"), None);
    }
    let facts = verify_bundle_facts(&bundle, trust.as_ref());
    if !facts.ok {
        return browser_bundle_result("NOT_VERIFIED", None, None, None);
    }
    match jcs::canonical_checked(&bundle) {
        Some(bytes) => browser_bundle_result("VERIFIED", Some(hex(&sha256(&bytes))), None, Some(&facts)),
        None => browser_bundle_result("NOT_VERIFIED", None, None, None),
    }
}

#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;
    /// Verify a bundle and return its versioned result and canonical digest.
    #[wasm_bindgen]
    pub fn verify_bundle_json(json: &[u8]) -> String {
        super::browser_bundle_verification_result(json, None)
    }

    /// Verify a bundle against separately supplied relying-party trust.
    #[wasm_bindgen]
    pub fn verify_bundle_with_trust_json(json: &[u8], trust_json: &[u8]) -> String {
        super::browser_bundle_verification_result(json, Some(trust_json))
    }
}

#[cfg(test)]
#[path = "../tests/internal/lib_tests.rs"]
mod tests;
