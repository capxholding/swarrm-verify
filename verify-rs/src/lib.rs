// Apache-2.0 (public verifier repo)
//! Public Rust second implementation for evd/bundle/v1.
//!
//! A SECOND implementation, on purpose: it shares no code with the Python
//! verifier, so agreement on the shared golden suite (tests/golden/) is real
//! evidence that the format is unambiguous. Verify-only, offline, no network.

pub mod action;
pub mod b28;
#[allow(dead_code)] // Test-only canonical JSON adapter.
mod cbor;
mod cbor_wire;
pub mod certificate; // `verify_certificate_cbor` also serves the WASM export.
#[allow(dead_code)] // COSE adapter used by SCITT and golden tests.
mod cose;
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
const CHECKPOINT_TYPE: &str = "application/vnd.evd.checkpoint.v1+json";
const EXPORT_MANIFEST_TYPE: &str = "application/vnd.evd.export-manifest.v1+json";
const DISCLOSURE_SCHEMA: &str = "evd/disclosure/v1";
const SPARSE_CHECKPOINT_CHAIN_PROFILE: &str = "evd/checkpoint-chain/sparse-proof-v1";
const DOMAIN_PREFIX: &str = "evd/v1/";

// Resource caps match `verify/verifier.py`: input over any cap is NOT VERIFIED
// in either implementation.
// All caps sit far above every legitimate bundle.
#[allow(dead_code)] // enforced at byte entry points (verify_bundle_json/wasm)
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;
const MAX_INCLUSION_PROOF_LEN: usize = 64;
const MAX_CHECKPOINT_CHAIN_LEN: usize = 100_000;
const MAX_SIGNATURES_PER_ENVELOPE: usize = 9;
const MAX_ATTESTATION_RECORDS: usize = 256;

// A signed checkpoint whose tree_size covers a leaf is the log's own sworn
// statement that it already HELD that receipt, so a receipt's ts_server may
// exceed the FIRST covering checkpoint's signed ts by at most this many
// seconds — anything later is the log contradicting itself. Same value and
// semantics as verify/verifier.py::RECEIPT_CHECKPOINT_SKEW_S.
const RECEIPT_CHECKPOINT_SKEW_S: i64 = 300;

pub(crate) fn depth_exceeds(v: &Value, limit: i64) -> bool {
    // bounded recursion: bails at the first over-deep branch (limit+2 frames
    // at most), so the walk itself can never overflow the stack
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

/// Resource caps are checked before cryptographic work, using the same caps
/// same order as _cap_error in verify/verifier.py.
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
    jcs::canonical_checked(bundle).is_some()
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
    // SPEC/bundle-v1.md §3.1: every JWK's kid matches its key material, reject
    // aliases. Guarding the comparison with `.as_str()` meant a kid that was
    // PRESENT but not a string (false, 0, {}, []) skipped the check entirely
    // and the alias was accepted — 10 of 672 type-confusion mutants verified
    // here and were rejected by Python, all at jwks.keys[0].kid. A carried
    // member that is not the shape it claims is
    // MALFORMED, not absent; `null` alone stays equal to missing, which is the
    // no-claim state the rest of this verifier reads through `.get()`.
    match jwk.get("kid") {
        None | Some(Value::Null) => {}
        Some(Value::String(claimed)) if *claimed == kid => {}
        Some(_) => return None,
    }
    Some((k, kid))
}

pub(crate) fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(v) => v,
        Err(_) => return false,
    };
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

fn signature_valid(sig: &Value, message: &[u8], pubkey: &[u8; 32]) -> bool {
    sig.get("sig").and_then(Value::as_str).and_then(|raw| B64.decode(raw).ok()).is_some_and(|raw| ed25519_verify(pubkey, message, &raw))
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
    canonical_body(&payload_of(env)?)
}

fn canonical_body(raw: &[u8]) -> Option<Value> {
    let mut body = serde_json::from_slice(raw).ok()?;
    jcs::promote_jcs_integer_lexemes(&mut body).then_some(())?;
    (jcs::canonical_checked(&body)?.as_slice() == raw).then_some(body)
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

/// Canonical extended UTC (per `canonical_utc`) → microseconds since the Unix
/// epoch. The covering-checkpoint rule needs `checkpoint ts + 300 s`, which is
/// ARITHMETIC — the lexicographic comparison `kid_valid_at` uses cannot add
/// seconds, and `action::nts` only normalizes. So this reuses the strict
/// grammar for validation (never `nts`'s permissive superset — the parser-gap
/// lesson of `_not_before_checkpoint`) and does days-from-civil arithmetic on
/// the already-validated parts, matching Python's `datetime` to the microsecond.
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

/// Some envelope signature is by a key the log had active at `ts` AND that
/// signature actually verifies. With `issuer_only`, keys the log has marked
/// non-issuer are excluded — one predicate, so the "active key vouched" and
/// "an ISSUER vouched" arms of the key-created sponsorship rule below can
/// never drift apart on what "active and signed" means.
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
    kl.state.insert(kid, KeyState { introduced: (leaf, effective), revoked_at: None, non_issuer: role.is_some() || !issuer_sponsored, recorder: role == Some("recorder") });
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
    let jwk_canon = match jcs::canonical_checked(jwk) {
        Some(c) => c,
        None => return false, // over-deep / non-integer jwk cannot verify
    };
    let cont = match B64.decode(continuity.unwrap()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    if !ed25519_verify(&kl.keys[prev_kid], &jwk_canon, &cont) {
        return false;
    }
    let non_issuer = kl.state.get(prev_kid).is_some_and(|state| state.non_issuer);
    kl.keys.insert(kid.clone(), material);
    kl.state.insert(kid, KeyState { introduced: (leaf, effective), revoked_at: None, non_issuer, recorder: false });
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
        let (material, kid) = match key_from_jwk(&jwk) {
            Some(m) => m,
            None => return kl,
        };
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

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

/// A Merkle proof is a sequence of 32-byte hashes or it is not a proof.
///
/// `filter_map` over the hex decode DROPPED every element it could not decode,
/// so a proof with junk spliced into it was evaluated as a shorter proof instead
/// of being rejected. A proof containing `"zz"` must fail in both verifiers.
/// ABSENT (or null) still means an empty proof — the no-claim shape, which only
/// ever verifies a one-leaf tree — but a carried member that
/// is not a list of 32-byte hex hashes is MALFORMED and rejects the proof.
fn proof_hashes(v: Option<&Value>) -> Option<Vec<[u8; 32]>> {
    match v {
        None | Some(Value::Null) => Some(Vec::new()),
        Some(Value::Array(items)) => items.iter().map(|x| x.as_str().and_then(hex_to_bytes).and_then(|b| b.try_into().ok())).collect(),
        Some(_) => None,
    }
}

fn verify_checkpoint_sig(cp: &Value, keys: &BTreeMap<String, [u8; 32]>) -> bool {
    let Some(kid) = cp.get("kid").and_then(|v| v.as_str()) else { return false };
    let Some(pubkey) = keys.get(kid) else { return false };
    let Some(body) = cp.get("body") else { return false };
    let Some(sig_b64) = cp.get("sig").and_then(|v| v.as_str()) else { return false };
    let sig = match B64.decode(sig_b64) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let canon = match jcs::canonical_checked(body) {
        Some(c) => c,
        None => return false, // over-deep / non-integer body cannot verify
    };
    let msg = pae(CHECKPOINT_TYPE, &canon);
    ed25519_verify(pubkey, &msg, &sig)
}

/// Both directions. Every JWKS kid must be witnessed by the log — and every key
/// the log says is ACTIVE must be in the JWKS.
///
/// The second half catches key-log TAIL TRUNCATION. The JWKS is derived from
/// active keys, so a bundle whose `evd.key.revoked` entry has been deleted
/// carries a log saying the key is live beside a JWKS that omits it. Entry
/// density is computed over the key entries PRESENT, so [1, 2] reads dense once
/// entry 3 is gone: dropping `evd.key.rotated` or `evd.key.created` was caught,
/// dropping `evd.key.revoked` was not, and the golden `post_revocation_forgery`
/// fixture must be rejected in both engines.
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
    // `bundle.origin` is outside every checkpoint signature but is consumed by
    // reports, certificates, and relying-party trust lookup. It must exactly
    // name the signed target and the complete signed checkpoint history.
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
    // Verify EACH signature's OWN bytes, mirroring Python verify_envelope's
    // every-signature scan. Delegating to env_signed_by (first keyid match)
    // let a duplicate keyid with arbitrary bytes ride on the first valid
    // signature — Rust accepted a bundle Python rejects (parity divergence,
    // adversarial review 2026-08-08).
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

fn check_entry(e: &Value, kl: &KeyLog, size: u64, root: &[u8], covers: &[(u64, i64)]) -> bool {
    let env = &e["envelope"];
    let Some(payload) = payload_of(env) else { return false };
    let Some(body) = canonical_body(&payload) else { return false };
    // schema
    if body.get("schema").and_then(|v| v.as_str()) != Some("evd/receipt/v1") {
        return false;
    }
    // every signature valid + key valid at ts_server
    let ts_server = body.get("ts_server").and_then(|v| v.as_str()).unwrap_or("");
    let ts_client = body.get("ts_client").and_then(|v| v.as_str()).unwrap_or("");
    if !canonical_utc(ts_client) || !canonical_utc(ts_server) {
        return false;
    }
    // ts_server may not postdate the FIRST chain checkpoint whose tree_size
    // covers this leaf by more than RECEIPT_CHECKPOINT_SKEW_S — the same rule,
    // boundary and skew as verify/verifier.py::_check_entries. The chain's
    // monotone tree_size is enforced by check_checkpoint_chain; a chain that
    // fails there fails the bundle regardless of what partition_point saw
    // here. A leaf no presented checkpoint covers keeps its prior behavior.
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

/// Did this bundle arrive carrying what it was exported to carry?
///
/// Everything in a bundle is signed except the bundle. Entries are individually
/// signed and individually proven included, so deleting one leaves every
/// remaining signature valid, every inclusion proof valid, and the same target
/// root. Removing a force-included `evd.finding.raised` must be rejected in
/// both engines.
///
/// ABSENT (or null) means the bundle makes no completeness claim, which stays
/// valid: bundles predate the manifest, and a key-less replica exports honestly
/// without one. Python carries that third state in its report; here a bool is
/// enough, and the asymmetry is deliberate — the same shape anchors already use.
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

/// PRESENT means it must hold: signed by this target checkpoint's non-recorder
/// issuer (never `bundle["jwks"]`), at that checkpoint's signed timestamp,
/// and SET-EQUAL to the receipts actually carried, so neither removal nor
/// injection survives.
///
/// THREE states, not two (verify/verifier.py::_check_export_manifest): None is
/// "no completeness claim carried" — bundles predate the manifest and a
/// key-less replica export (scripts/restore_check.py) cannot sign one — and it
/// is NOT failure. Only `Some(false)` gates the bundle verdict.
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

/// Everything about the ENTRIES a bundle carries: each one individually, the
/// signed manifest saying which ones there should be, and per-agent sequence
/// uniqueness. Split out of `check_checkpoints_and_entries` to keep that
/// function within the §0.2·3a complexity ceiling.
fn check_entry_set(bundle: &Value, entries: &[Value], target: &Value, chain: &[Value], kl: &KeyLog, trust: Option<&Value>, facts: &mut BundleFacts) -> bool {
    // seq GAPS are legitimate (subset exports); a duplicate (agent_id, seq) is
    // always forgery or corruption. The manifest answer is recorded BEFORE the
    // conjunction so a bundle that fails elsewhere still reports the same
    // tri-state Python reports — `_check_export_manifest` runs unconditionally.
    facts.complete = check_export_manifest(bundle, entries, target, kl);
    check_entries(entries, target, chain, kl, trust, facts) && facts.complete != Some(false) && check_seq_uniqueness(entries)
}

/// (tree_size, latest admissible ts_server in epoch µs) per chain checkpoint.
/// None when any checkpoint lacks a usable tree_size or canonical ts — Python
/// refuses such a chain at parse (`_check_chain`), so failing the entry set
/// here lands both engines on the same NOT VERIFIED.
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
    for e in entries {
        if !check_entry(e, kl, size, &root, &covers) {
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
    // `_rel_*` was exempt here too, on a false premise: it is the
    // per-relationship SEQUENCE COUNTER id, never a receipt agent_id. The
    // exemption shielded forged lineage and protected nothing honest.
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
    // anti-laundering: `born` asserts no prior history so it must
    // sit at seq 1 (an agent with earlier activity can't put born
    // there). `adopted` is established at its first-OBSERVED seq
    // and legitimately sits above seq 1 — only born is constrained.
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

/// A carried anchor/TST time must be canonical and cannot predate its signed checkpoint.
///
/// `block_ts` and `gen_time` have equal standing as independent time. Their
/// record member is unsigned, but the checkpoint's own `ts` is signed, so an
/// earlier claim is refutable from the bytes alone. A malformed claimed time is
/// a malformed carried claim, never an exemption from the ordering rule.
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

fn check_tst_records(records: &Value, checkpoints: &CheckpointFacts, roots: Option<&str>, facts: &mut BundleFacts) -> bool {
    if !check_bound_records(records, &["checkpoint_body_hash", "token_der_b64", "tsa_url", "gen_time", "cert_chain_pem", "qualified"], "gen_time", checkpoints) {
        return false;
    }
    let Some(items) = records.as_array() else { return false };
    for record in items {
        let (Some(body_hash), Some(token_b64), Some(displayed), Some(chain)) = (record.get("checkpoint_body_hash").and_then(Value::as_str), record.get("token_der_b64").and_then(Value::as_str), record.get("gen_time").and_then(Value::as_str), record.get("cert_chain_pem").and_then(Value::as_str)) else { return false };
        let Ok(token) = B64.decode(token_b64) else { return false };
        let Some((actual, trusted)) = crate::tsa::verified_tst(&token, body_hash, chain, roots) else { return false };
        if actual.to_date_time().to_string() != displayed {
            return false;
        }
        if trusted {
            facts.trusted_tst_checkpoints.push(body_hash.to_string());
        }
    }
    true
}

fn check_attestation_records(bundle: &Value, checkpoints: &CheckpointFacts, trust: Option<&Value>, facts: &mut BundleFacts) -> bool {
    // 7. timestamp records (if present): full RFC 3161 CMS validation plus
    // checkpoint binding and an exact verifier-derived genTime match. A
    // structurally bound but unverified token is not time evidence and cannot
    // feed action::independent_ts_map.
    // Null compares equal to missing, the same `.get()` semantics
    // `check_input_echo` already documents — a producer emitting null for an
    // empty optional is not making a claim about timestamps or anchors. Any
    // OTHER non-list value IS a claim, and a malformed one (parity with
    // verify/verifier.py; tests/test_engine_parity.py).
    if let Some(tsts) = bundle.get("tst_records").filter(|v| !v.is_null()) {
        let roots = trust::tsa_roots_pem(trust);
        if !check_tst_records(tsts, checkpoints, roots.as_deref(), facts) {
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
    // Never filter malformed links out of a presented history: Python rejects
    // every malformed entry, and silently skipping one can create a false
    // genesis or hide a broken predecessor.
    let chain: Vec<Value> = match chain_entries.iter().map(|entry| entry.get("checkpoint").cloned()).collect() {
        Some(chain) => chain,
        None => return false,
    };
    if chain.is_empty() {
        return false;
    }
    // The completeness tri-state settles HERE, at the point verify/verifier.py
    // settles it: past the target and a structurally intact chain,
    // `_check_export_manifest` runs whatever else fails. Deferring it to the
    // tail would make a certificate over a chain-invalid bundle report
    // `export_complete: null` where Python reports the real answer.
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

    // 6. lineage (birthtag-v1): absence is fine; forgery is fatal. Mirrors
    // the Python verifier's hard-fail rules exactly (advisory notes are a
    // Python-report concern; the boolean contract here only encodes fatality).
    if !check_lineage(entries) {
        return false;
    }

    let Some(checkpoints) = checkpoint_facts(&chain) else { return false };
    if !check_attestation_records(bundle, &checkpoints, trust, facts) {
        return false;
    }
    facts.chain_sizes = checkpoints.into_iter().map(|(hash, (_ts, size))| (hash, size)).collect();
    true
}

fn str_field(v: &Value, key: &str) -> Option<String> {
    Some(v.get(key)?.as_str()?.to_string())
}

type DisclosureFields = (String, String, String, Vec<u8>, Vec<u8>); // (receipt_hash, field, domain, nonce, payload)

fn disclosure_fields(pkg: &Value) -> Option<DisclosureFields> {
    // any missing or undecodable member makes the whole package malformed
    if str_field(pkg, "schema")? != DISCLOSURE_SCHEMA {
        return None;
    }
    let nonce = hex_to_bytes(&str_field(pkg, "nonce_hex")?)?;
    let payload = B64.decode(str_field(pkg, "payload_b64")?).ok()?;
    Some((str_field(pkg, "receipt_hash")?, str_field(pkg, "field")?, str_field(pkg, "domain")?, nonce, payload))
}

fn disclosure_commitment(domain: &str, payload: &[u8], nonce: &[u8]) -> Option<String> {
    // core/canonical.py commitment(): an unscoped domain or a weak nonce
    // silently destroys the privacy model, so it never verifies.
    if !domain.starts_with(DOMAIN_PREFIX) || nonce.len() < 16 {
        return None;
    }
    let mut h = Sha256::new();
    h.update(domain.as_bytes());
    h.update([0x00u8]);
    h.update(nonce);
    h.update([0x00u8]);
    h.update(payload);
    Some(hex(&h.finalize()))
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
pub fn verify_disclosure(pkg: &Value, bundle: &Value) -> bool {
    let (rh, field, domain, nonce, payload) = match disclosure_fields(pkg) {
        Some(t) => t,
        None => return false,
    };
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
        return disclosure_commitment(&domain, &payload, &nonce).as_deref() == Some(&expected);
    }
    false
}

/// Verify an evd/bundle/v1 document. Returns true iff VERIFIED.
pub fn verify_bundle(bundle: &Value) -> bool {
    verify_bundle_report(bundle).0
}

/// E3 leg (B29.1) per SPEC/receipt-v1 §5 (amended) — mirror of
/// `verify/verifier.py::_recorder_attested`: the co-signature bytes must
/// verify under a relying-party-named recorder key (a NON-ISSUER log kid,
/// beside an issuer signature); log registration is necessary, never
/// sufficient. Under the gate a keyid resolves to at most one verifying key,
/// so equality with the supplied key reuses the completed signature check.
/// This helper is called only after the full entry gate succeeds.
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

/// B29 evidence-level facts (SPEC/log-v1 §4 award law). VERDICT-NEUTRAL: a
/// NOT VERIFIED bundle earns nothing. Returns the facts verify/verifier.py
/// exposes on its report, pinned across engines by expected_evidence.json.
pub fn verify_bundle_levels(bundle: &Value, trust: Option<&Value>) -> Value {
    let facts = verify_bundle_facts(bundle, trust);
    serde_json::json!({"ok": facts.ok, "recorder_attested": facts.recorder_attested, "trusted_tst_checkpoints": facts.trusted_tst_checkpoints, "chain_sizes": facts.chain_sizes})
}

/// (VERIFIED, export-completeness tri-state). The certificate layer computed
/// the second value and threw it away, so a certificate consumer read a bare
/// "VERIFIED" over a bundle whose entries may have been deleted after export
/// while a bundle consumer read "VERIFIED (completeness unproven)". `None` —
/// no manifest carried, or the run never reached the manifest — is NOT
/// failure, and nothing in either engine gates on it.
pub(crate) fn verify_bundle_report(bundle: &Value) -> (bool, Option<bool>) {
    let facts = verify_bundle_facts(bundle, None);
    (facts.ok, facts.complete)
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
    if !facts.ok {
        facts.recorder_attested.clear();
        facts.trusted_tst_checkpoints.clear();
        facts.chain_sizes.clear();
    }
    facts
}

#[cfg(any(test, feature = "wasm"))]
const BROWSER_BUNDLE_RESULT_SCHEMA: &str = "evd/browser-bundle-verification-result/v2";

#[cfg(any(test, feature = "wasm"))]
fn browser_bundle_result(verdict: &str, bundle_digest: Option<String>, error: Option<&str>) -> String {
    serde_json::json!({
        "schema": BROWSER_BUNDLE_RESULT_SCHEMA,
        "verdict": verdict,
        "bundle_digest": bundle_digest,
        "error": error,
    })
    .to_string()
}

#[cfg(any(test, feature = "wasm"))]
fn browser_bundle_verification_result(json: &str) -> String {
    // Preserve the verifier's established over-limit verdict without parsing
    // or allocating another copy of attacker-controlled input.
    if json.len() > MAX_BUNDLE_BYTES {
        return browser_bundle_result("NOT_VERIFIED", None, None);
    }
    let Some(bundle) = trust::strict_json(json.as_bytes()) else {
        return browser_bundle_result("ERROR", None, Some("INVALID_JSON"));
    };
    if !verify_bundle(&bundle) {
        return browser_bundle_result("NOT_VERIFIED", None, None);
    }
    // Cite the exact verified bundle semantics, independent of JSON whitespace.
    // Never surface a digest for bytes that did not pass the full verifier.
    match jcs::canonical_checked(&bundle) {
        Some(bytes) => browser_bundle_result("VERIFIED", Some(hex(&sha256(&bytes))), None),
        None => browser_bundle_result("NOT_VERIFIED", None, None),
    }
}

// -- WASM binding (feature-gated; native build never pulls wasm-bindgen) -----
#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// Verify a bundle and return the versioned browser result JSON. A
    /// VERIFIED result alone carries SHA-256 of the JCS-canonical full bundle.
    #[wasm_bindgen]
    pub fn verify_bundle_json(json: &str) -> String {
        super::browser_bundle_verification_result(json)
    }
}

#[cfg(test)]
#[path = "../tests/internal/lib_tests.rs"]
mod tests;
