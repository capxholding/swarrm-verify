// Apache-2.0 (public verifier repo)
//! Independent Rust verifier for evd/bundle/v1.
//!
//! A SECOND implementation, on purpose: it shares no code with the Python
//! verifier, so agreement on the shared golden suite (tests/golden/) is real
//! evidence that the format is unambiguous. Verify-only, offline, no network.

pub mod action;
#[allow(dead_code)] // canonical_from_json: golden-phase seam; tests use #[path]
mod cbor;
pub mod certificate; // B24.3 — verify_certificate_cbor doubles as the wasm export
#[allow(dead_code)] // B25 W1 COSE adapter: consumed by later SCITT weeks and the golden test
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
const DOMAIN_PREFIX: &str = "evd/v1/";

// H5 resource caps — IDENTICAL to verify/verifier.py: a bundle over any cap
// is NOT VERIFIED by BOTH implementations, so golden agreement stays pinned.
// All caps sit far above every legitimate bundle.
#[allow(dead_code)] // enforced at byte entry points (verify_bundle_json/wasm)
const MAX_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 200_000;
const MAX_INCLUSION_PROOF_LEN: usize = 64;
const MAX_CHECKPOINT_CHAIN_LEN: usize = 100_000;
const MAX_SIGNATURES_PER_ENVELOPE: usize = 8;
const MAX_JSON_DEPTH: i64 = jcs::MAX_DEPTH; // 64 — whole bundle shares the JCS cap

fn depth_exceeds(v: &Value, limit: i64) -> bool {
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

/// H5 resource caps, checked BEFORE any cryptographic work — same caps,
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
    !depth_exceeds(bundle, MAX_JSON_DEPTH)
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
    // here and were rejected by Python, all at jwks.keys[0].kid (owner audit
    // 2026-08-05). A carried member that is not the shape it claims is
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

pub(crate) fn env_signed_by(env: &Value, kid: &str, pubkey: &[u8; 32]) -> bool {
    let Some(ptype) = env.get("payloadType").and_then(|v| v.as_str()) else { return false };
    let payload = match env.get("payload").and_then(|v| v.as_str()) {
        Some(p) => match B64.decode(p) {
            Ok(b) => b,
            Err(_) => return false,
        },
        None => return false,
    };
    let msg = pae(ptype, &payload);
    if let Some(sigs) = env.get("signatures").and_then(|v| v.as_array()) {
        for s in sigs {
            if s.get("keyid").and_then(|v| v.as_str()) == Some(kid) {
                if let Some(sig_b64) = s.get("sig").and_then(|v| v.as_str()) {
                    if let Ok(sig) = B64.decode(sig_b64) {
                        return ed25519_verify(pubkey, &msg, &sig);
                    }
                }
            }
        }
    }
    false
}

fn payload_of(env: &Value) -> Option<Vec<u8>> {
    B64.decode(env.get("payload")?.as_str()?).ok()
}

pub(crate) fn receipt_hash_hex(env: &Value) -> Option<String> {
    // receipt_hash = sha256 of the decoded DSSE payload bytes (receipt-v1)
    let b64 = env.get("payload")?.as_str()?;
    let bytes = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    Some(hex(&sha256(&bytes)))
}

pub(crate) fn body_of(env: &Value) -> Option<Value> {
    serde_json::from_slice(&payload_of(env)?).ok()
}

fn decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0, |n, c| c.is_ascii_digit().then_some(n * 10 + u32::from(*c - b'0')))
}

fn canonical_utc(s: &str) -> bool {
    let b = s.as_bytes();
    if !(b.len() == 20 || (22..=27).contains(&b.len())) || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' || *b.last().unwrap() != b'Z' || (b.len() > 20 && (b[19] != b'.' || decimal(&b[20..b.len() - 1]).is_none())) {
        return false;
    }
    let (Some(y), Some(m), Some(d), Some(h), Some(n), Some(sec)) = (decimal(&b[..4]), decimal(&b[5..7]), decimal(&b[8..10]), decimal(&b[11..13]), decimal(&b[14..16]), decimal(&b[17..19])) else { return false };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = [0, 31, 28 + u32::from(leap), 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    y > 0 && (1..=12).contains(&m) && d > 0 && d <= days[m as usize] && h < 24 && n < 60 && sec < 60
}

fn forbidden_managed_edge_cosign(body: &Value, env: &Value) -> bool {
    let multi = env.get("signatures").and_then(Value::as_array).is_some_and(|s| s.len() > 1);
    let agent = body.get("agent_id").and_then(Value::as_str).unwrap_or("");
    let action = body.get("action_type").and_then(Value::as_str).unwrap_or("");
    multi && (agent.starts_with('_') || ["evd.key.", "authority.", "source.", "action.", "lineage.", "node.", "evd.finding.", "evd.gap.", "evd.coverage.", "registration."].iter().any(|prefix| action.starts_with(prefix)))
}

/// The trust root of the key-log replay: all keys (incl. revoked) + revoke ts.
pub(crate) struct KeyLog {
    pub(crate) keys: BTreeMap<String, [u8; 32]>,
    pub(crate) revoked_at: BTreeMap<String, String>,
    non_issuer: BTreeSet<String>,
    pub(crate) ok: bool,
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

fn key_active(keys: &BTreeMap<String, [u8; 32]>, revoked: &BTreeMap<String, String>, kid: &str, at: &str) -> bool {
    keys.contains_key(kid) && kid_valid_at(kid, at, revoked)
}

/// Some envelope signature is by a key the log had active at `ts` AND that
/// signature actually verifies. With `issuer_only`, keys the log has marked
/// non-issuer are excluded — one predicate, so the "active key vouched" and
/// "an ISSUER vouched" arms of the key-created sponsorship rule below can
/// never drift apart on what "active and signed" means.
fn signed_by_active_key(env: &Value, kl: &KeyLog, ts: &str, issuer_only: bool) -> bool {
    env.get("signatures").and_then(Value::as_array).is_some_and(|ss| {
        ss.iter().any(|s| {
            let kid = s.get("keyid").and_then(Value::as_str).unwrap_or("");
            (!issuer_only || !kl.non_issuer.contains(kid)) && key_active(&kl.keys, &kl.revoked_at, kid, ts) && env_signed_by(env, kid, &kl.keys[kid])
        })
    })
}

fn apply_key_created(kl: &mut KeyLog, pos: usize, env: &Value, ctx: &Value, ts: &str, kid: String, material: [u8; 32]) -> bool {
    let issuer_sponsored = if pos == 0 {
        if !env_signed_by(env, &kid, &material) {
            return false;
        }
        true
    } else {
        // sponsored: some active key signed it
        if !signed_by_active_key(env, kl, ts, false) {
            return false;
        }
        signed_by_active_key(env, kl, ts, true)
    };
    kl.keys.insert(kid.clone(), material);
    if ctx.get("role").is_some() || !issuer_sponsored {
        kl.non_issuer.insert(kid);
    }
    true
}

fn apply_key_rotated(kl: &mut KeyLog, env: &Value, ctx: &Value, jwk: &Value, ts: &str, kid: String, material: [u8; 32]) -> bool {
    let prev_kid = ctx.get("prev_kid").and_then(|v| v.as_str()).unwrap_or("");
    let continuity = ctx.get("continuity_sig").and_then(|v| v.as_str());
    if prev_kid.is_empty() || continuity.is_none() {
        return false;
    }
    if !key_active(&kl.keys, &kl.revoked_at, prev_kid, ts) {
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
    kl.keys.insert(kid.clone(), material);
    if kl.non_issuer.contains(prev_kid) || ctx.get("role").is_some() {
        kl.non_issuer.insert(kid);
    }
    true
}

fn apply_key_revoked(kl: &mut KeyLog, env: &Value, ctx: &Value, ts: &str, kid: String) -> bool {
    if !kl.keys.contains_key(&kid) {
        return false;
    }
    if !signed_by_active_key(env, kl, ts, false) {
        return false;
    }
    let eff = ctx.get("effective_ts").and_then(|v| v.as_str()).unwrap_or("");
    if !canonical_utc(eff) {
        return false;
    }
    kl.revoked_at.insert(kid, eff.to_string());
    true
}

pub(crate) fn replay_key_log(entries: &[Value]) -> KeyLog {
    let mut kl = KeyLog { keys: BTreeMap::new(), revoked_at: BTreeMap::new(), non_issuer: BTreeSet::new(), ok: false };
    let key_entries = collect_key_entries(entries);
    if !key_entries_well_formed(&key_entries) {
        return kl;
    }

    for (pos, (_idx, env, body)) in key_entries.iter().enumerate() {
        let action = body.get("action_type").and_then(|v| v.as_str()).unwrap_or("");
        let ctx = body.get("context").cloned().unwrap_or(Value::Null);
        let jwk = ctx.get("jwk").cloned().unwrap_or(Value::Null);
        let ts = body.get("ts_server").and_then(|v| v.as_str()).unwrap_or("");
        if !canonical_utc(ts) || !ctx.get("effective_ts").and_then(Value::as_str).is_some_and(canonical_utc) {
            return kl;
        }
        let (material, kid) = match key_from_jwk(&jwk) {
            Some(m) => m,
            None => return kl,
        };
        let applied = match action {
            "evd.key.created" => apply_key_created(&mut kl, pos, env, &ctx, ts, kid, material),
            "evd.key.rotated" => apply_key_rotated(&mut kl, env, &ctx, &jwk, ts, kid, material),
            "evd.key.revoked" => apply_key_revoked(&mut kl, env, &ctx, ts, kid),
            _ => return kl,
        };
        if !applied {
            return kl;
        }
    }
    kl.ok = true;
    kl
}

pub(crate) fn kid_valid_at(kid: &str, at: &str, revoked_at: &BTreeMap<String, String>) -> bool {
    canonical_utc(at) && revoked_at.get(kid).map(|r| canonical_utc(r) && at <= r.as_str()).unwrap_or(true)
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
/// so a proof with junk spliced into it was evaluated as a SHORTER proof
/// instead of being rejected: the audit lengthened a valid inclusion proof with
/// `"zz"` and verify-rs answered on the remaining siblings while Python's
/// `bytes.fromhex` raised and the bundle was NOT VERIFIED (owner audit
/// 2026-08-05). ABSENT (or null) still means an empty proof — the no-claim
/// shape, which only ever verifies a one-leaf tree — but a carried member that
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
/// fixture flipped to VERIFIED in both engines (owner audit 2026-08-05).
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
    kl.keys.keys().all(|kid| kl.revoked_at.contains_key(kid) || listed.contains(kid))
}

fn check_target_checkpoint(target: &Value, kl: &KeyLog) -> bool {
    if !verify_checkpoint_sig(target, &kl.keys) {
        return false;
    }
    let target_ts = target.get("body").and_then(|b| b.get("ts")).and_then(|v| v.as_str()).unwrap_or("");
    let target_kid = target.get("kid").and_then(|v| v.as_str()).unwrap_or("");
    kid_valid_at(target_kid, target_ts, &kl.revoked_at)
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

fn check_chain_link(prev: &Value, cp: &Value, entry: &Value) -> bool {
    let Some(prev_bh) = checkpoint_body_hash(prev) else { return false };
    let cur_prev = cp.get("body").and_then(|b| b.get("prev_hash")).and_then(|v| v.as_str()).unwrap_or("");
    if cur_prev != prev_bh {
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

fn check_checkpoint_chain(chain: &[Value], chain_entries: &[Value], kl: &KeyLog) -> bool {
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
        let kid = cp.get("kid").and_then(|v| v.as_str()).unwrap_or("");
        if !kid_valid_at(kid, ts, &kl.revoked_at) {
            return false;
        }
        if i > 0 && !check_chain_link(&chain[i - 1], cp, &chain_entries[i]) {
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

fn check_entry_sigs(env: &Value, sigs: &[Value], ts_server: &str, kl: &KeyLog) -> bool {
    for s in sigs {
        let kid = s.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
        let Some(pubkey) = kl.keys.get(kid) else { return false };
        if !env_signed_by(env, kid, pubkey) {
            return false;
        }
        if !kid_valid_at(kid, ts_server, &kl.revoked_at) {
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

fn check_entry(e: &Value, kl: &KeyLog, size: u64, root: &[u8]) -> bool {
    let env = &e["envelope"];
    let Some(payload) = payload_of(env) else { return false };
    let body: Value = match serde_json::from_slice(&payload) {
        Ok(b) => b,
        Err(_) => return false,
    };
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
    let sigs = match env.get("signatures").and_then(|v| v.as_array()) {
        Some(s) if !s.is_empty() => s,
        _ => return false,
    };
    if env.get("payloadType").and_then(|v| v.as_str()) != Some(RECEIPT_TYPE) {
        return false;
    }
    if !check_entry_sigs(env, sigs, ts_server, kl) {
        return false;
    }
    check_entry_inclusion(e, &payload, size, root)
}

/// Did this bundle arrive carrying what it was exported to carry?
///
/// Everything in a bundle is signed except the bundle. Entries are individually
/// signed and individually proven included, so deleting one leaves every
/// remaining signature valid, every inclusion proof valid, and the same target
/// root — a real force-included `evd.finding.raised` was removed in flight with
/// VERDICT: VERIFIED and exit 0 in BOTH engines (owner audit 2026-08-05).
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
    if kl.non_issuer.contains(kid) || !kid_valid_at(kid, &ts, &kl.revoked_at) {
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
fn check_entry_set(bundle: &Value, entries: &[Value], target: &Value, kl: &KeyLog, complete: &mut Option<bool>) -> bool {
    // seq GAPS are legitimate (subset exports); a duplicate (agent_id, seq) is
    // always forgery or corruption. The manifest answer is recorded BEFORE the
    // conjunction so a bundle that fails elsewhere still reports the same
    // tri-state Python reports — `_check_export_manifest` runs unconditionally.
    *complete = check_export_manifest(bundle, entries, target, kl);
    check_entries(entries, target, kl) && *complete != Some(false) && check_seq_uniqueness(entries)
}

fn check_entries(entries: &[Value], target: &Value, kl: &KeyLog) -> bool {
    let size = target.get("body").and_then(|b| b.get("tree_size")).and_then(|v| v.as_u64()).unwrap_or(0);
    let root_hex = target.get("body").and_then(|b| b.get("root_hash")).and_then(|v| v.as_str()).unwrap_or("");
    let Some(root) = hex_to_bytes(root_hex) else { return false };
    for e in entries {
        if !check_entry(e, kl, size, &root) {
            return false;
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

/// A checkpoint cannot be anchored before it was signed.
///
/// `block_ts` is an unsigned string in an additive bundle member, never checked
/// against a chain offline, yet authority-v1 §4 consumed it as verified time.
/// Backdating it flipped an intent recorded 17 days AFTER its grant was revoked
/// to authority VERIFIED (owner audit 2026-08-05). The checkpoint's own `ts` IS
/// signed, so an earlier claim is refutable from the bytes alone. A malformed
/// `block_ts` is not an ordering violation — §4 already ignores it.
fn anchor_not_before_checkpoint(rec: &Value, signed_ts: Option<&str>) -> bool {
    let signed = Value::String(signed_ts.unwrap_or_default().to_string());
    let (Some(anchored), Some(signed)) = (crate::action::nts(rec.get("block_ts").unwrap_or(&Value::Null)), crate::action::nts(&signed)) else { return true };
    anchored >= signed
}

fn bound_record_ok(rec: &Value, required: &[&str], chain_ts: &BTreeMap<String, String>) -> bool {
    let Some(obj) = rec.as_object() else { return false };
    if required.iter().any(|f| !obj.contains_key(*f)) {
        return false;
    }
    let bh = rec.get("checkpoint_body_hash").and_then(|v| v.as_str()).unwrap_or("");
    let Some(signed) = chain_ts.get(bh) else {
        return false;
    }; // not a checkpoint in this chain
    !obj.contains_key("block_ts") || anchor_not_before_checkpoint(rec, Some(signed.as_str()))
}

fn check_bound_records(records: &Value, required: &[&str], chain: &[Value]) -> bool {
    let Some(arr) = records.as_array() else { return false };
    let chain_ts: BTreeMap<String, String> = chain
        .iter()
        .filter_map(|c| {
            let h = checkpoint_body_hash(c)?;
            let ts = c.get("body")?.get("ts")?.as_str().unwrap_or("").to_string();
            Some((h, ts))
        })
        .collect();
    arr.iter().all(|rec| bound_record_ok(rec, required, &chain_ts))
}

fn check_tst_records(records: &Value, chain: &[Value]) -> bool {
    if !check_bound_records(records, &["checkpoint_body_hash", "token_der_b64", "tsa_url", "gen_time", "cert_chain_pem", "qualified"], chain) {
        return false;
    }
    records.as_array().is_some_and(|items| {
        items.iter().all(|record| {
            let (Some(body_hash), Some(token_b64), Some(displayed_time), Some(chain)) = (record.get("checkpoint_body_hash").and_then(Value::as_str), record.get("token_der_b64").and_then(Value::as_str), record.get("gen_time").and_then(Value::as_str), record.get("cert_chain_pem").and_then(Value::as_str)) else { return false };
            let Ok(token) = B64.decode(token_b64) else { return false };
            crate::tsa::verify_tst_gen_time(&token, body_hash, chain).is_some_and(|actual_time| actual_time == displayed_time)
        })
    })
}

fn check_attestation_records(bundle: &Value, chain: &[Value]) -> bool {
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
        if !check_tst_records(tsts, chain) {
            return false;
        }
    }

    // 8. anchor records (if present): each must bind to a chain checkpoint
    if let Some(anchors) = bundle.get("anchor_records").filter(|v| !v.is_null()) {
        if !check_bound_records(anchors, &["checkpoint_body_hash", "chain_id", "tx_hash", "block_number", "block_ts", "contract"], chain) {
            return false;
        }
    }
    true
}

fn check_checkpoints_and_entries(bundle: &Value, entries: &[Value], kl: &KeyLog, complete: &mut Option<bool>) -> bool {
    // 2. target checkpoint
    let Some(target) = bundle.get("target_checkpoint") else { return false };
    if !check_target_checkpoint(target, kl) {
        return false;
    }

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
    if !check_entry_set(bundle, entries, target, kl, complete) {
        return false;
    }
    if !check_checkpoint_chain(&chain, chain_entries, kl) {
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

    check_attestation_records(bundle, &chain)
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
    let body: Value = serde_json::from_slice(raw).ok()?;
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

/// (VERIFIED, export-completeness tri-state). The certificate layer computed
/// the second value and threw it away, so a certificate consumer read a bare
/// "VERIFIED" over a bundle whose entries may have been deleted after export
/// while a bundle consumer read "VERIFIED (completeness unproven)". `None` —
/// no manifest carried, or the run never reached the manifest — is NOT
/// failure, and nothing in either engine gates on it.
pub(crate) fn verify_bundle_report(bundle: &Value) -> (bool, Option<bool>) {
    let mut complete = None;
    if bundle.get("schema").and_then(|v| v.as_str()) != Some("evd/bundle/v1") {
        return (false, complete);
    }
    // H5 resource caps (parse phase) — over-cap is NOT VERIFIED, never a panic
    if !within_caps(bundle) {
        return (false, complete);
    }
    let entries: Vec<Value> = bundle.get("entries").and_then(|v| v.as_array()).cloned().unwrap_or_default();
    if entries.is_empty() {
        return (false, complete);
    }
    if entries.iter().any(|e| {
        let env = &e["envelope"];
        body_of(env).is_some_and(|body| forbidden_managed_edge_cosign(&body, env))
    }) {
        return (false, complete);
    }

    // 0. key log replay
    let kl = replay_key_log(&entries);
    if !kl.ok {
        return (false, complete);
    }

    // 1. jwks agrees with the log
    if !check_jwks_match_log(bundle, &kl) {
        return (false, complete);
    }

    let ok = check_checkpoints_and_entries(bundle, &entries, &kl, &mut complete);
    (ok, complete)
}

// -- WASM binding (feature-gated; native build never pulls wasm-bindgen) -----
#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// Verify a bundle passed as a JSON string. Returns "VERIFIED" /
    /// "NOT VERIFIED" / "ERROR: <reason>". For the file-drop static page.
    #[wasm_bindgen]
    pub fn verify_bundle_json(json: &str) -> String {
        // H5 byte cap: this entry point receives raw bytes, so the size cap
        // is enforced BEFORE parsing (identical cap documented in verifier.py)
        if json.len() > super::MAX_BUNDLE_BYTES {
            return "NOT VERIFIED".to_string();
        }
        match serde_json::from_str::<serde_json::Value>(json) {
            Ok(v) => {
                if super::verify_bundle(&v) {
                    "VERIFIED".to_string()
                } else {
                    "NOT VERIFIED".to_string()
                }
            }
            Err(e) => format!("ERROR: {e}"),
        }
    }
}
