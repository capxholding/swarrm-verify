// Apache-2.0 (public verifier repo)
//! Independent Rust verifier for evd/bundle/v1.
//!
//! A SECOND implementation, on purpose: it shares no code with the Python
//! verifier, so agreement on the shared golden suite (tests/golden/) is real
//! evidence that the format is unambiguous. Verify-only, offline, no network.

pub mod action;
pub(crate) mod jcs;
mod merkle;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const RECEIPT_TYPE: &str = "application/vnd.evd.receipt.v1+json";
const CHECKPOINT_TYPE: &str = "application/vnd.evd.checkpoint.v1+json";
const DISCLOSURE_SCHEMA: &str = "evd/disclosure/v1";
const DOMAIN_PREFIX: &str = "evd/v1/";

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
    let pad = (4 - s.len() % 4) % 4;
    let s = format!("{}{}", s, "=".repeat(pad));
    base64::engine::general_purpose::URL_SAFE.decode(s).ok()
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
    if let Some(claimed) = jwk.get("kid").and_then(|v| v.as_str()) {
        if claimed != kid {
            return None;
        }
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
    let ptype = match env.get("payloadType").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return false,
    };
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

/// The trust root of the key-log replay: all keys (incl. revoked) + revoke ts.
pub(crate) struct KeyLog {
    pub(crate) keys: BTreeMap<String, [u8; 32]>,
    pub(crate) revoked_at: BTreeMap<String, String>,
    pub(crate) ok: bool,
}

fn collect_key_entries(entries: &[Value]) -> Vec<(u64, &Value, Value)> {
    // collect key entries (agent_id=_system, action evd.key.*) with leaf index
    let mut key_entries: Vec<(u64, &Value, Value)> = Vec::new();
    for e in entries {
        if let Some(body) = body_of(&e["envelope"]) {
            let is_sys = body.get("agent_id").and_then(|v| v.as_str()) == Some("_system");
            let is_key = body
                .get("action_type")
                .and_then(|v| v.as_str())
                .map(|a| a.starts_with("evd.key."))
                .unwrap_or(false);
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
    if key_entries[0].0 != 0
        || key_entries[0].2.get("action_type").and_then(|v| v.as_str()) != Some("evd.key.created")
    {
        return false;
    }
    // dense _system sequence
    let seqs: Vec<i64> = key_entries
        .iter()
        .map(|t| t.2.get("seq").and_then(|v| v.as_i64()).unwrap_or(-1))
        .collect();
    for (i, s) in seqs.iter().enumerate() {
        if *s != (i as i64) + 1 {
            return false;
        }
    }
    true
}

fn key_active(
    keys: &BTreeMap<String, [u8; 32]>,
    revoked: &BTreeMap<String, String>,
    kid: &str,
    at: &str,
) -> bool {
    keys.contains_key(kid) && revoked.get(kid).map(|r| at <= r.as_str()).unwrap_or(true)
}

fn signed_by_active_key(env: &Value, kl: &KeyLog, ts: &str) -> bool {
    env.get("signatures")
        .and_then(|v| v.as_array())
        .map(|ss| {
            ss.iter().any(|s| {
                let sk = s.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
                key_active(&kl.keys, &kl.revoked_at, sk, ts)
                    && env_signed_by(env, sk, &kl.keys[sk])
            })
        })
        .unwrap_or(false)
}

fn apply_key_created(
    kl: &mut KeyLog,
    pos: usize,
    env: &Value,
    ts: &str,
    kid: String,
    material: [u8; 32],
) -> bool {
    if pos == 0 {
        if !env_signed_by(env, &kid, &material) {
            return false;
        }
    } else {
        // sponsored: some active key signed it
        if !signed_by_active_key(env, kl, ts) {
            return false;
        }
    }
    kl.keys.insert(kid, material);
    true
}

fn apply_key_rotated(
    kl: &mut KeyLog,
    env: &Value,
    ctx: &Value,
    jwk: &Value,
    ts: &str,
    kid: String,
    material: [u8; 32],
) -> bool {
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
    let jwk_canon = jcs::canonical(jwk);
    let cont = match B64.decode(continuity.unwrap()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    if !ed25519_verify(&kl.keys[prev_kid], &jwk_canon, &cont) {
        return false;
    }
    kl.keys.insert(kid, material);
    true
}

fn apply_key_revoked(kl: &mut KeyLog, env: &Value, ctx: &Value, ts: &str, kid: String) -> bool {
    if !kl.keys.contains_key(&kid) {
        return false;
    }
    if !signed_by_active_key(env, kl, ts) {
        return false;
    }
    let eff = ctx
        .get("effective_ts")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    kl.revoked_at.insert(kid, eff.to_string());
    true
}

pub(crate) fn replay_key_log(entries: &[Value]) -> KeyLog {
    let mut kl = KeyLog {
        keys: BTreeMap::new(),
        revoked_at: BTreeMap::new(),
        ok: false,
    };
    let key_entries = collect_key_entries(entries);
    if !key_entries_well_formed(&key_entries) {
        return kl;
    }

    for (pos, (_idx, env, body)) in key_entries.iter().enumerate() {
        let action = body
            .get("action_type")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let ctx = body.get("context").cloned().unwrap_or(Value::Null);
        let jwk = ctx.get("jwk").cloned().unwrap_or(Value::Null);
        let ts = body.get("ts_server").and_then(|v| v.as_str()).unwrap_or("");
        let (material, kid) = match key_from_jwk(&jwk) {
            Some(m) => m,
            None => return kl,
        };
        let applied = match action {
            "evd.key.created" => apply_key_created(&mut kl, pos, env, ts, kid, material),
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
    revoked_at
        .get(kid)
        .map(|r| at <= r.as_str())
        .unwrap_or(true)
}

pub(crate) fn checkpoint_body_hash(cp: &Value) -> Option<String> {
    let body = cp.get("body")?;
    Some(hex(&sha256(&jcs::canonical(body))))
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn verify_checkpoint_sig(cp: &Value, keys: &BTreeMap<String, [u8; 32]>) -> bool {
    let kid = match cp.get("kid").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => return false,
    };
    let pubkey = match keys.get(kid) {
        Some(p) => p,
        None => return false,
    };
    let body = match cp.get("body") {
        Some(b) => b,
        None => return false,
    };
    let sig_b64 = match cp.get("sig").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return false,
    };
    let sig = match B64.decode(sig_b64) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let msg = pae(CHECKPOINT_TYPE, &jcs::canonical(body));
    ed25519_verify(pubkey, &msg, &sig)
}

fn check_jwks_match_log(bundle: &Value, kl: &KeyLog) -> bool {
    let jwks = match bundle
        .get("jwks")
        .and_then(|v| v.get("keys"))
        .and_then(|v| v.as_array())
    {
        Some(k) if !k.is_empty() => k,
        _ => return false,
    };
    for jwk in jwks {
        match key_from_jwk(jwk) {
            Some((mat, kid)) => match kl.keys.get(&kid) {
                Some(logmat) if *logmat == mat => {}
                _ => {
                    return false;
                }
            },
            None => {
                return false;
            }
        }
    }
    true
}

fn check_target_checkpoint(target: &Value, kl: &KeyLog) -> bool {
    if !verify_checkpoint_sig(target, &kl.keys) {
        return false;
    }
    let target_ts = target
        .get("body")
        .and_then(|b| b.get("ts"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target_kid = target.get("kid").and_then(|v| v.as_str()).unwrap_or("");
    kid_valid_at(target_kid, target_ts, &kl.revoked_at)
}

fn check_chain_consistency(prev: &Value, cp: &Value, entry: &Value, prev_size: u64, cur_size: u64) -> bool {
    let proof_hex: Vec<String> = entry
        .get("consistency_from_prev")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let proof: Vec<[u8; 32]> = proof_hex
        .iter()
        .filter_map(|h| hex_decode(h))
        .filter_map(|b| b.try_into().ok())
        .collect();
    let prev_root = prev
        .get("body")
        .and_then(|b| b.get("root_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let cur_root = cp
        .get("body")
        .and_then(|b| b.get("root_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let (pr, cr) = match (hex_decode(prev_root), hex_decode(cur_root)) {
        (Some(a), Some(b)) => (a, b),
        _ => return false,
    };
    merkle::verify_consistency(prev_size, cur_size, &pr, &cr, &proof)
}

fn check_chain_link(prev: &Value, cp: &Value, entry: &Value) -> bool {
    let prev_bh = match checkpoint_body_hash(prev) {
        Some(h) => h,
        None => return false,
    };
    let cur_prev = cp
        .get("body")
        .and_then(|b| b.get("prev_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if cur_prev != prev_bh {
        return false;
    }
    let prev_size = prev
        .get("body")
        .and_then(|b| b.get("tree_size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cur_size = cp
        .get("body")
        .and_then(|b| b.get("tree_size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if cur_size < prev_size {
        return false;
    }
    let prev_origin = prev
        .get("body")
        .and_then(|b| b.get("origin"))
        .and_then(|v| v.as_str());
    let cur_origin = cp
        .get("body")
        .and_then(|b| b.get("origin"))
        .and_then(|v| v.as_str());
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
    for (i, cp) in chain.iter().enumerate() {
        if !verify_checkpoint_sig(cp, &kl.keys) {
            return false;
        }
        let ts = cp
            .get("body")
            .and_then(|b| b.get("ts"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
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

fn chain_head_matches(chain: &[Value], target: &Value) -> bool {
    match (
        checkpoint_body_hash(chain.last().unwrap()),
        checkpoint_body_hash(target),
    ) {
        (Some(a), Some(b)) if a == b => true,
        _ => false,
    }
}

fn check_entry_sigs(env: &Value, sigs: &[Value], ts_server: &str, kl: &KeyLog) -> bool {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for s in sigs {
        let kid = s.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
        let pubkey = match kl.keys.get(kid) {
            Some(p) => p,
            None => return false,
        };
        if !env_signed_by(env, kid, pubkey) {
            return false;
        }
        if !kid_valid_at(kid, ts_server, &kl.revoked_at) {
            return false;
        }
        seen.insert(kid.to_string());
    }
    true
}

fn check_entry_inclusion(e: &Value, payload: &[u8], size: u64, root: &[u8]) -> bool {
    // recomputed receipt hash, then the RFC 6962 leaf hash (0x00 prefix)
    let rh = sha256(payload);
    let mut leaf_data = vec![0x00u8];
    leaf_data.extend_from_slice(&rh);
    let leaf_hash = sha256(&leaf_data);
    let leaf_index = e
        .get("leaf_index")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let proof: Vec<[u8; 32]> = e
        .get("inclusion_proof")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str())
                .filter_map(hex_decode)
                .filter_map(|b| b.try_into().ok())
                .collect()
        })
        .unwrap_or_default();
    merkle::verify_inclusion(&leaf_hash, leaf_index, size, &proof, root)
}

fn check_entry(e: &Value, kl: &KeyLog, size: u64, root: &[u8]) -> bool {
    let env = &e["envelope"];
    let payload = match payload_of(env) {
        Some(p) => p,
        None => return false,
    };
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

fn check_entries(entries: &[Value], target: &Value, kl: &KeyLog) -> bool {
    let size = target
        .get("body")
        .and_then(|b| b.get("tree_size"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let root_hex = target
        .get("body")
        .and_then(|b| b.get("root_hash"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let root = match hex_decode(root_hex) {
        Some(r) => r,
        None => return false,
    };
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
    matches!(
        a,
        "_system" | "_grants" | "_reports" | "_detect" | "_idem" | "_authority" | "_node"
    ) || a.starts_with("_rel_")
}

fn collect_lineage(
    entries: &[Value],
) -> Option<BTreeMap<String, Vec<(String, String, i64, Value)>>> {
    // (action_type, receipt_hash, seq, context) per acting agent
    let mut by_agent: BTreeMap<String, Vec<(String, String, i64, Value)>> = BTreeMap::new();
    for e in entries {
        if let Some(body) = e.get("envelope").and_then(body_of) {
            let agent = body.get("agent_id").and_then(|v| v.as_str()).unwrap_or("");
            if agent.is_empty() || is_internal_agent(agent) {
                continue; // ONLY known internal bookkeeping agents are exempt
            }
            let at = body
                .get("action_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let seq = body.get("seq").and_then(|v| v.as_i64()).unwrap_or(-1);
            let rh = match e.get("envelope").and_then(receipt_hash_hex) {
                Some(h) => h,
                None => return None,
            };
            let ctx = body.get("context").cloned().unwrap_or(Value::Null);
            by_agent.entry(agent.to_string()).or_default().push((at, rh, seq, ctx));
        }
    }
    Some(by_agent)
}

fn check_lineage_orphan(items: &[(String, String, i64, Value)], valid: &BTreeSet<String>) -> bool {
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

fn check_lineage_established(
    items: &[(String, String, i64, Value)],
    valid: &BTreeSet<String>,
    birth_at: &str,
    birth_hash: &str,
    birth_seq: i64,
) -> bool {
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
    let est: Vec<&(String, String, i64, Value)> = items
        .iter()
        .filter(|(at, _, _, _)| at == "lineage.born" || at == "lineage.adopted")
        .collect();
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
        Some((birth_at, birth_hash, birth_seq, _)) => {
            check_lineage_established(items, &valid, birth_at, birth_hash, *birth_seq)
        }
    }
}

fn check_lineage(entries: &[Value]) -> bool {
    let by_agent = match collect_lineage(entries) {
        Some(m) => m,
        None => return false,
    };
    for (_agent, items) in by_agent {
        if !check_agent_lineage(&items) {
            return false;
        }
    }
    true
}

fn check_bound_records(records: &Value, required: &[&str], chain: &[Value]) -> bool {
    let arr = match records.as_array() {
        Some(a) => a,
        None => return false,
    };
    if arr.is_empty() {
        return true;
    }
    let chain_hashes: BTreeSet<String> =
        chain.iter().filter_map(checkpoint_body_hash).collect();
    for rec in arr {
        let obj = match rec.as_object() {
            Some(o) => o,
            None => return false,
        };
        for f in required {
            if !obj.contains_key(*f) {
                return false;
            }
        }
        let bh = rec
            .get("checkpoint_body_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if !chain_hashes.contains(bh) {
            return false;
        }
    }
    true
}

fn check_attestation_records(bundle: &Value, chain: &[Value]) -> bool {
    // 7. timestamp records (if present): structural + binding checks. Full
    // RFC 3161 CMS validation is the Python verifier's job (documented
    // divergence closed to the binding level here: a TST that names a
    // checkpoint outside this bundle's chain is a forgery, both verifiers).
    if let Some(tsts) = bundle.get("tst_records") {
        if !check_bound_records(
            tsts,
            &["checkpoint_body_hash", "token_der_b64", "gen_time"],
            chain,
        ) {
            return false;
        }
    }

    // 8. anchor records (if present): each must bind to a chain checkpoint
    if let Some(anchors) = bundle.get("anchor_records") {
        if !check_bound_records(
            anchors,
            &[
                "checkpoint_body_hash",
                "chain_id",
                "tx_hash",
                "block_number",
                "block_ts",
                "contract",
            ],
            chain,
        ) {
            return false;
        }
    }
    true
}

fn check_checkpoints_and_entries(bundle: &Value, entries: &[Value], kl: &KeyLog) -> bool {
    // 2. target checkpoint
    let target = match bundle.get("target_checkpoint") {
        Some(t) => t,
        None => return false,
    };
    if !check_target_checkpoint(target, kl) {
        return false;
    }

    // 3. chain: signatures, linkage, monotonic, same origin, consistency
    let chain: Vec<Value> = bundle
        .get("checkpoint_chain")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.get("checkpoint").cloned())
                .collect()
        })
        .unwrap_or_default();
    let chain_entries: Vec<Value> = bundle
        .get("checkpoint_chain")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if chain.is_empty() {
        return false;
    }
    if !check_checkpoint_chain(&chain, &chain_entries, kl) {
        return false;
    }

    // 4. target == chain head
    if !chain_head_matches(&chain, target) {
        return false;
    }

    // 5. entries
    if !check_entries(entries, target, kl) {
        return false;
    }

    // 5b. per-agent seq uniqueness: seq GAPS are legitimate (subset exports)
    // but a duplicate (agent_id, seq) is always forgery/corruption.
    if !check_seq_uniqueness(entries) {
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

fn disclosure_fields(pkg: &Value) -> Option<(String, String, String, Vec<u8>, Vec<u8>)> {
    // (receipt_hash, field, domain, nonce, payload); any missing or
    // undecodable member makes the whole package malformed.
    if str_field(pkg, "schema")? != DISCLOSURE_SCHEMA {
        return None;
    }
    let nonce = hex_decode(&str_field(pkg, "nonce_hex")?)?;
    let payload = B64.decode(str_field(pkg, "payload_b64")?).ok()?;
    Some((
        str_field(pkg, "receipt_hash")?,
        str_field(pkg, "field")?,
        str_field(pkg, "domain")?,
        nonce,
        payload,
    ))
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
    body.get("commitments")?
        .get(field)?
        .as_str()
        .map(String::from)
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
    let entries = match bundle.get("entries").and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return false,
    };
    for e in entries {
        let raw = match e.get("envelope").and_then(payload_of) {
            Some(r) => r,
            None => continue,
        };
        if hex(&sha256(&raw)) != rh {
            continue;
        }
        let expected = match disclosure_committed_value(&raw, &field) {
            Some(x) => x,
            None => return false,
        };
        return disclosure_commitment(&domain, &payload, &nonce).as_deref() == Some(&expected);
    }
    false
}

/// Verify an evd/bundle/v1 document. Returns true iff VERIFIED.
pub fn verify_bundle(bundle: &Value) -> bool {
    if bundle.get("schema").and_then(|v| v.as_str()) != Some("evd/bundle/v1") {
        return false;
    }
    let entries: Vec<Value> = bundle
        .get("entries")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    if entries.is_empty() {
        return false;
    }

    // 0. key log replay
    let kl = replay_key_log(&entries);
    if !kl.ok {
        return false;
    }

    // 1. jwks agrees with the log
    if !check_jwks_match_log(bundle, &kl) {
        return false;
    }

    check_checkpoints_and_entries(bundle, &entries, &kl)
}

// -- WASM binding (feature-gated; native build never pulls wasm-bindgen) -----
#[cfg(feature = "wasm")]
mod wasm {
    use wasm_bindgen::prelude::*;

    /// Verify a bundle passed as a JSON string. Returns "VERIFIED" /
    /// "NOT VERIFIED" / "ERROR: <reason>". For the file-drop static page.
    #[wasm_bindgen]
    pub fn verify_bundle_json(json: &str) -> String {
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
