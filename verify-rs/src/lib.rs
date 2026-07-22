// Apache-2.0 (public verifier repo)
//! Independent Rust verifier for evd/bundle/v1.
//!
//! A SECOND implementation, on purpose: it shares no code with the Python
//! verifier, so agreement on the shared golden suite (tests/golden/) is real
//! evidence that the format is unambiguous. Verify-only, offline, no network.

mod jcs;
mod merkle;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const RECEIPT_TYPE: &str = "application/vnd.evd.receipt.v1+json";
const CHECKPOINT_TYPE: &str = "application/vnd.evd.checkpoint.v1+json";

fn sha256(data: &[u8]) -> [u8; 32] {
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

/// Extract raw Ed25519 public key from a JWK, validating the kid binding.
fn key_from_jwk(jwk: &Value) -> Option<([u8; 32], String)> {
    if jwk.get("kty")?.as_str()? != "OKP" || jwk.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    let raw = b64url_decode(jwk.get("x")?.as_str()?)?;
    if raw.len() != 32 {
        return None;
    }
    let mut k = [0u8; 32];
    k.copy_from_slice(&raw);
    // kid = base64url(sha256(raw))[:16]
    let full = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sha256(&raw));
    let kid = full.chars().take(16).collect::<String>();
    if let Some(claimed) = jwk.get("kid").and_then(|v| v.as_str()) {
        if claimed != kid {
            return None;
        }
    }
    Some((k, kid))
}

fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
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

fn env_signed_by(env: &Value, kid: &str, pubkey: &[u8; 32]) -> bool {
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

fn body_of(env: &Value) -> Option<Value> {
    serde_json::from_slice(&payload_of(env)?).ok()
}

/// The trust root of the key-log replay: all keys (incl. revoked) + revoke ts.
struct KeyLog {
    keys: BTreeMap<String, [u8; 32]>,
    revoked_at: BTreeMap<String, String>,
    ok: bool,
}

fn replay_key_log(entries: &[Value]) -> KeyLog {
    let mut kl = KeyLog {
        keys: BTreeMap::new(),
        revoked_at: BTreeMap::new(),
        ok: false,
    };
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
    if key_entries.is_empty() {
        return kl;
    }
    if key_entries[0].0 != 0
        || key_entries[0].2.get("action_type").and_then(|v| v.as_str()) != Some("evd.key.created")
    {
        return kl;
    }
    // dense _system sequence
    let seqs: Vec<i64> = key_entries
        .iter()
        .map(|t| t.2.get("seq").and_then(|v| v.as_i64()).unwrap_or(-1))
        .collect();
    for (i, s) in seqs.iter().enumerate() {
        if *s != (i as i64) + 1 {
            return kl;
        }
    }

    let active = |keys: &BTreeMap<String, [u8; 32]>,
                  revoked: &BTreeMap<String, String>,
                  kid: &str,
                  at: &str|
     -> bool {
        keys.contains_key(kid) && revoked.get(kid).map(|r| at <= r.as_str()).unwrap_or(true)
    };

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
        match action {
            "evd.key.created" => {
                if pos == 0 {
                    if !env_signed_by(env, &kid, &material) {
                        return kl;
                    }
                } else {
                    // sponsored: some active key signed it
                    let sigs = env.get("signatures").and_then(|v| v.as_array());
                    let ok = sigs
                        .map(|ss| {
                            ss.iter().any(|s| {
                                let sk = s.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
                                active(&kl.keys, &kl.revoked_at, sk, ts)
                                    && env_signed_by(env, sk, &kl.keys[sk])
                            })
                        })
                        .unwrap_or(false);
                    if !ok {
                        return kl;
                    }
                }
                kl.keys.insert(kid, material);
            }
            "evd.key.rotated" => {
                let prev_kid = ctx.get("prev_kid").and_then(|v| v.as_str()).unwrap_or("");
                let continuity = ctx.get("continuity_sig").and_then(|v| v.as_str());
                if prev_kid.is_empty() || continuity.is_none() {
                    return kl;
                }
                if !active(&kl.keys, &kl.revoked_at, prev_kid, ts) {
                    return kl;
                }
                if !env_signed_by(env, prev_kid, &kl.keys[prev_kid]) {
                    return kl;
                }
                // continuity: prev key signed canonical(jwk)
                let jwk_canon = jcs::canonical(&jwk);
                let cont = match B64.decode(continuity.unwrap()) {
                    Ok(c) => c,
                    Err(_) => return kl,
                };
                if !ed25519_verify(&kl.keys[prev_kid], &jwk_canon, &cont) {
                    return kl;
                }
                kl.keys.insert(kid, material);
            }
            "evd.key.revoked" => {
                if !kl.keys.contains_key(&kid) {
                    return kl;
                }
                let sigs = env.get("signatures").and_then(|v| v.as_array());
                let ok = sigs
                    .map(|ss| {
                        ss.iter().any(|s| {
                            let sk = s.get("keyid").and_then(|v| v.as_str()).unwrap_or("");
                            active(&kl.keys, &kl.revoked_at, sk, ts)
                                && env_signed_by(env, sk, &kl.keys[sk])
                        })
                    })
                    .unwrap_or(false);
                if !ok {
                    return kl;
                }
                let eff = ctx
                    .get("effective_ts")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                kl.revoked_at.insert(kid, eff.to_string());
            }
            _ => return kl,
        }
    }
    kl.ok = true;
    kl
}

fn kid_valid_at(kid: &str, at: &str, revoked_at: &BTreeMap<String, String>) -> bool {
    revoked_at
        .get(kid)
        .map(|r| at <= r.as_str())
        .unwrap_or(true)
}

fn checkpoint_body_hash(cp: &Value) -> Option<String> {
    let body = cp.get("body")?;
    Some(hex(&sha256(&jcs::canonical(body))))
}

fn hex(b: &[u8]) -> String {
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

    // 2. target checkpoint
    let target = match bundle.get("target_checkpoint") {
        Some(t) => t,
        None => return false,
    };
    if !verify_checkpoint_sig(target, &kl.keys) {
        return false;
    }
    let target_ts = target
        .get("body")
        .and_then(|b| b.get("ts"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let target_kid = target.get("kid").and_then(|v| v.as_str()).unwrap_or("");
    if !kid_valid_at(target_kid, target_ts, &kl.revoked_at) {
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
        if i > 0 {
            let prev = &chain[i - 1];
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
            if prev_size > 0 {
                let proof_hex: Vec<String> = chain_entries[i]
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
                if !merkle::verify_consistency(prev_size, cur_size, &pr, &cr, &proof) {
                    return false;
                }
            }
        }
    }

    // 4. target == chain head
    match (
        checkpoint_body_hash(chain.last().unwrap()),
        checkpoint_body_hash(target),
    ) {
        (Some(a), Some(b)) if a == b => {}
        _ => {
            return false;
        }
    }

    // 5. entries
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
    for e in &entries {
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
        // recomputed receipt hash, then the RFC 6962 leaf hash (0x00 prefix)
        let rh = sha256(&payload);
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
        if !merkle::verify_inclusion(&leaf_hash, leaf_index, size, &proof, &root) {
            return false;
        }
    }

    // 6. anchor records (if present): each must bind to a chain checkpoint
    if let Some(anchors) = bundle.get("anchor_records") {
        let arr = match anchors.as_array() {
            Some(a) => a,
            None => return false,
        };
        if !arr.is_empty() {
            let chain_hashes: BTreeSet<String> =
                chain.iter().filter_map(checkpoint_body_hash).collect();
            for rec in arr {
                let obj = match rec.as_object() {
                    Some(o) => o,
                    None => return false,
                };
                for f in [
                    "checkpoint_body_hash",
                    "chain_id",
                    "tx_hash",
                    "block_number",
                    "block_ts",
                    "contract",
                ] {
                    if !obj.contains_key(f) {
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
        }
    }

    true
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
