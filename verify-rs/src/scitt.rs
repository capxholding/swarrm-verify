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

use ciborium::Value;
use serde_json::json;
use std::collections::BTreeMap;

const MAX_BYTES: usize = 65536; // §6.1: each COSE_Sign1 <= 64 KiB
const MAX_DEPTH: usize = 16; // §6.1: CBOR depth <= 16
const MAX_AUDIT_PATH: usize = 64; // scitt-v1.cddl caps trailer

const CHECKPOINT_SCHEMA: &str = "evd/checkpoint/v1";
const STATEMENT_CTY: &str = "application/vnd.swarrm.action-certificate+cbor";
const SCOPE_DIGEST_CLAIM: &str = "evd_scope_digest";

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
/// the more permissive engine on the same bytes (owner audit 2026-08-05,
/// second pass).
fn checkpoint_body(body: &Value) -> Option<(serde_json::Value, &str)> {
    // Exactly six members, all present and well-typed. Extracted from
    // `checkpoint` to keep that function inside the §0.2·3a complexity ceiling.
    if btext(body, "schema")? != CHECKPOINT_SCHEMA || map_len(body) != Some(6) {
        return None; // a member the signature does not cover is not "signed"
    }
    let root_hex = btext(body, "root_hash")?;
    let obj = json!({
        "schema": CHECKPOINT_SCHEMA,
        "origin": btext(body, "origin")?,
        "tree_size": as_uint(tmap(body, "tree_size")?)?,
        "root_hash": root_hex,
        "ts": btext(body, "ts")?,
        "prev_hash": btext(body, "prev_hash")?,
    });
    Some((obj, root_hex))
}

fn checkpoint(unprotected: &Value) -> Option<(String, Vec<u8>)> {
    let (obj, root_hex) = checkpoint_body(imap(unprotected, -2)?)?;
    let canon = crate::jcs::canonical_checked(&obj)?;
    Some((crate::hex(&crate::sha256(&canon)), hex_to_bytes(root_hex)?))
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

/// Derive `scitt_receipt_valid` for a statement+receipt pair (§6). ALL of §6
/// must hold or the result is `false` (fail-closed); never panics.
pub fn verify_scitt_receipt(signed_statement: &[u8], receipt: &[u8], ts_keys: &BTreeMap<String, [u8; 32]>, issuer_keys: &BTreeMap<String, [u8; 32]>, certificate_id: &str) -> bool {
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
    let Some((body_hash, root)) = checkpoint(&rcpt.unprotected) else { return false };
    if rcpt.payload.as_deref().map(crate::hex) != Some(body_hash) {
        return false;
    }
    // §6.6 RFC 9162 inclusion of statement_digest to checkpoint.root. This
    // engine's `merkle::verify_inclusion` takes the ALREADY-HASHED RFC 6962
    // leaf (SHA-256(0x00 ‖ statement_digest)), where Python's takes the leaf
    // data and hashes it — compute the leaf hash here so both agree.
    let Some((tree_size, leaf_index, path)) = inclusion(&rcpt.unprotected) else { return false };
    let leaf = crate::sha256(&[&[0x00u8], &statement_digest[..]].concat());
    crate::merkle::verify_inclusion(&leaf, leaf_index, tree_size, &path, &root)
}
