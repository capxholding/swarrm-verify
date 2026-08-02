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

/// Hex string → bytes; None on non-ASCII, odd length, or a bad nibble. Shared
/// with the certificate layer's pack decode (H5: no panic on hostile input).
pub(crate) fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn imap<'a>(v: &'a Value, key: i128) -> Option<&'a Value> {
    let Value::Map(m) = v else { return None };
    m.iter()
        .find(|(k, _)| matches!(k, Value::Integer(i) if i128::from(*i) == key))
        .map(|(_, x)| x)
}

fn tmap<'a>(body: &'a Value, key: &str) -> Option<&'a Value> {
    let Value::Map(m) = body else { return None };
    m.iter().find(|(k, _)| matches!(k, Value::Text(t) if t == key)).map(|(_, x)| x)
}

fn btext<'a>(body: &'a Value, key: &str) -> Option<&'a str> {
    match tmap(body, key)? {
        Value::Text(t) => Some(t),
        _ => None,
    }
}

fn as_uint(v: &Value) -> Option<u64> {
    match v {
        Value::Integer(i) => u64::try_from(i128::from(*i)).ok(),
        _ => None,
    }
}

/// §6.5: recompute the checkpoint body_hash from unprotected -2 exactly as
/// `core.checkpoint.Checkpoint.from_dict(...).body_hash()` — JCS over the six
/// fixed fields (extra keys dropped, schema pinned) → (body_hash hex, root).
fn checkpoint(unprotected: &Value) -> Option<(String, Vec<u8>)> {
    let body = imap(unprotected, -2)?;
    if btext(body, "schema")? != CHECKPOINT_SCHEMA {
        return None;
    }
    let tree_size = as_uint(tmap(body, "tree_size")?)?;
    let root_hex = btext(body, "root_hash")?;
    let obj = json!({
        "schema": CHECKPOINT_SCHEMA,
        "origin": btext(body, "origin")?,
        "tree_size": tree_size,
        "root_hash": root_hex,
        "ts": btext(body, "ts")?,
        "prev_hash": btext(body, "prev_hash")?,
    });
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
pub fn verify_scitt_receipt(
    signed_statement: &[u8],
    receipt: &[u8],
    ts_keys: &BTreeMap<String, [u8; 32]>,
    issuer_keys: &BTreeMap<String, [u8; 32]>,
    certificate_id: &str,
) -> bool {
    let Some(cid) = hex_to_bytes(certificate_id) else { return false };
    // §6.2 issuer signature; the payload is exactly the 32-byte certificate_id
    let Some(stmt) = crate::cose::verify_sign1(signed_statement, issuer_keys, MAX_BYTES, MAX_DEPTH)
    else {
        return false;
    };
    if stmt.payload.as_deref() != Some(cid.as_slice()) {
        return false;
    }
    // §6.3 statement digest → §6.4 TS signature over the receipt
    let statement_digest = crate::sha256(signed_statement);
    let Some(rcpt) = crate::cose::verify_sign1(receipt, ts_keys, MAX_BYTES, MAX_DEPTH) else {
        return false;
    };
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
