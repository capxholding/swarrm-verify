// Apache-2.0 (public verifier repo)
//! COSE_Sign1 canonical-byte gate (B25 W1) — the Rust twin of
//! tests/test_cose_canonical.py. Every golden vector must build byte-identical
//! to its `.cose` file, sign over exactly the `.sig_input.bin` Sig_structure,
//! verify and round-trip, and reject every tamper — hostile bytes are a clean
//! `None`, never a panic (H5). The `.cose` bytes are the shared truth.
//!
//! `cose` is pub(crate) (the bare-`pub` budget is reserved elsewhere), so the
//! module is compiled directly via `#[path]`, exactly like cbor_canonical.rs.
//! It refers to `crate::cbor` and `crate::ed25519_verify`, so both are
//! provided here at the test-crate root.

#[path = "../src/cbor.rs"]
#[allow(dead_code)] // this binary uses only the emitter; the decoder is cbor_canonical.rs's
mod cbor;
#[path = "../src/cose.rs"]
mod cose;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use ciborium::Value;
use ed25519_dalek::{Signature, SigningKey, Verifier, VerifyingKey};
use serde_json::Value as Json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

/// cose.rs verifies signatures through this crate-root symbol (mirrors lib.rs).
pub(crate) fn ed25519_verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
        return false;
    };
    if sig.len() != 64 {
        return false;
    }
    let mut s = [0u8; 64];
    s.copy_from_slice(sig);
    vk.verify(msg, &Signature::from_bytes(&s)).is_ok()
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/golden/cose")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn seed32(hex: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&unhex(hex));
    out
}

/// (raw public key, kid) for a fixed Ed25519 seed — the exact core/keys rule.
fn key_of(seed: &[u8; 32]) -> ([u8; 32], String) {
    let pk = SigningKey::from_bytes(seed).verifying_key().to_bytes();
    let kid = B64URL.encode(Sha256::digest(pk)).chars().take(16).collect();
    (pk, kid)
}

/// Inverse of gen_cose_golden.to_jm: the tagged JSON model → ciborium Value.
fn from_jm(v: &Json) -> Option<Value> {
    let o = v.as_object()?;
    if o.contains_key("n") {
        return Some(Value::Null);
    }
    if let Some(i) = o.get("i") {
        return Some(Value::Integer(i.as_i64()?.into()));
    }
    if let Some(s) = o.get("s") {
        return Some(Value::Text(s.as_str()?.to_owned()));
    }
    if let Some(b) = o.get("b") {
        return Some(Value::Bytes(unhex(b.as_str()?)));
    }
    if let Some(a) = o.get("a") {
        return Some(Value::Array(a.as_array()?.iter().map(from_jm).collect::<Option<_>>()?));
    }
    if let Some(m) = o.get("m") {
        let pairs = m
            .as_array()?
            .iter()
            .map(|p| {
                let pa = p.as_array()?;
                Some((from_jm(pa.first()?)?, from_jm(pa.get(1)?)?))
            })
            .collect::<Option<Vec<_>>>()?;
        return Some(Value::Map(pairs));
    }
    None
}

fn payload_opt(v: &Value) -> Option<Vec<u8>> {
    match v {
        Value::Bytes(b) => Some(b.clone()),
        _ => None,
    }
}

struct Vector {
    name: String,
    seed: [u8; 32],
    protected: Value,
    unprotected: Value,
    payload: Option<Vec<u8>>,
    cose: Vec<u8>,
    sig_input: Vec<u8>,
}

fn load_vectors() -> Vec<Vector> {
    let dir = golden_dir();
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("cose") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let src: Json =
            serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap())
                .unwrap();
        let seed = seed32(src["signer_seed"].as_str().unwrap());
        let payload = from_jm(&src["payload"]).unwrap();
        out.push(Vector {
            protected: from_jm(&src["protected"]).unwrap(),
            unprotected: from_jm(&src["unprotected"]).unwrap(),
            payload: payload_opt(&payload),
            cose: fs::read(dir.join(format!("{name}.cose"))).unwrap(),
            sig_input: fs::read(dir.join(format!("{name}.sig_input.bin"))).unwrap(),
            seed,
            name,
        });
    }
    out
}

#[test]
fn build_matches_golden_byte_identical() {
    let vectors = load_vectors();
    assert!(vectors.len() >= 20, "only {} COSE vectors", vectors.len());
    for v in &vectors {
        let built = cose::build_sign1(&v.protected, &v.unprotected, v.payload.as_deref(), &v.seed)
            .unwrap_or_else(|| panic!("build refused {}", v.name));
        assert_eq!(built, v.cose, "byte mismatch on {}", v.name);
    }
}

#[test]
fn sig_structure_matches_golden() {
    for v in &load_vectors() {
        // Recover the protected bstr from the trusted golden, then rebuild the
        // Sig_structure through the sanctioned emitter (crate::cbor).
        let arr = match ciborium::de::from_reader::<Value, _>(&v.cose[1..]) {
            Ok(Value::Array(a)) => a,
            _ => panic!("golden {} is not a tag-18 array body", v.name),
        };
        let protected_bytes = match &arr[0] {
            Value::Bytes(b) => b.clone(),
            _ => panic!("protected not a bstr in {}", v.name),
        };
        let body = v.payload.clone().unwrap_or_default();
        let sig = cbor::canonical_cbor(&Value::Array(vec![
            Value::Text("Signature1".to_owned()),
            Value::Bytes(protected_bytes),
            Value::Bytes(Vec::new()),
            Value::Bytes(body),
        ]))
        .unwrap();
        assert_eq!(sig, v.sig_input, "sig_input mismatch on {}", v.name);
    }
}

#[test]
fn verify_accepts_and_roundtrips() {
    for v in &load_vectors() {
        let (pk, kid) = key_of(&v.seed);
        let mut keys = BTreeMap::new();
        keys.insert(kid.clone(), pk);
        let s = cose::verify_sign1(&v.cose, &keys, 65536, 16)
            .unwrap_or_else(|| panic!("verify refused {}", v.name));
        assert_eq!(s.kid, kid, "kid mismatch on {}", v.name);
        assert_eq!(s.payload, v.payload, "payload mismatch on {}", v.name);
        // Header faithfulness: the decoded headers re-encode to the exact
        // golden bytes (ciborium Map is a Vec, so compare canonically, not by
        // source insertion order).
        let rebuilt = cose::build_sign1(&s.protected, &s.unprotected, s.payload.as_deref(), &v.seed)
            .unwrap_or_else(|| panic!("rebuild refused {}", v.name));
        assert_eq!(rebuilt, v.cose, "header round-trip mismatch on {}", v.name);
    }
}

#[test]
fn verify_rejects_tampering() {
    for v in &load_vectors() {
        let (pk, kid) = key_of(&v.seed);
        let mut keys = BTreeMap::new();
        keys.insert(kid, pk);
        // flipped signature byte (last byte lives in the signature bstr)
        let mut flipped = v.cose.clone();
        *flipped.last_mut().unwrap() ^= 0x01;
        assert!(cose::verify_sign1(&flipped, &keys, 65536, 16).is_none(), "flip {}", v.name);
        // unknown kid
        let empty: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        assert!(cose::verify_sign1(&v.cose, &empty, 65536, 16).is_none(), "kid {}", v.name);
        // over the byte cap
        assert!(
            cose::verify_sign1(&v.cose, &keys, v.cose.len() - 1, 16).is_none(),
            "cap {}",
            v.name
        );
    }
}

#[test]
fn hostile_bytes_never_panic() {
    let keys: BTreeMap<String, [u8; 32]> = BTreeMap::new();
    let mut cases: Vec<Vec<u8>> = vec![
        vec![],
        vec![0xd2],
        vec![0xd2, 0x00],
        unhex("d29fff"),
        unhex("d284"),
        unhex("d2a10101"),
        vec![0xff],
        vec![0x00; 10],
    ];
    // a deeply nested body under the tag: the depth cap bails before any
    // recursion can overflow the stack.
    cases.push([vec![0xd2], vec![0x81; 40]].concat());
    cases.push(vec![0x81; 1 << 16]); // no tag, absurd nesting
    for bytes in &cases {
        assert!(cose::verify_sign1(bytes, &keys, 1 << 20, 16).is_none());
    }
}
