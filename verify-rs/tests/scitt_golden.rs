// Apache-2.0 (public verifier repo)
//! B25 W4 — the Rust engine runs the SAME SCITT golden bytes the Python engine
//! compiled (scripts/gen_scitt_golden.py, tests/golden/scitt/) and must
//! reproduce the hand-authored `scitt_receipt_valid` in expected.json for every
//! family. Two independent implementations agreeing on the ten §6 outcomes —
//! and never panicking on hostile bytes (H5) — is the B25 conformance contract.
//!
//! `scitt` (and its `cose` / `cbor` / `jcs` / `merkle` dependencies) are
//! pub(crate), so — exactly like cose_canonical.rs — the modules are compiled
//! directly via `#[path]` and the crate-root helpers `sha256` / `hex` /
//! `ed25519_verify` are re-provided here (mirrors lib.rs).

#[path = "../src/cbor.rs"]
#[allow(dead_code)]
mod cbor;
#[path = "../src/cbor_wire.rs"]
#[allow(dead_code)]
mod cbor_wire;
#[path = "../src/cose.rs"]
#[allow(dead_code)]
mod cose;
#[path = "../src/jcs.rs"]
#[allow(dead_code)]
mod jcs;
#[path = "../src/merkle.rs"]
#[allow(dead_code)]
mod merkle;
#[path = "../src/scitt.rs"]
mod scitt;

use base64::{
    engine::general_purpose::{STANDARD as B64, URL_SAFE_NO_PAD as B64URL},
    Engine,
};
use ciborium::Value as Cbor;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

// ---- crate-root helpers the included modules resolve as `crate::…` ----------

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

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

pub(crate) fn key_from_jwk(jwk: &Value) -> Option<([u8; 32], String)> {
    if jwk.get("kty")?.as_str()? != "OKP" || jwk.get("crv")?.as_str()? != "Ed25519" {
        return None;
    }
    let raw = B64URL.decode(jwk.get("x")?.as_str()?).ok()?;
    let key: [u8; 32] = raw.try_into().ok()?;
    let kid = B64URL.encode(sha256(&key)).chars().take(16).collect::<String>();
    match jwk.get("kid") {
        None | Some(Value::Null) => {}
        Some(Value::String(claimed)) if *claimed == kid => {}
        Some(_) => return None,
    }
    Some((key, kid))
}

// ---- fixture loading --------------------------------------------------------

fn scitt_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/scitt")
}

fn read_json(path: PathBuf) -> Value {
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// One JWK (OKP/Ed25519) → (raw 32-byte pubkey, kid), the core/keys rule.
fn key_of(jwk: &Value) -> ([u8; 32], String) {
    key_from_jwk(jwk).unwrap()
}

fn keys_from_jwks(jwks: &Value) -> BTreeMap<String, [u8; 32]> {
    let mut out = BTreeMap::new();
    for jwk in jwks["keys"].as_array().unwrap() {
        let (pk, kid) = key_of(jwk);
        out.insert(kid, pk);
    }
    out
}

fn integer_member_mut(value: &mut Cbor, label: i128) -> Option<&mut Cbor> {
    let Cbor::Map(entries) = value else { return None };
    entries.iter_mut().find_map(|(key, item)| matches!(key, Cbor::Integer(number) if i128::from(*number) == label).then_some(item))
}

fn mutate_inclusion_number(receipt: &[u8], ts_keys: &BTreeMap<String, [u8; 32]>, position: usize, value: u64) -> Vec<u8> {
    let parsed = cose::verify_sign1(receipt, ts_keys, 65536, 16).unwrap();
    let mut unprotected = parsed.unprotected;
    let triple = integer_member_mut(integer_member_mut(&mut unprotected, 396).unwrap(), -1).unwrap();
    let Cbor::Array(items) = triple else { panic!("fixture inclusion is not an array") };
    items[position] = Cbor::Integer(value.into());
    let seed = <[u8; 32]>::try_from((64u8..96).collect::<Vec<_>>()).unwrap();
    cose::build_sign1(&parsed.protected, &unprotected, parsed.payload.as_deref(), &seed).unwrap()
}

// ---- the gate ---------------------------------------------------------------

#[test]
fn scitt_suite_agrees_with_expected() {
    let dir = scitt_dir();
    let doc = read_json(dir.join("expected.json"));
    let cid = doc["certificate_id"].as_str().unwrap();
    let issuer_keys = keys_from_jwks(&read_json(dir.join("keys.json"))["issuer_jwks"]);

    let mut checked = 0;
    for (name, exp) in doc["families"].as_object().unwrap() {
        let stmt = fs::read(dir.join(format!("{name}.stmt.cose"))).unwrap();
        let rcpt = fs::read(dir.join(format!("{name}.rcpt.cose"))).unwrap();
        // the family's OWN pack publishes the trust keys (wrong_policy's is a
        // different root, so §6.4 closes) — exactly as the certificate layer.
        let pack = read_json(dir.join(format!("{name}.pack.json")));
        let ts_keys = keys_from_jwks(&pack["ts_jwks"]);

        let got = scitt::verify_scitt_receipt(&stmt, &rcpt, &ts_keys, &issuer_keys, cid);
        let want = exp["scitt_receipt_valid"].as_bool().unwrap();
        assert_eq!(got, want, "family {name}: scitt_receipt_valid");
        checked += 1;
    }
    assert!(checked >= 10, "expected at least 10 SCITT families, ran {checked}");
}

#[test]
fn cross_engine_certificate_id_matches_the_core() {
    // §2/§6.2: the core hashes to the certificate_id every statement
    // commits to — the receipt registers precisely this immutable core.
    let dir = scitt_dir();
    let cid = read_json(dir.join("expected.json"))["certificate_id"].as_str().unwrap().to_owned();
    let core = fs::read(dir.join("registered_valid.core.cbor")).unwrap();
    assert_eq!(hex(&sha256(&core)), cid);
}

#[test]
fn wrong_ts_key_and_hostile_bytes_fail_closed() {
    let dir = scitt_dir();
    let cid = read_json(dir.join("expected.json"))["certificate_id"].as_str().unwrap().to_owned();
    let issuer_keys = keys_from_jwks(&read_json(dir.join("keys.json"))["issuer_jwks"]);
    let stmt = fs::read(dir.join("registered_valid.stmt.cose")).unwrap();
    let rcpt = fs::read(dir.join("registered_valid.rcpt.cose")).unwrap();
    let empty: BTreeMap<String, [u8; 32]> = BTreeMap::new();

    // the valid receipt under NO trust keys fails §6.4; never panics
    assert!(!scitt::verify_scitt_receipt(&stmt, &rcpt, &empty, &issuer_keys, &cid));
    // hostile bytes on either side are a clean false, not a panic
    let pack = read_json(dir.join("registered_valid.pack.json"));
    let ts_keys = keys_from_jwks(&pack["ts_jwks"]);
    for (s, r) in [(vec![], vec![]), (vec![0xd2u8], vec![0xd2u8]), (unhex("d2819f"), rcpt.clone()), (stmt.clone(), vec![0xff; 8])] {
        assert!(!scitt::verify_scitt_receipt(&s, &r, &ts_keys, &issuer_keys, &cid));
    }
    // a genuinely valid family still verifies True under its own pack keys
    assert!(scitt::verify_scitt_receipt(&stmt, &rcpt, &ts_keys, &issuer_keys, &cid));
}

#[test]
fn pack_policy_is_locally_anchored_and_binds_checkpoint_metadata() {
    let dir = scitt_dir();
    let pack = read_json(dir.join("registered_valid.pack.json"));
    let statement = unhex(pack["signed_statement"].as_str().unwrap());
    let receipt = unhex(pack["receipt"].as_str().unwrap());
    let cid = pack["certificate_id"].as_str().unwrap();
    let issuer_keys = keys_from_jwks(&read_json(dir.join("keys.json"))["issuer_jwks"]);
    // Out-of-band fixture root: the generator's fixed TS seed, never read from
    // this subject-carried pack.
    let root_seed = <[u8; 32]>::try_from((64u8..96).collect::<Vec<_>>()).unwrap();
    let root = SigningKey::from_bytes(&root_seed).verifying_key().to_bytes();
    let local_roots = BTreeMap::from([("ts-1".to_owned(), root)]);

    let ts_keys = scitt::verified_scitt_pack_keys(&pack, &local_roots, &statement).expect("locally anchored honest pack");
    assert!(scitt::verify_scitt_receipt_with_checkpoint(&statement, &receipt, &ts_keys, &issuer_keys, cid, &pack["checkpoint"]));
    assert!(scitt::verified_scitt_pack_keys(&pack, &BTreeMap::new(), &statement).is_none(), "carried TS JWKs cannot bootstrap trust");

    // This pack is internally coherent: an attacker root signs the same exact
    // TS-key policy, and the TS receipt/checkpoint remain genuine. It validates
    // under that attacker root but not under the relying party's local root.
    let mut attacker_pack = pack.clone();
    let mut unsigned = attacker_pack["registration_policy"].as_object().unwrap().clone();
    unsigned.remove("signature");
    let seed = <[u8; 32]>::try_from((96u8..128).collect::<Vec<_>>()).unwrap();
    let attacker = SigningKey::from_bytes(&seed);
    let signature = attacker.sign(&jcs::canonical_checked(&Value::Object(unsigned)).unwrap());
    attacker_pack["registration_policy"]["signature"] = Value::String(B64.encode(signature.to_bytes()));
    let attacker_roots = BTreeMap::from([("attacker".to_owned(), attacker.verifying_key().to_bytes())]);
    assert!(scitt::verified_scitt_pack_keys(&attacker_pack, &attacker_roots, &statement).is_some(), "attacker fixture must be internally valid");
    assert!(scitt::verified_scitt_pack_keys(&attacker_pack, &local_roots, &statement).is_none(), "local root rejects attacker policy");

    let mut policy_tamper = pack.clone();
    policy_tamper["registration_policy"]["policy_version"] = Value::String("attacker-policy".to_owned());
    assert!(scitt::verified_scitt_pack_keys(&policy_tamper, &local_roots, &statement).is_none());

    let mut checkpoint_tamper = pack.clone();
    checkpoint_tamper["checkpoint"]["body"]["ts"] = Value::String("2020-01-01T00:00:00.000000Z".to_owned());
    assert!(scitt::verified_scitt_pack_keys(&checkpoint_tamper, &local_roots, &statement).is_none());

    let mut carried_key_tamper = pack.clone();
    carried_key_tamper["ts_jwks"]["keys"][0]["use"] = Value::String("enc".to_owned());
    assert!(scitt::verified_scitt_pack_keys(&carried_key_tamper, &local_roots, &statement).is_none());
}

#[test]
fn inclusion_numbers_must_match_the_signed_checkpoint() {
    let dir = scitt_dir();
    let pack = read_json(dir.join("registered_valid.pack.json"));
    let statement = unhex(pack["signed_statement"].as_str().unwrap());
    let receipt = unhex(pack["receipt"].as_str().unwrap());
    let cid = pack["certificate_id"].as_str().unwrap();
    let ts_keys = keys_from_jwks(&pack["ts_jwks"]);
    let issuer_keys = keys_from_jwks(&read_json(dir.join("keys.json"))["issuer_jwks"]);

    let size_mismatch = mutate_inclusion_number(&receipt, &ts_keys, 0, 2);
    assert!(!scitt::verify_scitt_receipt(&statement, &size_mismatch, &ts_keys, &issuer_keys, cid));
    let out_of_range = mutate_inclusion_number(&receipt, &ts_keys, 1, 1);
    assert!(!scitt::verify_scitt_receipt(&statement, &out_of_range, &ts_keys, &issuer_keys, cid));
}
