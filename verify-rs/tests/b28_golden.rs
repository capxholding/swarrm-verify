// Apache-2.0 (public verifier repo)
//! Native Rust half of the raw B28 Python/Rust/WASM parity corpus.

use serde_json::Value as J;
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use swarrm_verify::b28::verify_b28_cwt;

const B28_TRUST_PACK_PIN: [u8; 32] = [0x04, 0x2b, 0x49, 0x80, 0x6f, 0xbe, 0x4e, 0x17, 0x58, 0x28, 0xbd, 0xbf, 0xc9, 0x63, 0x86, 0xe8, 0xec, 0x88, 0xa7, 0x1d, 0x38, 0x6e, 0xd2, 0x53, 0x6d, 0x8c, 0x30, 0x45, 0x9c, 0x25, 0xc5, 0xcc];

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/golden/b28")
}

fn manifest() -> J {
    serde_json::from_slice(&fs::read(dir().join("manifest.json")).unwrap()).unwrap()
}

fn digest(raw: &[u8]) -> String {
    Sha256::digest(raw).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn verify_exchange(raw: &[u8], local_context: &[u8]) -> String {
    let pack = fs::read(dir().join("trust-pack.cbor")).unwrap();
    verify_b28_cwt(raw, local_context, &pack, &B28_TRUST_PACK_PIN)
}

fn context(name: &str) -> Vec<u8> {
    fs::read(dir().join(name)).unwrap()
}

#[test]
fn raw_corpus_hashes_and_read_only_result_match_python() {
    let expected = manifest();
    for (name, hash) in expected["inputs"].as_object().unwrap() {
        let raw = fs::read(dir().join(name)).unwrap();
        assert_eq!(digest(&raw), hash.as_str().unwrap(), "{name}");
    }
    let input = fs::read(dir().join("verify-input.cbor")).unwrap();
    let got: J = serde_json::from_str(&verify_exchange(&input, &context("verify-context.cbor"))).unwrap();
    assert_eq!(got, expected["expected_read_only"]);
    let successor = fs::read(dir().join("successor-input.cbor")).unwrap();
    let got: J = serde_json::from_str(&verify_exchange(&successor, &context("successor-context.cbor"))).unwrap();
    assert_eq!(got, expected["expected_successor_read_only"]);
}

#[test]
fn every_strict_profile_hostile_case_matches_python() {
    let expected = manifest();
    let context = context("verify-context.cbor");
    for (name, item) in expected["hostile"].as_object().unwrap() {
        let raw = fs::read(dir().join("hostile").join(format!("{name}.input.cbor"))).unwrap();
        assert_eq!(digest(&raw), item["sha256"].as_str().unwrap(), "{name}");
        let got: J = serde_json::from_str(&verify_exchange(&raw, &context)).unwrap();
        assert_eq!(got, item["expected"], "{name}");
    }
}

#[test]
fn successor_hostile_cases_match_python() {
    let expected = manifest();
    let context = context("successor-context.cbor");
    for (name, item) in expected["successor_hostile"].as_object().unwrap() {
        let raw = fs::read(dir().join("successor-hostile").join(format!("{name}.input.cbor"))).unwrap();
        assert_eq!(digest(&raw), item["sha256"].as_str().unwrap(), "{name}");
        let got: J = serde_json::from_str(&verify_exchange(&raw, &context)).unwrap();
        assert_eq!(got, item["expected"], "{name}");
    }
}

#[test]
fn hostile_local_contexts_match_python() {
    let expected = manifest();
    let exchange = fs::read(dir().join("verify-input.cbor")).unwrap();
    for (name, item) in expected["context_hostile"].as_object().unwrap() {
        let context = fs::read(dir().join("context-hostile").join(format!("{name}.context.cbor"))).unwrap();
        assert_eq!(digest(&context), item["sha256"].as_str().unwrap(), "{name}");
        let got: J = serde_json::from_str(&verify_exchange(&exchange, &context)).unwrap();
        assert_eq!(got, item["expected"], "{name}");
    }
}

#[test]
fn signed_refusal_matches_python_without_authorizing_execution() {
    let expected = manifest();
    let input = fs::read(dir().join("refusal-input.cbor")).unwrap();
    let got: J = serde_json::from_str(&verify_exchange(&input, &context("refusal-context.cbor"))).unwrap();
    assert_eq!(got, expected["expected_refusal"]);
    assert_eq!(got["verdict"], "FAIL");
    assert_eq!(got["should_execute"], false);
}

#[test]
fn hostile_signed_refusals_match_python() {
    let expected = manifest();
    for (name, item) in expected["refusal_hostile"].as_object().unwrap() {
        let raw = fs::read(dir().join("refusal-hostile").join(format!("{name}.exchange.cbor"))).unwrap();
        let context = fs::read(dir().join("refusal-hostile").join(format!("{name}.context.cbor"))).unwrap();
        assert_eq!(digest(&raw), item["exchange_sha256"].as_str().unwrap(), "{name} exchange");
        assert_eq!(digest(&context), item["context_sha256"].as_str().unwrap(), "{name} context");
        let got: J = serde_json::from_str(&verify_exchange(&raw, &context)).unwrap();
        assert_eq!(got, item["expected"], "{name}");
    }
}

#[test]
fn hostile_authority_states_match_python() {
    let expected = manifest();
    for (name, item) in expected["state_hostile"].as_object().unwrap() {
        let raw = fs::read(dir().join("state-hostile").join(format!("{name}.exchange.cbor"))).unwrap();
        let context = fs::read(dir().join("state-hostile").join(format!("{name}.context.cbor"))).unwrap();
        assert_eq!(digest(&raw), item["exchange_sha256"].as_str().unwrap(), "{name} exchange");
        assert_eq!(digest(&context), item["context_sha256"].as_str().unwrap(), "{name} context");
        let got: J = serde_json::from_str(&verify_exchange(&raw, &context)).unwrap();
        assert_eq!(got, item["expected"], "{name}");
    }
}

#[test]
fn bounded_mutations_fail_closed_without_panicking() {
    let input = fs::read(dir().join("verify-input.cbor")).unwrap();
    let context = context("verify-context.cbor");
    let stride = (input.len() / 256).max(1);
    for offset in (0..input.len()).step_by(stride) {
        let mut changed = input.clone();
        changed[offset] ^= 1;
        let got: J = serde_json::from_str(&verify_exchange(&changed, &context)).unwrap();
        assert_ne!(got["verdict"], "PASS", "byte {offset}");
        assert_eq!(got["should_execute"], false, "byte {offset}");
    }
    let oversized = vec![0; 2 * 1024 * 1024 + 1];
    let got: J = serde_json::from_str(&verify_exchange(&oversized, &context)).unwrap();
    assert_eq!(got["verdict"], "INDETERMINATE");
    assert_eq!(got["reasons"], serde_json::json!(["VERIFIER_CONTEXT_INVALID"]));
}
