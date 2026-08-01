// Apache-2.0 (public verifier repo)
//! Disclosure-package golden fixtures (H6a): the SAME files as
//! tests/test_disclosure_golden.py, same expectations. Two independent
//! implementations agreeing is the spec-hardening guarantee.

use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/golden/bundles")
}

fn load(name: &str) -> Value {
    let path = golden_dir().join(name);
    serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap()
}

#[test]
fn disclosure_golden_agrees_with_expected() {
    let bundle = load("disclosure_bundle.json");
    // a disclosure only means something against an already-verified bundle
    assert!(swarrm_verify::verify_bundle(&bundle));
    let expected = load("expected_disclosure.json");
    let mut checked = 0;
    for (name, want) in expected.as_object().unwrap() {
        let pkg = load(&format!("{name}.json"));
        let got = swarrm_verify::verify_disclosure(&pkg, &bundle);
        assert_eq!(
            got,
            want.as_bool().unwrap(),
            "fixture {name}: Rust got {got}, expected {want}"
        );
        checked += 1;
    }
    assert!(
        checked >= 2,
        "expected at least 2 disclosure fixtures, ran {checked}"
    );
}

#[test]
fn disclosure_malformed_input_is_false_never_a_panic() {
    let bundle = load("disclosure_bundle.json");
    let valid = load("disclosure_valid.json");
    // not a disclosure package at all
    assert!(!swarrm_verify::verify_disclosure(&json!({}), &bundle));
    assert!(!swarrm_verify::verify_disclosure(&json!({"schema": "evd/other/v1"}), &bundle));
    // bundle with no entries
    assert!(!swarrm_verify::verify_disclosure(&valid, &json!({})));
    // undecodable nonce / payload
    let mut p = valid.clone();
    p["nonce_hex"] = json!("zz");
    assert!(!swarrm_verify::verify_disclosure(&p, &bundle));
    let mut p = valid.clone();
    p["payload_b64"] = json!("%%%");
    assert!(!swarrm_verify::verify_disclosure(&p, &bundle));
    // unknown receipt / unknown committed field
    let mut p = valid.clone();
    p["receipt_hash"] = json!("ff".repeat(32));
    assert!(!swarrm_verify::verify_disclosure(&p, &bundle));
    let mut p = valid.clone();
    p["field"] = json!("no_such_field");
    assert!(!swarrm_verify::verify_disclosure(&p, &bundle));
    // unscoped domain and weak nonce never verify (privacy-model guards)
    let mut p = valid.clone();
    p["domain"] = json!("wrong/prefix");
    assert!(!swarrm_verify::verify_disclosure(&p, &bundle));
    let mut p = valid.clone();
    p["nonce_hex"] = json!("00".repeat(8));
    assert!(!swarrm_verify::verify_disclosure(&p, &bundle));
}
