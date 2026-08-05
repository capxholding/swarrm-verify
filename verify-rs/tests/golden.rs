// Apache-2.0 (public verifier repo)
//! The Rust verifier runs the SAME shared golden fixtures as the Python
//! verifier (tests/golden/) and must agree with expected.json. Two
//! independent implementations agreeing is the spec-hardening guarantee.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles")
}

#[test]
fn golden_suite_agrees_with_expected() {
    let dir = golden_dir();
    let expected: Value = serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (name, want) in expected.as_object().unwrap() {
        let bundle: Value = serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap()).unwrap();
        let got = if swarrm_verify::verify_bundle(&bundle) { "VERIFIED" } else { "NOT_VERIFIED" };
        assert_eq!(got, want.as_str().unwrap(), "fixture {name}: Rust got {got}, expected {}", want);
        checked += 1;
    }
    assert!(checked >= 6, "expected at least 6 golden fixtures, ran {checked}");
}
