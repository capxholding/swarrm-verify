// Apache-2.0 (public verifier repo)
//! Mirror of tests/test_authority_golden.py: the Rust engine derives
//! authority facts (SPEC/authority-v1.md §4-§7) from the SAME golden bundles
//! and must reproduce expected_authority.json exactly — intent_interval and
//! byte-identical subject IDs included. Divergence is a spec bug.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles")
}

#[test]
fn authority_golden_agrees_with_expected() {
    let dir = golden_dir();
    let expected: Value = serde_json::from_str(&fs::read_to_string(dir.join("expected_authority.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (name, want) in expected.as_object().unwrap() {
        let bundle: Value = serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap()).unwrap();
        let got = swarrm_verify::action::authority_facts(&bundle, None);
        assert_eq!(&got, want, "fixture {name}: Rust authority_facts diverges");
        checked += 1;
    }
    assert!(checked >= 19, "expected at least 19 authority fixtures, ran {checked}");
}
