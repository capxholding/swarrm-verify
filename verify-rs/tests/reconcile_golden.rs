// Apache-2.0 (public verifier repo)
//! B23 reconcile golden suite: the Rust engine runs the SAME verdict-input
//! documents the reconcile pipeline built (scripts/gen_reconcile_golden.py,
//! tests/golden/reconcile/) and must produce vectors equal to
//! expected_vectors.json. Two independent implementations agreeing on the
//! closed B23 gate results is the conformance contract.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn reconcile_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/golden/reconcile")
}

#[test]
fn reconcile_suite_agrees_with_expected_vectors() {
    let dir = reconcile_dir();
    let expected: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("expected_vectors.json")).unwrap())
            .unwrap();
    // the relying-party anchors these goldens were generated under
    let trust: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("trust_context.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (name, want) in expected.as_object().unwrap() {
        let input: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap())
                .unwrap();
        let got = swarrm_verify::action::derive_vector_with_trust(&input, Some(&trust));
        assert_eq!(&got, want, "fixture {name}: Rust vector diverges from expected");
        checked += 1;
    }
    assert!(
        checked >= 8,
        "expected at least 8 reconcile fixtures, ran {checked}"
    );
}
