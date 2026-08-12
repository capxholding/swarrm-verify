// Apache-2.0 (public verifier repo)
//! Shared selective-disclosure profile corpus; Python and WASM read the same file.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn verify_json(package: &str, bundle: &str) -> bool {
    swarrm_verify::verify_disclosure_json(package.as_bytes(), bundle.as_bytes())
}

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles")
}

#[test]
fn disclosure_golden_agrees_with_expected() {
    let dir = golden_dir();
    let bundle_json = fs::read_to_string(dir.join("disclosure_bundle.json")).unwrap();
    let bundle: Value = serde_json::from_str(&bundle_json).unwrap();
    assert!(swarrm_verify::verify_bundle(&bundle));
    let cases: Vec<Value> = serde_json::from_str(&fs::read_to_string(dir.join("disclosure_cases.json")).unwrap()).unwrap();
    assert!(cases.len() >= 40);
    for case in cases {
        let package = serde_json::to_string(&case["package"]).unwrap();
        let got = verify_json(&package, &bundle_json);
        assert_eq!(got, case["expected"].as_bool().unwrap(), "fixture {}", case["name"]);
    }
}

#[test]
fn disclosure_json_boundary_is_strict() {
    let bundle = fs::read_to_string(golden_dir().join("disclosure_bundle.json")).unwrap();
    assert!(!verify_json("{}", &bundle));
    assert!(!verify_json(r#"{"schema":"evd/disclosure/v1","schema":"evd/disclosure/v1"}"#, &bundle));
    assert!(!verify_json("{}", "{}"));
}
