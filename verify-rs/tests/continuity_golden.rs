// Apache-2.0 (public verifier repo)
//! Mirror of tests/test_continuity_golden.py: both engines must report the
//! same continuity presence, cover verdict and gap count for every case in
//! tests/golden/continuity/bundles.json, and the bundle stays VERIFIED in all
//! of them because continuity never gates. Divergence is a spec bug.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn document() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/continuity/bundles.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn trial(document: &Value, case: &Value) -> Value {
    let mut bundle = document["bundle"].clone();
    if let Some(continuity) = case.get("continuity") {
        bundle["continuity"] = continuity.clone();
    }
    bundle
}

#[test]
fn the_rust_engine_reports_every_case_and_the_verdict_never_moves() {
    let document = document();
    let cases = document["cases"].as_array().unwrap();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let bundle = trial(&document, case);
        assert!(swarrm_verify::verify_bundle(&bundle), "{name}: continuity must never gate");
        let got = swarrm_verify::verify_bundle_levels(&bundle, None);
        for member in ["continuity_present", "continuity_ok", "continuity_gaps"] {
            assert_eq!(got[member], case["expected"][member], "{name}: {member} — {}", case["why"]);
        }
    }
    assert!(cases.len() >= 15, "expected the full hostile set, ran {}", cases.len());
}

#[test]
fn an_absent_member_and_a_null_one_read_the_same() {
    let document = document();
    let by_name = |wanted: &str| document["cases"].as_array().unwrap().iter().find(|c| c["name"] == wanted).unwrap().clone();
    let absent = swarrm_verify::verify_bundle_levels(&trial(&document, &by_name("absent")), None);
    let null = swarrm_verify::verify_bundle_levels(&trial(&document, &by_name("null")), None);
    for member in ["continuity_present", "continuity_ok", "continuity_gaps"] {
        assert_eq!(absent[member], null[member], "{member}");
    }
}
