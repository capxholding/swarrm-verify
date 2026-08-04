// Apache-2.0 (public verifier repo)
//! Build 21 verdict fixtures: the Rust engine runs the SAME golden verdict
//! inputs as the Python verifier (tests/test_verdicts.py) and must produce
//! byte-identical vectors to expected_vectors.json. Two independent
//! implementations agreeing is the conformance contract.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn verdicts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/golden/verdicts")
}

#[test]
fn verdict_suite_agrees_with_expected_vectors() {
    let dir = verdicts_dir();
    let expected: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("expected_vectors.json")).unwrap())
            .unwrap();
    // The relying party's OWN anchors, out of band — the fixtures carry real
    // signatures and this names the keys that check them (src/trust.rs).
    let trust: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("trust_context.json")).unwrap()).unwrap();
    let mut checked = 0;
    let mut names: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().into_string().unwrap();
            name.strip_suffix(".json")
                .filter(|stem| stem.starts_with("va_"))
                .map(str::to_string)
        })
        .collect();
    names.sort();
    for name in names {
        let input: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(format!("{name}.json"))).unwrap())
                .unwrap();
        let got = swarrm_verify::action::derive_vector_with_trust(&input, Some(&trust));
        let want = expected
            .get(&name)
            .unwrap_or_else(|| panic!("fixture {name} missing from expected_vectors.json"));
        assert_eq!(&got, want, "fixture {name}: Rust vector diverges from expected");
        checked += 1;
    }
    assert!(
        checked >= 40,
        "expected at least 40 verdict fixtures, ran {checked}"
    );
}

/// THE regression guard for the owner audit (2026-08-03), mirroring
/// tests/test_verdicts.py: a subject's own document, with NO independently
/// supplied anchors, must never reach a favourable externally-grounded value —
/// whatever it declares.
#[test]
fn no_fixture_is_favourable_without_a_trust_anchor() {
    let dir = verdicts_dir();
    let weak = [
        ("node_observation", "NOT_OBSERVED"),
        ("node_integrity_basis", "LOG_WITNESSED_SOFTWARE"),
        ("coverage_basis", "INSUFFICIENT"),
        ("temporal_binding", "UNPROVEN"),
    ];
    // PENDING is not favourable, so registration is guarded as "never REGISTERED".
    // OVERLAPPING is an admission against interest -> believed without proof;
    // only the favourable INDEPENDENT is forbidden.
    // source_signature is guarded by FAVOURABILITY: NOT_RECOMPUTED is a per-view
    // statement ("the source signed, this view cannot check it"), legitimately
    // reachable with no anchor — it is simply not favourable.
    let never = [
        ("source_signature", "ASYMMETRIC"),
        ("source_signature", "SHARED_SECRET"),
        ("control_domain", "INDEPENDENT"),
        ("registration_status", "REGISTERED"),
        ("coverage", "CLOSED"),
        ("technical_eligibility", "ELIGIBLE"),
    ];
    let mut checked = 0;
    for entry in fs::read_dir(&dir).unwrap() {
        let name = entry.unwrap().file_name().into_string().unwrap();
        let Some(stem) = name.strip_suffix(".json").filter(|s| s.starts_with("va_")) else {
            continue;
        };
        let input: Value =
            serde_json::from_str(&fs::read_to_string(dir.join(format!("{stem}.json"))).unwrap())
                .unwrap();
        let v = swarrm_verify::action::derive_vector(&input); // no anchors
        for (dim, want) in weak {
            assert_eq!(v[dim], serde_json::json!(want), "{stem}: {dim} favourable with no anchor");
        }
        for (dim, forbidden) in never {
            assert_ne!(v[dim], serde_json::json!(forbidden), "{stem}: {dim} favourable, no anchor");
        }
        checked += 1;
    }
    assert!(checked >= 40, "ran {checked}");
}

#[test]
fn scan_binding_rejects_shared_noncanonical_cases() {
    let dir = verdicts_dir();
    let base: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("va_hardware_full_scan.json")).unwrap())
            .unwrap();
    let trust: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("trust_context.json")).unwrap()).unwrap();
    let cases: Value = serde_json::from_str(
        &fs::read_to_string(dir.join("negative/canonical_cases.json")).unwrap(),
    )
    .unwrap();
    for case in cases.as_array().unwrap() {
        let mut input = base.clone();
        if case.get("period_start").is_some() {
            input["batch"]["period_start"] = case["period_start"].clone();
            input["batch"]["period_end"] = case["period_end"].clone();
        } else {
            input["batch"]["attack"] =
                if let Some(depth) = case.get("depth").and_then(Value::as_u64) {
                    (0..depth).fold(Value::Null, |v, _| Value::Array(vec![v]))
                } else {
                    case["batch_value"].clone()
                };
        }
        input["scan"]["batch_digest"] = case["batch_digest"].clone();
        input["scan"]["signature"] = case["scan_signature"].clone();
        let got = swarrm_verify::action::derive_vector_with_trust(&input, Some(&trust));
        assert_eq!(got["node_observation"], "NOT_OBSERVED", "{}", case["name"]);
        assert_eq!(got["coverage"], "UNKNOWN", "{}", case["name"]);
        assert_eq!(got["coverage_basis"], "INSUFFICIENT", "{}", case["name"]);
    }
}
