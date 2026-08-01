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
        let got = swarrm_verify::action::derive_vector(&input);
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
