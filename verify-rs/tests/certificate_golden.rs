// Apache-2.0 (public verifier repo)
//! B24 W4 — the Rust engine runs the SAME certificate golden bytes the Python
//! engine compiled (scripts/gen_certificate_golden.py, tests/golden/
//! certificates/) and must reproduce the hand-authored load-bearing fields in
//! expected.json. It also replays the committed certfuzz corpus and the §4.1
//! over-cap synthetics fail-closed. Two independent implementations agreeing
//! on VERIFIED_CORROBORATED / CLAIM_ONLY / CONTRADICTED / ORPHAN / GAPPED /
//! authority NOT_VERIFIED and the selectively-disclosed NOT_RECOMPUTED — and
//! never panicking on hostile bytes — is the B24 conformance contract.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

use swarrm_verify::certificate::verify_certificate_cbor;

fn certs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/golden/certificates")
}

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("tests/golden/certfuzz")
}

fn verify(bytes: &[u8]) -> Value {
    serde_json::from_str(&verify_certificate_cbor(bytes)).expect("result is valid JSON")
}

#[test]
fn certificate_suite_agrees_with_expected() {
    let dir = certs_dir();
    let expected: Value =
        serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (name, exp) in expected.as_object().unwrap() {
        let view = fs::read(dir.join(format!("{name}.view.cbor"))).unwrap();
        let got = verify(&view);
        assert_eq!(got["mark"], exp["mark"], "fixture {name}: mark");
        assert_eq!(
            got["cross_checks_ok"], exp["cross_checks_ok"],
            "fixture {name}: cross_checks_ok ({:?})",
            got["errors"]
        );
        for (key, value) in exp["vector"].as_object().unwrap() {
            assert_eq!(&got["vector"][key], value, "fixture {name}: vector[{key}]");
        }
        if !exp["partial"].is_null() {
            let partial = fs::read(dir.join(format!("{name}.partial.cbor"))).unwrap();
            let gp = verify(&partial);
            assert_eq!(gp["mark"], exp["partial"]["mark"], "fixture {name}: partial mark");
            assert_eq!(
                gp["vector"]["technical_eligibility"],
                exp["partial"]["technical_eligibility"],
                "fixture {name}: partial technical_eligibility"
            );
        }
        checked += 1;
    }
    assert!(checked >= 9, "expected at least 9 certificate families, ran {checked}");
}

#[test]
fn certfuzz_corpus_replays_crash_free() {
    let mut count = 0;
    for entry in fs::read_dir(fuzz_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let res = verify(&fs::read(&path).unwrap());
        assert!(res.get("parse_ok").is_some(), "{:?}: shape", path);
        assert_ne!(res["mark"], Value::from("VERIFIED_CORROBORATED"), "{:?}: headline pass", path);
        count += 1;
    }
    assert!(count >= 30, "expected at least 30 certfuzz cases, ran {count}");
}

#[test]
fn over_cap_synthetics_fail_closed() {
    let mut deep = vec![0x81u8; 65]; // 65 nested single-element arrays: past the depth cap
    deep.push(0x01);
    let huge = vec![0x5b, 0, 0, 1, 0, 0, 0, 0, 0, b'a', b'b']; // bstr header ~1 TiB, truncated
    let over_pack = vec![0u8; 16 * 1024 * 1024 + 1]; // past the 16 MiB pack cap
    for input in [deep, huge, over_pack] {
        let res = verify(&input);
        assert_eq!(res["parse_ok"], Value::Bool(false));
        assert_eq!(res["errors"][0], Value::from("PARSE"));
        assert_ne!(res["mark"], Value::from("VERIFIED_CORROBORATED"));
    }
}
