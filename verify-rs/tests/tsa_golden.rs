// Apache-2.0 (public verifier repo)
//! RFC 3161 golden fixtures (H6 remainder): the SAME files as
//! tests/test_tsa_golden.py. Rust asserts its `rust` column in
//! expected_tsa.json. The sanctioned verifier covers ECDSA P-256/P-384 and
//! RSASSA-PKCS1-v1_5, so both columns agree on every stored token.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles")
}

#[test]
fn tsa_golden_agrees_with_expected() {
    let expected: Value = serde_json::from_str(&fs::read_to_string(golden_dir().join("expected_tsa.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (name, case) in expected.as_object().unwrap() {
        if name.starts_with('_') {
            continue;
        }
        let token = fs::read(golden_dir().join(case["token"].as_str().unwrap())).unwrap();
        let chain = fs::read_to_string(golden_dir().join(case["chain"].as_str().unwrap())).unwrap();
        let got = swarrm_verify::tsa::verify_tst(&token, case["digest"].as_str().unwrap(), &chain);
        assert_eq!(got, case["rust"].as_bool().unwrap(), "fixture {name}: Rust got {got}, expected {}", case["rust"]);
        if case["python"] != case["rust"] {
            assert!(case["why_diverges"].is_string(), "fixture {name}: undocumented python/rust divergence");
        }
        checked += 1;
    }
    assert!(checked >= 5, "expected at least 5 TSA fixtures, ran {checked}");
}

#[test]
fn tsa_malformed_input_is_false_never_a_panic() {
    let chain = fs::read_to_string(golden_dir().join("tsa_p256_chain.pem")).unwrap();
    let token = fs::read(golden_dir().join("tsa_p256_valid.der")).unwrap();
    let digest = "ab".repeat(32);
    // hostile bytes in every argument position
    assert!(!swarrm_verify::tsa::verify_tst(b"", &digest, &chain));
    assert!(!swarrm_verify::tsa::verify_tst(&[0x30, 0x03, 0x02, 0x01, 0x01], &digest, &chain));
    assert!(!swarrm_verify::tsa::verify_tst(&[0xffu8; 64], &digest, &chain));
    assert!(!swarrm_verify::tsa::verify_tst(&token[..token.len() / 2], &digest, &chain));
    assert!(!swarrm_verify::tsa::verify_tst(&token, "not-hex", &chain));
    assert!(!swarrm_verify::tsa::verify_tst(&token, "", &chain));
    assert!(!swarrm_verify::tsa::verify_tst(&token, &digest, ""));
    assert!(!swarrm_verify::tsa::verify_tst(&token, &digest, "no pem here"));
    // uppercase hex never matches — string compare, exactly like Python
    let expected: Value = serde_json::from_str(&fs::read_to_string(golden_dir().join("expected_tsa.json")).unwrap()).unwrap();
    let real = expected["tsa_p256_valid"]["digest"].as_str().unwrap();
    assert!(swarrm_verify::tsa::verify_tst(&token, real, &chain));
    assert_eq!(swarrm_verify::tsa::verify_tst_gen_time(&token, real, &chain).as_deref(), Some("2026-07-17T21:38:25Z"));
    assert!(!swarrm_verify::tsa::verify_tst(&token, &real.to_uppercase(), &chain));
}
