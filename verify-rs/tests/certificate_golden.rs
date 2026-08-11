// Apache-2.0 (public verifier repo)
//! B24 W4 — the Rust engine runs the SAME certificate golden bytes the Python
//! engine compiled (scripts/gen_certificate_golden.py, tests/golden/
//! certificates/) and must reproduce the hand-authored load-bearing fields in
//! expected.json. It also replays the committed certfuzz corpus and the §4.1
//! over-cap synthetics fail-closed. Two independent implementations agreeing
//! on UNMARKED_ASSURANCE_WITHDRAWN / CLAIM_ONLY / CONTRADICTED / ORPHAN / GAPPED /
//! authority NOT_VERIFIED and a selectively-disclosed coreless view with no
//! recomputed vector or mark — and never panicking on hostile bytes — is the
//! B24 conformance contract.

use serde_json::Value;
use std::fs;
use std::path::PathBuf;

#[path = "../src/cbor.rs"]
#[allow(dead_code)]
mod cbor;
#[path = "../src/cbor_wire.rs"]
#[allow(dead_code)]
mod cbor_wire;

use ciborium::Value as CborValue;

fn certs_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/certificates")
}

fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/certfuzz")
}

/// The relying-party anchors these goldens were generated under — the SAME
/// file the Python runner loads, so both engines verify identically.
fn trust() -> Value {
    serde_json::from_str(&fs::read_to_string(certs_dir().join("trust_context.json")).unwrap()).unwrap()
}

fn verify(bytes: &[u8]) -> Value {
    serde_json::from_str(&swarrm_verify::certificate::verify_certificate_cbor_with_trust(bytes, Some(&trust()))).expect("result is valid JSON")
}

fn member_mut<'a>(value: &'a mut CborValue, key: &str) -> &'a mut CborValue {
    let CborValue::Map(members) = value else { panic!("expected map") };
    members.iter_mut().find_map(|(member, value)| matches!(member, CborValue::Text(name) if name == key).then_some(value)).unwrap_or_else(|| panic!("missing member {key}"))
}

#[test]
fn certificate_suite_agrees_with_expected() {
    let dir = certs_dir();
    let expected: Value = serde_json::from_str(&fs::read_to_string(dir.join("expected.json")).unwrap()).unwrap();
    let mut checked = 0;
    for (name, exp) in expected.as_object().unwrap() {
        let view = fs::read(dir.join(format!("{name}.view.cbor"))).unwrap();
        let got = verify(&view);
        assert_eq!(got["mark"], exp["mark"], "fixture {name}: mark");
        assert_eq!(got["cross_checks_ok"], exp["cross_checks_ok"], "fixture {name}: cross_checks_ok ({:?})", got["errors"]);
        for (key, value) in exp["vector"].as_object().unwrap() {
            assert_eq!(&got["vector"][key], value, "fixture {name}: vector[{key}]");
        }
        if !exp["partial"].is_null() {
            let partial = fs::read(dir.join(format!("{name}.partial.cbor"))).unwrap();
            let gp = verify(&partial);
            assert_eq!(gp["mark"], exp["partial"]["mark"], "fixture {name}: partial mark");
            assert_eq!(gp["core_present"], exp["partial"]["core_present"], "fixture {name}: partial core privacy");
            assert_eq!(gp["vector"]["technical_eligibility"], exp["partial"]["technical_eligibility"], "fixture {name}: partial technical_eligibility");
            assert_eq!(gp["errors"], exp["partial"]["errors"], "fixture {name}: partial errors");
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
        assert_ne!(res["mark"], Value::from("UNMARKED_ASSURANCE_WITHDRAWN"), "{:?}: headline pass", path);
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
        assert_ne!(res["mark"], Value::from("UNMARKED_ASSURANCE_WITHDRAWN"));
    }
}

#[test]
fn subject_display_fields_must_bind_to_verified_inputs() {
    let valid = fs::read(certs_dir().join("valid.core.cbor")).unwrap();
    for (field, replacement, error) in [("origin", "evd://tenant/t_attacker", "SUBJECT_ORIGIN_MISMATCH"), ("action_id", "act-attacker", "SUBJECT_ACTION_ID_MISMATCH"), ("action_class", "privileged.unrelated", "SUBJECT_ACTION_CLASS_MISMATCH")] {
        let mut core = cbor::decode_cbor(&valid, cbor::MAX_DEPTH as usize, cbor::MAX_BYTES).expect("valid fixture parses");
        *member_mut(member_mut(&mut core, "subject"), field) = CborValue::Text(replacement.into());
        let bytes = cbor::canonical_cbor(&core).expect("canonical replacement");
        let got = verify(&bytes);
        assert_eq!(got["cross_checks_ok"], Value::Bool(false), "{field}: {:?}", got["errors"]);
        assert!(got["errors"].as_array().unwrap().iter().any(|e| e.as_str() == Some(error)), "{field}: {:?}", got["errors"]);
    }
}

#[test]
fn certificate_action_identity_must_be_the_signed_intent_identity() {
    let valid = fs::read(certs_dir().join("valid.core.cbor")).unwrap();
    let mut core = cbor::decode_cbor(&valid, cbor::MAX_DEPTH as usize, cbor::MAX_BYTES).expect("valid fixture parses");
    *member_mut(member_mut(&mut core, "subject"), "action_class") = CborValue::Text("privileged.unrelated".into());
    *member_mut(member_mut(member_mut(&mut core, "verdict_input"), "action"), "action_class") = CborValue::Text("privileged.unrelated".into());

    let got = verify(&cbor::canonical_cbor(&core).expect("canonical replacement"));

    assert_eq!(got["cross_checks_ok"], Value::Bool(false), "{:?}", got["errors"]);
    assert!(got["errors"].as_array().unwrap().iter().any(|e| e.as_str() == Some("ACTION_CONTEXT_MISMATCH")), "{:?}", got["errors"]);
}

#[test]
fn certificate_action_id_cannot_be_erased_from_display_and_input() {
    let valid = fs::read(certs_dir().join("valid.core.cbor")).unwrap();
    let mut core = cbor::decode_cbor(&valid, cbor::MAX_DEPTH as usize, cbor::MAX_BYTES).expect("valid fixture parses");
    *member_mut(member_mut(&mut core, "subject"), "action_id") = CborValue::Text(String::new());
    *member_mut(member_mut(member_mut(&mut core, "verdict_input"), "action"), "action_id") = CborValue::Text(String::new());

    let got = verify(&cbor::canonical_cbor(&core).expect("canonical replacement"));

    assert_eq!(got["cross_checks_ok"], Value::Bool(false), "{:?}", got["errors"]);
    assert!(got["errors"].as_array().unwrap().iter().any(|e| e.as_str() == Some("SUBJECT_ACTION_ID_MISMATCH")), "{:?}", got["errors"]);
}

#[test]
fn certificate_subject_ids_must_be_recomputed_from_authority() {
    let valid = fs::read(certs_dir().join("valid.core.cbor")).unwrap();
    let mut core = cbor::decode_cbor(&valid, cbor::MAX_DEPTH as usize, cbor::MAX_BYTES).expect("valid fixture parses");
    *member_mut(member_mut(&mut core, "subject"), "subject_ids") = CborValue::Map(vec![(CborValue::Text("org_id".into()), CborValue::Text("00".repeat(32)))]);

    let got = verify(&cbor::canonical_cbor(&core).expect("canonical replacement"));

    assert_eq!(got["cross_checks_ok"], Value::Bool(false), "{:?}", got["errors"]);
    assert!(got["errors"].as_array().unwrap().iter().any(|e| e.as_str() == Some("SUBJECT_IDS_MISMATCH")), "{:?}", got["errors"]);
}
