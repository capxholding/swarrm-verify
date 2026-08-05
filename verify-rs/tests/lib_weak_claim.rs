// Apache-2.0 (public verifier repo)
//! Two engines, one answer — the weak-claim seam in verify-rs/src/lib.rs
//! (owner audit 2026-08-05).
//!
//! Both cases below let a hostile bundle read as VERIFIED in Rust while Python
//! rejects it, which breaks the product claim that either engine answers the
//! same question. The Python half of each is asserted in
//! tests/test_engine_parity.py; if you change either, change both.

use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;

fn load_bundle(name: &str) -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles").join(name);
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// DO NOT BREAK HONEST BEHAVIOUR: the fixture carries a real string `kid` and a
/// real hex proof, and it must stay VERIFIED through both fixes.
#[test]
fn the_baseline_bundle_is_genuinely_valid() {
    let bundle = load_bundle("valid_e1.json");
    assert!(bundle["jwks"]["keys"][0]["kid"].is_string(), "fixture must exercise the string-kid path");
    assert!(swarrm_verify::verify_bundle(&bundle));
}

/// SPEC/bundle-v1.md §3.1: "every JWK's kid matches its key material; reject
/// aliases." The check was guarded by `.as_str()`, so a kid that was present
/// but not a string skipped it entirely and the alias was never rejected.
/// House convention (tests/test_engine_parity.py): a carried member that is not
/// the shape it claims is MALFORMED, not absent.
#[test]
fn a_present_non_string_kid_is_malformed_not_absent() {
    let base = load_bundle("valid_e1.json");
    for junk in [json!(false), json!(0), json!(3.5), json!({}), json!([]), json!("")] {
        let mut bundle = base.clone();
        bundle["jwks"]["keys"][0]["kid"] = junk.clone();
        assert!(!swarrm_verify::verify_bundle(&bundle), "jwks.keys[0].kid = {junk} is malformed, not an absent claim");
    }
}

/// `null` stays equal to missing — the `.get()` semantics the rest of the
/// verifier documents. A producer emitting null for an optional makes no claim,
/// and verify-rs recomputes the kid from the key material anyway.
///
/// KNOWN DIVERGENCE, pinned here so it is not mistaken for parity: Python keys
/// its JWKS by the CARRIED kid (verify/verifier.py, core/keys.py:120), so it
/// answers NOT VERIFIED for both of these — "jwks kid None is not witnessed by
/// the key log" for absent, "kid does not match key material" for null. That
/// predates this fix and lives in files this change does not own; see notes.
#[test]
fn an_absent_or_null_kid_makes_no_claim() {
    let base = load_bundle("valid_e1.json");
    let mut nulled = base.clone();
    nulled["jwks"]["keys"][0]["kid"] = Value::Null;
    assert!(swarrm_verify::verify_bundle(&nulled), "null kid claims nothing and must not fail the bundle");

    let mut absent = base;
    absent["jwks"]["keys"][0].as_object_mut().unwrap().remove("kid");
    assert!(swarrm_verify::verify_bundle(&absent), "absent kid claims nothing and must not fail the bundle");
}

/// An alias — a syntactically fine kid that names other key material — is still
/// rejected. This is the check that was being skipped.
#[test]
fn a_string_kid_that_aliases_other_key_material_is_rejected() {
    let mut bundle = load_bundle("valid_e1.json");
    bundle["jwks"]["keys"][0]["kid"] = json!("AAAAAAAAAAAAAAAA");
    assert!(!swarrm_verify::verify_bundle(&bundle));
}

/// Malformed proof elements were dropped by `filter_map`, so a proof with junk
/// spliced in was evaluated as a SHORTER proof rather than rejected. Python
/// does not drop: `bytes.fromhex` raises and the bundle is NOT VERIFIED.
#[test]
fn a_malformed_element_rejects_the_whole_inclusion_proof() {
    let base = load_bundle("valid_e1.json");
    assert!(!base["entries"][0]["inclusion_proof"].as_array().unwrap().is_empty(), "fixture must carry a non-empty inclusion proof");
    for junk in [json!("zz"), json!("abc"), json!(""), json!("00"), json!(false), json!(0), json!(null), json!([]), json!("ffff")] {
        let mut bundle = base.clone();
        bundle["entries"][0]["inclusion_proof"].as_array_mut().unwrap().push(junk.clone());
        assert!(!swarrm_verify::verify_bundle(&bundle), "inclusion proof element {junk} must reject the proof, not shorten it");
    }
    // absent/null stays the no-claim empty proof, and a carried non-list is
    // malformed — all three are NOT VERIFIED here, as in Python.
    for carried in [Some(json!("abc")), Some(json!({})), Some(Value::Null), None] {
        let mut bundle = base.clone();
        match carried {
            Some(v) => bundle["entries"][0]["inclusion_proof"] = v,
            None => {
                bundle["entries"][0].as_object_mut().unwrap().remove("inclusion_proof");
            }
        }
        assert!(!swarrm_verify::verify_bundle(&bundle), "a four-leaf tree is not proven by a proof that is not two hashes");
    }
}

/// Same drop, same fix, on the checkpoint-chain consistency proof.
#[test]
fn a_malformed_element_rejects_the_whole_consistency_proof() {
    let base = load_bundle("b21_authority_valid.json");
    assert!(swarrm_verify::verify_bundle(&base), "the two-checkpoint fixture must be valid to start");
    let step = base["checkpoint_chain"].as_array().unwrap().len() - 1;
    for junk in [json!("zz"), json!("abc"), json!(false), json!(null), json!({})] {
        let mut bundle = base.clone();
        bundle["checkpoint_chain"][step]["consistency_from_prev"].as_array_mut().unwrap().push(junk.clone());
        assert!(!swarrm_verify::verify_bundle(&bundle), "consistency proof element {junk} must reject the proof, not shorten it");
    }
    for carried in [json!("abc"), json!({}), Value::Null] {
        let mut bundle = base.clone();
        bundle["checkpoint_chain"][step]["consistency_from_prev"] = carried;
        assert!(!swarrm_verify::verify_bundle(&bundle), "a 6-to-8 leaf extension is not proven by a proof that is not three hashes");
    }
}
