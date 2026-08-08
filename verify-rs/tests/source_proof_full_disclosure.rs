// Apache-2.0 (public verifier repo)
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};

fn fixture() -> Value {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/source_proof_full_disclosure.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn source_signature(input: &Value, trust: Option<&Value>) -> String {
    swarrm_verify::action::derive_vector_with_trust(input, trust)["source_signature"].as_str().unwrap().to_owned()
}

#[test]
fn retained_webhook_material_requires_local_trust_and_exact_context() {
    let fixture = fixture();
    let input = &fixture["verdict_input"];
    let trust = &fixture["trust"];
    assert_eq!(source_signature(input, None), "NONE");
    assert_eq!(source_signature(input, Some(trust)), fixture["expected"]);
    assert_eq!(source_signature(&fixture["mac_verdict_input"], None), "NONE");
    assert_eq!(source_signature(&fixture["mac_verdict_input"], Some(&fixture["mac_trust"])), fixture["mac_expected"]);

    let mut selective = input.clone();
    selective.as_object_mut().unwrap().remove("source_proofs");
    selective["view"] = json!({"withheld_fields": ["source_proofs"]});
    assert_eq!(source_signature(&selective, Some(trust)), "NOT_RECOMPUTED");

    let mut declaration = input.clone();
    declaration["source_proofs"][0]["verified"] = Value::Bool(true);
    assert_eq!(source_signature(&declaration, Some(trust)), "ASYMMETRIC");

    for (field, value) in [("material", Value::String("***not-base64***".into())), ("material_digest", Value::String("00".repeat(32))), ("signature_context", Value::String("vendor-guessed-context".into()))] {
        let mut hostile = input.clone();
        hostile["source_proofs"][0][field] = value;
        assert_eq!(source_signature(&hostile, Some(trust)), "NONE", "{field}");
    }

    let mut family = input.clone();
    family["source_identity"]["keys"][0]["algorithm_family"] = Value::String("Ed25519".into());
    assert_eq!(source_signature(&family, Some(trust)), "NONE");

    let mut kid = input.clone();
    kid["source_proofs"][0]["key_identity"] = Value::String("other-kid".into());
    assert_eq!(source_signature(&kid, Some(trust)), "NONE");
}

#[test]
fn duplicate_or_over_count_material_never_reaches_asymmetric() {
    let fixture = fixture();
    let mut input = fixture["verdict_input"].clone();
    let trust = &fixture["trust"];
    let encoded = input["source_proofs"][0]["material"].as_str().unwrap();
    let raw = String::from_utf8(B64.decode(encoded).unwrap()).unwrap();
    let duplicate = raw.replace("\"event_key\": \"evt-000000\"", "\"event_key\": \"evt-000000\", \"event_key\": \"evt-000000\"");
    let bytes = duplicate.as_bytes();
    input["source_proofs"][0]["material"] = Value::String(B64.encode(bytes));
    input["source_proofs"][0]["material_digest"] = Value::String(format!("{:x}", Sha256::digest(bytes)));
    assert_eq!(source_signature(&input, Some(trust)), "NONE");

    let mut trailing = fixture["verdict_input"].clone();
    let mut trailing_bytes = B64.decode(trailing["source_proofs"][0]["material"].as_str().unwrap()).unwrap();
    trailing_bytes.extend_from_slice(b"{}");
    trailing["source_proofs"][0]["material"] = Value::String(B64.encode(&trailing_bytes));
    trailing["source_proofs"][0]["material_digest"] = Value::String(format!("{:x}", Sha256::digest(&trailing_bytes)));
    assert_eq!(source_signature(&trailing, Some(trust)), "NONE");

    let mut oversized = fixture["verdict_input"].clone();
    let oversized_bytes = vec![b' '; 1024 * 1024 + 1];
    oversized["source_proofs"][0]["material"] = Value::String(B64.encode(&oversized_bytes));
    oversized["source_proofs"][0]["material_digest"] = Value::String(format!("{:x}", Sha256::digest(&oversized_bytes)));
    assert_eq!(source_signature(&oversized, Some(trust)), "NONE");

    let mut over_count = fixture["verdict_input"].clone();
    let proof = over_count["source_proofs"][0].clone();
    over_count["source_proofs"] = Value::Array(vec![proof; 129]);
    assert_eq!(source_signature(&over_count, Some(trust)), "NONE");
}
