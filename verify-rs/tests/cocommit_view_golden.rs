// Apache-2.0 (public verifier repo)
//! Mirror of tests/test_cocommit_view_golden.py: both engines must accept the
//! SAME `cocommit_shown_view` fixture, which is the one committed bundle that
//! carries the four shown_* co-commit view members, and a drop or change of
//! any member must be visible. Divergence is a spec bug.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

const FIXTURE: &str = "cocommit_shown_view";
const SHOWN_VIEW_MEMBERS: [&str; 4] = ["shown_checkpoint_hash", "shown_origin", "shown_root_hash", "shown_tree_size"];

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles")
}

fn load_bundle() -> Value {
    serde_json::from_str(&fs::read_to_string(golden_dir().join(format!("{FIXTURE}.json"))).unwrap()).unwrap()
}

fn decode_payload(entry: &Value) -> Value {
    let raw = B64.decode(entry["envelope"]["payload"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

fn cocommit_index(bundle: &Value) -> usize {
    let entries = bundle["entries"].as_array().unwrap();
    let found: Vec<usize> = entries.iter().enumerate().filter(|(_, entry)| decode_payload(entry)["action_type"] == "cocommit.head.signed").map(|(i, _)| i).collect();
    assert_eq!(found.len(), 1, "expected one cocommit.head.signed receipt, found {}", found.len());
    found[0]
}

fn shown_context(bundle: &Value) -> Value {
    decode_payload(&bundle["entries"][cocommit_index(bundle)])["context"].clone()
}

fn rewrite_payload(bundle: &mut Value, body: &Value) {
    let index = cocommit_index(bundle);
    bundle["entries"][index]["envelope"]["payload"] = Value::String(B64.encode(serde_json::to_vec(body).unwrap()));
}

fn carried_checkpoints(bundle: &Value) -> Vec<Value> {
    let mut bodies = Vec::new();
    if let Some(chain) = bundle.get("checkpoint_chain").and_then(Value::as_array) {
        for item in chain {
            if let Some(body) = item.get("checkpoint").and_then(|c| c.get("body")) {
                bodies.push(body.clone());
            }
        }
    }
    if let Some(body) = bundle.get("target_checkpoint").and_then(|c| c.get("body")) {
        bodies.push(body.clone());
    }
    bodies
}

fn hex64(value: &Value) -> bool {
    value.as_str().is_some_and(|text| text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}

#[test]
fn cocommit_shown_view_is_in_the_shared_verdict_suite() {
    let expected: Value = serde_json::from_str(&fs::read_to_string(golden_dir().join("expected.json")).unwrap()).unwrap();
    assert_eq!(expected[FIXTURE], "VERIFIED");
}

#[test]
fn both_engines_accept_the_shown_view_fixture() {
    let bundle = load_bundle();
    assert!(swarrm_verify::verify_bundle(&bundle), "cocommit_shown_view must verify");
}

#[test]
fn the_fixture_carries_all_four_shown_view_members_naming_a_carried_checkpoint() {
    let bundle = load_bundle();
    let ctx = shown_context(&bundle);
    for member in SHOWN_VIEW_MEMBERS {
        assert!(ctx.get(member).is_some(), "shown-view member {member} missing from signed payload");
    }
    let digest = &ctx["shown_checkpoint_hash"];
    let origin = ctx["shown_origin"].as_str().unwrap();
    let root = &ctx["shown_root_hash"];
    let size = ctx["shown_tree_size"].as_i64().unwrap();
    assert!(hex64(digest), "shown_checkpoint_hash must be 64 lowercase hex");
    assert!(!origin.is_empty(), "shown_origin must be non-empty");
    assert!(hex64(root), "shown_root_hash must be 64 lowercase hex");
    assert!(size >= 1, "shown_tree_size must be at least 1");
    let matches = carried_checkpoints(&bundle).into_iter().any(|body| body.get("origin").and_then(Value::as_str) == Some(origin) && body.get("root_hash") == Some(root) && body.get("tree_size").and_then(Value::as_i64) == Some(size));
    assert!(matches, "shown_* members do not name any checkpoint this bundle carries");
}

#[test]
fn mutating_a_shown_view_member_cannot_stay_silent() {
    let honest = load_bundle();
    assert!(swarrm_verify::verify_bundle(&honest), "control fixture must verify");
    for member in SHOWN_VIEW_MEMBERS {
        for kind in ["drop", "change"] {
            let mut bundle = honest.clone();
            let mut body = decode_payload(&bundle["entries"][cocommit_index(&bundle)]);
            if kind == "drop" {
                body["context"].as_object_mut().unwrap().remove(member);
            } else if member == "shown_tree_size" {
                let size = body["context"][member].as_i64().unwrap();
                body["context"][member] = Value::from(size + 1);
            } else if member == "shown_origin" {
                let origin = format!("{}/mutated", body["context"][member].as_str().unwrap());
                body["context"][member] = Value::String(origin);
            } else {
                let mut hex = body["context"][member].as_str().unwrap().to_owned();
                let last = if hex.ends_with('b') { 'a' } else { 'b' };
                hex.pop();
                hex.push(last);
                body["context"][member] = Value::String(hex);
            }
            rewrite_payload(&mut bundle, &body);
            assert!(!swarrm_verify::verify_bundle(&bundle), "{kind} of {member} was accepted");
        }
    }
}
