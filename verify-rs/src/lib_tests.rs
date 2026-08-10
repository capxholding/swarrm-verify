use super::*;

const VALID: &str = include_str!("../../tests/golden/bundles/valid_e1.json");
const VALID_DIGEST: &str = "c3c85b1143c937cacf692eb37377b72be4d53941055262623c022c64916e8239";

fn result(input: &str) -> Value {
    serde_json::from_str(&browser_bundle_verification_result(input)).unwrap()
}

fn assert_closed_shape(value: &Value) {
    let object = value.as_object().unwrap();
    assert_eq!(object.len(), 4);
    for field in ["schema", "verdict", "bundle_digest", "error"] {
        assert!(object.contains_key(field), "missing {field}");
    }
}

#[test]
fn verified_result_carries_only_the_recomputed_canonical_bundle_digest() {
    let pretty = result(VALID);
    let compact = result(&serde_json::to_string(&serde_json::from_str::<Value>(VALID).unwrap()).unwrap());
    for got in [&pretty, &compact] {
        assert_closed_shape(got);
        assert_eq!(got["schema"], BROWSER_BUNDLE_RESULT_SCHEMA);
        assert_eq!(got["verdict"], "VERIFIED");
        assert_eq!(got["bundle_digest"], VALID_DIGEST);
        assert!(got["error"].is_null());
    }
}

#[test]
fn every_non_verified_result_suppresses_the_bundle_digest() {
    let mut tampered: Value = serde_json::from_str(VALID).unwrap();
    tampered["entries"][0]["leaf_index"] = Value::Bool(false);
    let cases = [result(&serde_json::to_string(&tampered).unwrap()), result("{"), result(&"x".repeat(MAX_BUNDLE_BYTES + 1))];
    for got in &cases {
        assert_closed_shape(got);
        assert_ne!(got["verdict"], "VERIFIED");
        assert!(got["bundle_digest"].is_null());
    }
    assert_eq!(cases[0]["verdict"], "NOT_VERIFIED");
    assert_eq!(cases[1]["verdict"], "ERROR");
    assert_eq!(cases[1]["error"], "INVALID_JSON");
    assert_eq!(cases[2]["verdict"], "NOT_VERIFIED");
}

#[test]
fn receipt_payloads_are_exact_jcs_in_both_verifier_engines() {
    let canonical = br#"{"action_type":"llm.chat","seq":1}"#;
    let envelope = |raw: &[u8]| {
        serde_json::json!({
            "payload": B64.encode(raw), "payloadType": RECEIPT_TYPE, "signatures": []
        })
    };
    assert!(body_of(&envelope(canonical)).is_some());
    for hostile in [br#"{"action_type":"shadow","action_type":"llm.chat","seq":1}"#.as_slice(), br#"{"seq":1,"action_type":"llm.chat"}"#, br#"{"action_type":"llm.chat","seq":1.0}"#, br#"{"action_type":"llm.chat","seq":1}\n"#] {
        assert!(body_of(&envelope(hostile)).is_none());
    }
}

#[test]
fn anchor_and_tst_times_share_the_strict_signed_checkpoint_boundary() {
    let signed = "2024-02-29T00:00:00Z";
    for (field, record) in [("block_ts", serde_json::json!({"block_ts": "2024-02-29T00:00:00.000001Z"})), ("gen_time", serde_json::json!({"gen_time": "2024-02-29T00:00:00.000001Z"}))] {
        assert!(record_not_before_checkpoint(&record, field, signed));
        for bad in ["2024-02-29T00:00:00.Z", "2024-02-30T00:00:00Z", "2024-02-28T23:59:59Z"] {
            let mut hostile = record.clone();
            hostile[field] = serde_json::json!(bad);
            assert!(!record_not_before_checkpoint(&hostile, field, signed), "{field}={bad}");
        }
    }
}

#[test]
fn canonical_utc_rejects_non_decimal_components_without_panicking() {
    for hostile in ["202x-01-01T00:00:00Z", "2026-0x-01T00:00:00Z", "2026-01-01T00:00:0xZ", "2026-01-01T00:00:00.00000xZ"] {
        assert!(!canonical_utc(hostile), "accepted {hostile}");
    }
}

#[test]
fn genesis_has_no_role_and_delegated_roles_only_apply_to_creation() {
    assert!(key_role_ok(0, "evd.key.created", &serde_json::json!({"role": null})));
    for role in ["recorder", "scitt-issuer"] {
        assert!(!key_role_ok(0, "evd.key.created", &serde_json::json!({"role": role})));
        assert!(key_role_ok(1, "evd.key.created", &serde_json::json!({"role": role})));
        assert!(!key_role_ok(1, "evd.key.rotated", &serde_json::json!({"role": role})));
        assert!(!key_role_ok(1, "evd.key.revoked", &serde_json::json!({"role": role})));
    }
}
