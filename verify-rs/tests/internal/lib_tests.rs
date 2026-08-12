use super::*;

const VALID: &str = include_str!("../../../tests/golden/bundles/valid_e1.json");
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

fn bundle_with_fragment(fragment: &str) -> String {
    let base = VALID.trim_end();
    format!("{},{}{}", &base[..base.len() - 1], fragment, '}')
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
fn browser_entry_enforces_the_shared_json_number_profile() {
    let profile: Value = serde_json::from_str(include_str!("../../../tests/golden/json_number_profile.json")).unwrap();
    for (name, case) in profile.as_object().unwrap() {
        let token = case["token"].as_str().map(str::to_owned).unwrap_or_else(|| format!("{}{}{}", case["prefix"].as_str().unwrap_or(""), case["repeat"].as_str().unwrap().repeat(case["count"].as_u64().unwrap() as usize), case["suffix"].as_str().unwrap_or("")));
        let got = result(&bundle_with_fragment(&format!("\"number_probe\":{token}")));
        assert_eq!(got["verdict"], case["rust_verdict"], "{name}");
        assert_eq!(got["bundle_digest"].is_string(), case["accepted"].as_bool().unwrap(), "{name}");
    }
}

#[test]
fn browser_entry_rejects_nested_and_top_level_duplicate_keys() {
    let profile: Value = serde_json::from_str(include_str!("../../../tests/golden/json_duplicate_profile.json")).unwrap();
    for (name, fragment) in profile.as_object().unwrap() {
        let got = result(&bundle_with_fragment(fragment.as_str().unwrap()));
        assert_eq!(got["verdict"], "ERROR", "{name}");
        assert_eq!(got["error"], "INVALID_JSON", "{name}");
        assert!(got["bundle_digest"].is_null(), "{name}");
    }
}

#[test]
fn browser_entry_enforces_the_shared_unicode_scalar_profile() {
    let profile: Value = serde_json::from_str(include_str!("../../../tests/golden/json_unicode_profile.json")).unwrap();
    for (name, case) in profile.as_object().unwrap() {
        let got = result(&bundle_with_fragment(case["fragment"].as_str().unwrap()));
        let accepted = case["accepted"].as_bool().unwrap();
        assert_eq!(got["verdict"], if accepted { "VERIFIED" } else { "ERROR" }, "{name}");
        assert_eq!(got["bundle_digest"].is_string(), accepted, "{name}");
    }
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
    for (raw, accepted) in [(br#"{"n":9007199254740992}"#.as_slice(), true), (br#"{"n":-9007199254740992}"#, true), (br#"{"n":9007199254740993}"#, false), (br#"{"n":9007199254740994}"#, true)] {
        assert_eq!(body_of(&envelope(raw)).is_some(), accepted, "{}", String::from_utf8_lossy(raw));
    }
}

#[test]
fn rfc8785_appendix_b_numbers_match_python_profile() {
    let vectors: Value = serde_json::from_str(include_str!("../../../tests/golden/rfc8785_number_serialization.json")).unwrap();
    for case in vectors.as_array().unwrap() {
        let bits = u64::from_str_radix(case["ieee754"].as_str().unwrap(), 16).unwrap();
        let value = serde_json::Number::from_f64(f64::from_bits(bits)).map(Value::Number);
        let got = value.as_ref().and_then(crate::jcs::canonical_checked);
        let expected = case["canonical"].as_str().map(str::as_bytes);
        assert_eq!(got.as_deref(), expected, "{}", case["ieee754"]);
    }
}

#[test]
fn jcs_strings_use_required_minimal_escaping() {
    let value = serde_json::json!({"value": "\u{000f}\u{0008}\u{000c}\n\r\t\"\\/€ "});
    assert_eq!(crate::jcs::canonical_checked(&value).unwrap(), r#"{"value":"\u000f\b\f\n\r\t\"\\/€ "}"#.as_bytes());
}

#[test]
fn signed_action_semantics_remain_integer_only_inside_full_rfc8785_jcs() {
    let value = serde_json::json!({"nested": [1.5]});
    assert!(crate::jcs::canonical_checked(&value).is_some());
    assert!(crate::jcs::canonical_integer_checked(&value).is_none());
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
