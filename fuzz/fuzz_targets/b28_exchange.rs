#![no_main]

use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};

const MAX_INPUT: usize = 2 * 1024 * 1024 + 1;
const EXCHANGE: &[u8] = include_bytes!("../../tests/golden/b28/verify-input.cbor");
const CONTEXT: &[u8] = include_bytes!("../../tests/golden/b28/verify-context.cbor");
const TRUST_PACK: &[u8] = include_bytes!("../../tests/golden/b28/trust-pack.cbor");

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }
    let selector = data[0] % 3;
    let payload = &data[1..];
    let (exchange, context, trust_pack) = match selector {
        0 => (payload, CONTEXT, TRUST_PACK),
        1 => (EXCHANGE, payload, TRUST_PACK),
        _ => (EXCHANGE, CONTEXT, payload),
    };
    let digest = Sha256::digest(trust_pack);
    let first = swarrm_verify::b28::verify_b28_cwt(exchange, context, trust_pack, &digest);
    let second = swarrm_verify::b28::verify_b28_cwt(exchange, context, trust_pack, &digest);
    assert_eq!(first, second, "B28 verification must be deterministic");

    let report: serde_json::Value = serde_json::from_str(&first).expect("B28 verifier always returns JSON");
    let object = report.as_object().expect("B28 report is an object");
    assert_eq!(object.get("should_execute"), Some(&serde_json::Value::Bool(false)));
    assert_ne!(object.get("verdict").and_then(serde_json::Value::as_str), Some("PASS"));
    assert_eq!(object.len(), 4, "B28 report shape must stay closed");
});
