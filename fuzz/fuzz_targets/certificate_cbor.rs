#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 1024 * 1024;
const REQUIRED_KEYS: [&str; 9] = [
    "parse_ok",
    "layers",
    "certificate_id",
    "core_present",
    "cross_checks_ok",
    "vector",
    "mark",
    "errors",
    "export_complete",
];

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let first = swarrm_verify::certificate::verify_certificate_cbor(data);
    let second = swarrm_verify::certificate::verify_certificate_cbor(data);
    assert_eq!(first, second, "certificate verification must be deterministic");
    let report: serde_json::Value = serde_json::from_str(&first).expect("certificate verifier always returns JSON");
    let object = report.as_object().expect("certificate report is an object");
    for key in REQUIRED_KEYS {
        assert!(object.contains_key(key), "certificate report is missing {key}");
    }
    assert_eq!(object.len(), REQUIRED_KEYS.len(), "certificate report shape must stay closed");
});
