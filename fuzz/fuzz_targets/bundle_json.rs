#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 1024 * 1024;

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_INPUT {
        return;
    }
    let Ok(bundle) = serde_json::from_slice(data) else {
        return;
    };
    let first = swarrm_verify::verify_bundle(&bundle, None);
    let second = swarrm_verify::verify_bundle(&bundle, None);
    assert_eq!(first, second, "bundle verification must be deterministic");
    let report = first.as_object().expect("bundle report is an object");
    assert_eq!(report.len(), 7, "bundle report shape must stay closed");
    let ok = report["ok"].as_bool().expect("bundle verdict is a boolean");
    assert!(report["recorder_attested"].is_array());
    assert!(report["trusted_tst_checkpoints"].is_array());
    assert!(report["chain_sizes"].is_object());
    assert!(report["continuity_gaps"].is_u64());
    assert!(report["continuity_present"].is_boolean());
    assert!(report["continuity_ok"].is_boolean());
    if !ok {
        assert!(report["recorder_attested"].as_array().unwrap().is_empty());
        assert!(report["trusted_tst_checkpoints"].as_array().unwrap().is_empty());
    }
});
