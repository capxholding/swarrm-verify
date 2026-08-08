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
    let first = swarrm_verify::verify_bundle(&bundle);
    let second = swarrm_verify::verify_bundle(&bundle);
    assert_eq!(first, second, "bundle verification must be deterministic");
});
