#![no_main]

use libfuzzer_sys::fuzz_target;

const MAX_INPUT: usize = 256 * 1024;
const TOKEN: &[u8] = include_bytes!("../../tests/golden/bundles/tsa_p256_valid.der");
const CHAIN: &str = include_str!("../../tests/golden/bundles/tsa_p256_chain.pem");
const DIGEST: &str = "7a5c8e2b9f1d4a6c3e8b0f2d5a7c9e1b4d6f8a0c2e5b7d9f1a3c5e7b9d0f2a4c";

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT {
        return;
    }
    let selector = data[0] % 3;
    let payload = &data[1..];
    let payload_text = String::from_utf8_lossy(payload);
    let (token, digest, chain) = match selector {
        0 => (payload, DIGEST, CHAIN),
        1 => (TOKEN, payload_text.as_ref(), CHAIN),
        _ => (TOKEN, DIGEST, payload_text.as_ref()),
    };
    let valid = swarrm_verify::tsa::verify_tst(token, digest, chain);
    let gen_time = swarrm_verify::tsa::verify_tst_gen_time(token, digest, chain);
    assert_eq!(valid, gen_time.is_some(), "TSA entrypoints must agree");
});
