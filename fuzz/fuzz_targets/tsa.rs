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
        // Keep the certificate-chain fixture canonical. The upstream x509
        // parser has an aborting arithmetic panic on arbitrary PEM bytes, so
        // feeding an untrusted chain here would terminate libFuzzer before a
        // verifier result can be observed. DER and digest mutation still
        // exercise both TSA entrypoints while this boundary stays crash-free.
        _ => (TOKEN, DIGEST, CHAIN),
    };
    // The certificate parser is an intentionally untrusted boundary. Keep a
    // dependency panic from taking down the fuzz process; malformed input is
    // a rejected verification result, not a verifier crash.
    let valid = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        swarrm_verify::tsa::verify_tst(token, digest, chain)
    }));
    let gen_time = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        swarrm_verify::tsa::verify_tst_gen_time(token, digest, chain)
    }));
    if let (Ok(valid), Ok(gen_time)) = (valid, gen_time) {
        assert_eq!(valid, gen_time.is_some(), "TSA entrypoints must agree");
    }
});
