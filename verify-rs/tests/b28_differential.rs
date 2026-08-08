// Apache-2.0 (public verifier repo)
//! Fresh Python -> native Rust differential parity for raw B28 inputs.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, env, fs, path::PathBuf};
use swarrm_verify::b28::verify_b28_cwt;

const TRUST_PACK_PIN: [u8; 32] = [0x04, 0x2b, 0x49, 0x80, 0x6f, 0xbe, 0x4e, 0x17, 0x58, 0x28, 0xbd, 0xbf, 0xc9, 0x63, 0x86, 0xe8, 0xec, 0x88, 0xa7, 0x1d, 0x38, 0x6e, 0xd2, 0x53, 0x6d, 0x8c, 0x30, 0x45, 0x9c, 0x25, 0xc5, 0xcc];

fn digest(raw: &[u8]) -> String {
    Sha256::digest(raw).iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn fresh_mutations_match_python_exactly_and_never_authorize() {
    let Ok(directory) = env::var("SWARRM_B28_DIFF_DIR") else {
        println!("SWARRM_B28_DIFF_DIR unset - no fresh B28 corpus supplied; skipping");
        return;
    };
    let directory = PathBuf::from(directory);
    let manifest: Value = serde_json::from_slice(&fs::read(directory.join("manifest.json")).expect("read B28 differential manifest")).expect("parse B28 differential manifest");
    assert_eq!(manifest["schema"], "swarrm-b28/differential-corpus/v1");
    let cases = manifest["cases"].as_array().expect("B28 differential cases must be an array");
    assert_eq!(manifest["case_count"].as_u64(), Some(cases.len() as u64));
    assert!(manifest["seed_count"].as_u64().is_some_and(|n| n >= 90));

    let trust_pack = fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/golden/b28/trust-pack.cbor")).expect("read pinned B28 trust pack");
    assert_eq!(digest(&trust_pack), hex(&TRUST_PACK_PIN));

    let mut surfaces = BTreeSet::new();
    for case in cases {
        let name = case["name"].as_str().expect("case name");
        surfaces.insert((case["seed"].as_str().expect("case seed"), case["target"].as_str().expect("case target")));
        let exchange = fs::read(directory.join(case["exchange"].as_str().expect("case exchange path"))).expect("read case exchange");
        let context = fs::read(directory.join(case["context"].as_str().expect("case context path"))).expect("read case context");
        assert_eq!(digest(&exchange), case["exchange_sha256"], "{name}");
        assert_eq!(digest(&context), case["context_sha256"], "{name}");

        let got: Value = serde_json::from_str(&verify_b28_cwt(&exchange, &context, &trust_pack, &TRUST_PACK_PIN)).expect("B28 verifier must always return JSON");
        assert_eq!(got, case["expected"], "{name}: Rust diverged from Python");
        assert_ne!(got["verdict"], "PASS", "{name}: verifier returned PASS");
        assert_eq!(got["should_execute"], false, "{name}: read-only verifier authorized execution");
    }
    assert_eq!(manifest["mutation_surface_count"].as_u64(), Some(surfaces.len() as u64));
    println!("B28 differential: Rust == Python on {} fresh mutations", cases.len());
}
