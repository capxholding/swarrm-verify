// Apache-2.0 (public verifier repo)
//! B29 evidence-level parity: both engines derive the SAME upgrade facts from
//! the shared fixtures under the shared trust context. `recorder_attested`
//! (E3: co-signature under the relying-party-named recorder key) and
//! `trusted_tst_checkpoints` (E2 time leg: token chain terminating at the
//! SUPPLIED root) are favourable values, so cross-engine agreement is the
//! same law expected.json enforces for verdicts. evidence_tst_forged_ca is
//! THE audit fixture: VERIFIED under the carried-chain gate, never trusted
//! under the supplied root.

use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/bundles")
}

fn read(dir: &Path, name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(dir.join(name)).unwrap()).unwrap()
}

fn sorted_u64(v: &Value) -> Vec<u64> {
    let mut out: Vec<u64> = v.as_array().unwrap().iter().filter_map(Value::as_u64).collect();
    out.sort_unstable();
    out
}

fn sorted_str(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = v.as_array().unwrap().iter().filter_map(|x| x.as_str().map(String::from)).collect();
    out.sort();
    out
}

#[test]
fn evidence_levels_agree_with_expected() {
    let dir = golden_dir();
    let trust = read(&dir, "trust_evidence.json");
    let expected = read(&dir, "expected_evidence.json");
    let mut checked = 0;
    for (name, want) in expected.as_object().unwrap() {
        if name.starts_with('_') {
            continue;
        }
        let bundle = read(&dir, &format!("{name}.json"));
        for (label, ctx) in [("with_trust", Some(&trust)), ("without_trust", None)] {
            let got = swarrm_verify::verify_bundle_levels(&bundle, ctx);
            assert_eq!(got["ok"], Value::Bool(true), "{name}/{label}: fixture must verify");
            assert_eq!(sorted_u64(&got["recorder_attested"]), sorted_u64(&want[label]["recorder_attested"]), "{name}/{label}: recorder_attested");
            assert_eq!(sorted_str(&got["trusted_tst_checkpoints"]), sorted_str(&want[label]["trusted_tst_checkpoints"]), "{name}/{label}: trusted_tst_checkpoints");
        }
        checked += 1;
    }
    assert!(checked >= 4, "expected at least 4 evidence rows, ran {checked}");
}

#[test]
fn a_supplied_root_never_trusts_the_forged_ca() {
    let dir = golden_dir();
    let trust = read(&dir, "trust_evidence.json");
    let bundle = read(&dir, "evidence_tst_forged_ca.json");
    assert!(swarrm_verify::verify_bundle(&bundle), "the carried-chain GATE passes a forged CA");
    let got = swarrm_verify::verify_bundle_levels(&bundle, Some(&trust));
    assert!(got["trusted_tst_checkpoints"].as_array().unwrap().is_empty());
}

#[test]
fn public_sample_uses_a_real_sigstore_token_under_the_supplied_root() {
    let samples = golden_dir();
    let bundle = read(&samples, "public_sample_sigstore.json");
    let trust = read(&samples, "public_sample_sigstore_trust.json");
    let got = swarrm_verify::verify_bundle_levels(&bundle, Some(&trust));
    assert_eq!(got["ok"], Value::Bool(true));
    assert_eq!(sorted_str(&got["trusted_tst_checkpoints"]), vec!["1bea54aa22cf39b0d9af2a37058e07c08411f559bcbe8143f60cddcd471bdf1b"]);
}
