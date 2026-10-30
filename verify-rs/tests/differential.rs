// Apache-2.0 (public verifier repo)
//! Differential parity (SPEC/verified-action-v1.md §5): replay the generated
//! corpus through the Rust engine and demand Value-equality with the Python
//! engine's vectors for EVERY input. The corpus dir arrives via
//! SWARRM_DIFF_DIR (see the `differential` make target); when unset the
//! ordinary Cargo runs report an ignored test. The mandatory parity callers
//! explicitly include it and refuse missing or invalid corpus inputs.

use serde_json::Value;
use std::path::PathBuf;
use std::{env, fs};

/// Per-key mismatch listing for two vector objects (both are flat enough).
fn compact_diff(got: &Value, want: &Value) -> String {
    let (Some(g), Some(w)) = (got.as_object(), want.as_object()) else {
        return format!("rust={got} python={want}");
    };
    let mut lines = Vec::new();
    for key in g.keys().chain(w.keys().filter(|k| !g.contains_key(k.as_str()))) {
        let (a, b) = (g.get(key), w.get(key));
        if a != b {
            let show = |v: Option<&Value>| v.map_or("<absent>".into(), Value::to_string);
            lines.push(format!("  {key}: rust={} python={}", show(a), show(b)));
        }
    }
    lines.join("\n")
}

#[test]
#[ignore = "requires generated cross-runtime corpus; run make differential"]
fn differential_corpus_parity() {
    let dir = env::var("SWARRM_DIFF_DIR").expect("SWARRM_DIFF_DIR is required for differential parity");
    assert!(!dir.is_empty(), "SWARRM_DIFF_DIR must not be empty");
    let dir = PathBuf::from(dir);
    // The corpus now carries a trust context, because the gate whose job is
    // proving the engines agree was exercising only the UNANCHORED half of
    // derive_vector. Every trust-anchored dimension must participate in the
    // parity corpus; verify-rs/tests/verdicts.rs loads the same context.
    let trust: Option<Value> = Some(serde_json::from_str(&fs::read_to_string(dir.join("trust_context.json")).expect("read trust_context.json")).expect("parse trust_context.json"));
    let vectors: Value = serde_json::from_str(&fs::read_to_string(dir.join("python_vectors.json")).expect("read python_vectors.json")).expect("parse python_vectors.json");
    let vectors = vectors.as_object().expect("python_vectors.json is an object");
    let mut names: Vec<String> = fs::read_dir(&dir).expect("read corpus dir").filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned())).filter(|n| n.starts_with("input_") && n.ends_with(".json")).collect();
    names.sort();
    assert!(!names.is_empty(), "corpus dir {} has no input_*.json", dir.display());
    assert_eq!(names.len(), vectors.len(), "corpus/vector count mismatch");
    for name in &names {
        let raw = fs::read_to_string(dir.join(name)).expect("read input");
        let input: Value = serde_json::from_str(&raw).expect("parse input");
        let got = swarrm_verify::action::derive_vector_with_trust(&input, trust.as_ref());
        let want = vectors.get(name).unwrap_or_else(|| panic!("{name}: no python vector"));
        assert!(&got == want, "{name}: engines diverge\n{}", compact_diff(&got, want));
    }
    println!("differential: {} inputs, Rust == Python on every vector", names.len());
}
