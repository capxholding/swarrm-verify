// Apache-2.0 (public verifier repo)
//! Canonical-CBOR codec gate (B24 W1) — the Rust twin of
//! tests/test_cbor_canonical.py. Every JSON-sourced golden vector must emit
//! byte-identical output to the Python engine's .bin bytes; the five
//! byte-string vectors are reconstructed here IN CODE, mirroring
//! scripts/gen_cbor_golden.py case for case; every hostile input is a clean
//! rejection, never a panic (H5).
//!
//! The module under test is pub(crate) (the public-surface budget reserves
//! bare `pub` for verify_certificate_cbor alone), so this test compiles it
//! directly via #[path] instead of going through the crate API.

#[path = "../src/cbor.rs"]
mod cbor;

use cbor::{canonical_cbor, canonical_from_json, decode_cbor, MAX_BYTES, MAX_DEPTH};
use ciborium::value::Integer;
use ciborium::Value;
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden/cbor")
}

fn read_bin(name: &str) -> Vec<u8> {
    fs::read(golden_dir().join(format!("{name}.bin"))).unwrap()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn decode(data: &[u8]) -> Option<Value> {
    decode_cbor(data, MAX_DEPTH as usize, MAX_BYTES)
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

/// The five byte-string cases — MIRRORS CODE_CASES in
/// scripts/gen_cbor_golden.py; change only in lockstep.
fn code_cases() -> Vec<(&'static str, Value)> {
    vec![
        ("bytes_empty", Value::Bytes(vec![])),
        ("bytes_short", Value::Bytes(vec![1, 2, 3])),
        ("bytes_len23_24", Value::Map(vec![(text("a"), Value::Bytes((0..23u8).collect())), (text("b"), Value::Bytes((0..24u8).collect()))])),
        ("bytes_digest_map", Value::Map(vec![(text("digest"), Value::Bytes((0..32u8).collect())), (text("proofs"), Value::Array(vec![Value::Bytes(vec![0x00]), Value::Bytes(vec![0xff])]))])),
        ("bytes_mixed", Value::Map(vec![(text(""), Value::Bytes(vec![])), (text("k"), Value::Array(vec![Value::Bytes(b"ab".to_vec()), text("text"), Value::Integer(Integer::from(7))])), (text("z"), Value::Null)])),
    ]
}

#[test]
fn json_sourced_vectors_emit_python_bytes() {
    let mut checked = 0;
    for entry in fs::read_dir(golden_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path.file_stem().unwrap().to_str().unwrap().to_owned();
        let source: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let got = canonical_from_json(&source).unwrap_or_else(|| panic!("emitter refused JSON vector {name}"));
        assert_eq!(got, read_bin(&name), "byte mismatch on vector {name}");
        checked += 1;
    }
    assert!(checked >= 35, "only {checked} JSON-sourced vectors found");
}

#[test]
fn code_pair_vectors_emit_python_bytes() {
    let cases = code_cases();
    assert_eq!(cases.len(), 5);
    for (name, value) in &cases {
        let got = canonical_cbor(value).expect(name);
        assert_eq!(got, read_bin(name), "byte mismatch on code vector {name}");
    }
}

#[test]
fn every_golden_bin_decodes_and_reencodes_identically() {
    let mut checked = 0;
    for entry in fs::read_dir(golden_dir()).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("bin") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        let value = decode(&bytes).unwrap_or_else(|| panic!("decode refused golden {}", path.display()));
        assert_eq!(canonical_cbor(&value).unwrap(), bytes);
        checked += 1;
    }
    assert!(checked >= 40, "only {checked} golden .bin vectors found");
}

#[test]
fn key_order_is_encoded_byte_order() {
    // length first (the length head sorts before content), then byte order
    let v: serde_json::Value = serde_json::from_str(r#"{"aa":2,"b":3,"a":1}"#).unwrap();
    assert_eq!(canonical_from_json(&v).unwrap(), unhex("a361610161620362616102"));
}

#[test]
fn emitter_rejects_out_of_profile_json() {
    for src in [
        "1.5",
        "[1.0]",
        r#"{"a":2.5}"#,
        "1e30",
        "18446744073709551615", // u64 above i64::MAX
        r#"[18446744073709551615]"#,
    ] {
        let v: serde_json::Value = serde_json::from_str(src).unwrap();
        assert!(canonical_from_json(&v).is_none(), "accepted {src}");
    }
}

#[test]
fn emitter_rejects_out_of_profile_values() {
    let bad = [
        Value::Float(2.5),
        Value::Tag(0, Box::new(text("1970-01-01T00:00:00Z"))),
        Value::Map(vec![(Value::Integer(Integer::from(1)), Value::Null)]),    // non-text key
        Value::Map(vec![(Value::Bytes(vec![0x6b]), Value::Null)]),            // bstr key
        Value::Integer(Integer::from(u64::MAX)),                              // outside signed 64-bit
        Value::Map(vec![(text("a"), Value::Null), (text("a"), Value::Null)]), // duplicate
        Value::Array(vec![Value::Float(f64::NAN)]),
    ];
    for (i, v) in bad.iter().enumerate() {
        assert!(canonical_cbor(v).is_none(), "accepted bad value #{i}");
    }
}

#[test]
fn emitter_depth_cap() {
    let nest = |levels: usize| {
        let mut v = Value::Array(vec![Value::Integer(Integer::from(0))]);
        for _ in 0..levels - 1 {
            v = Value::Array(vec![v]);
        }
        v
    };
    assert!(canonical_cbor(&nest(MAX_DEPTH as usize)).is_some());
    assert!(canonical_cbor(&nest(MAX_DEPTH as usize + 1)).is_none());
}

#[test]
fn decoder_rejects_hostile_bytes() {
    // SAME list as tests/test_cbor_canonical.py — both engines reject identically.
    for hex in [
        "",                                             // empty input
        "18",                                           // truncated head
        "1a0000",                                       // truncated 4-byte argument
        "62e2",                                         // truncated text payload
        "9b7fffffffffffffff",                           // array claiming 2^63-1 members
        "a1",                                           // truncated map
        "c074323032362d30312d30315430303a30303a30305a", // tag 0
        "d81845",                                       // tag 24
        "f97e00",                                       // float16 NaN
        "fa47c35000",                                   // float32
        "fb4029000000000000",                           // float64
        "f7",                                           // simple value: undefined
        "f0",                                           // simple value 16
        "f820",                                         // simple value one-byte form
        "5f42010243030405ff",                           // indefinite bytes
        "7f61616161ff",                                 // indefinite text
        "9f01ff",                                       // indefinite array
        "bf616101ff",                                   // indefinite map
        "1c",                                           // reserved additional info 28
        "1e",                                           // reserved additional info 30
        "ff",                                           // lone break
        "1805",                                         // non-minimal int head (5 as one-byte argument)
        "1900ff",                                       // non-minimal int head (255 as two-byte argument)
        "a2616101616102",                               // duplicate map keys
        "a2616202616101",                               // unsorted map keys
        "a2616261016102",                               // truncated map: three items for two pairs
        "a1010a",                                       // integer map key
        "a1400a",                                       // byte-string map key
        "0001",                                         // trailing bytes after a complete item
        "1b8000000000000000",                           // 2^63: outside signed 64-bit
        "3b8000000000000000",                           // -2^63-1: outside signed 64-bit
        "61ff",                                         // invalid UTF-8 in text
    ] {
        assert!(decode(&unhex(hex)).is_none(), "accepted hostile bytes {hex}");
    }
}

#[test]
fn decoder_depth_cap() {
    let ok = [vec![0x81u8; MAX_DEPTH as usize], vec![0x00]].concat();
    assert!(decode(&ok).is_some());
    let over = [vec![0x81u8; MAX_DEPTH as usize + 1], vec![0x00]].concat();
    assert!(decode(&over).is_none());
}

#[test]
fn decoder_survives_absurd_nesting_without_crash() {
    // 1 MiB of container heads: the iterative pre-scan rejects before any
    // recursive decoding could touch the call stack.
    assert!(decode(&vec![0x9fu8; 1 << 20]).is_none());
    let deep = [vec![0x81u8; 1 << 20], vec![0x00]].concat();
    assert!(decode(&deep).is_none());
}

#[test]
fn decoder_byte_cap() {
    let payload = unhex("a1616b6176"); // {"k": "v"}
    assert!(decode_cbor(&payload, MAX_DEPTH as usize, payload.len()).is_some());
    assert!(decode_cbor(&payload, MAX_DEPTH as usize, payload.len() - 1).is_none());
}
