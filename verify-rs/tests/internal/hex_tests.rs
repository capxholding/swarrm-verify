// Apache-2.0 (public verifier repo)
use super::hex_to_bytes;
use serde_json::Value;

const PROFILE: &str = include_str!("../../../tests/golden/hex_decode_profile.json");

/// The hole this grammar closes: `u8::from_str_radix` treats `+` as a sign.
fn from_str_radix_only(s: &str) -> Option<Vec<u8>> {
    if !s.is_ascii() || !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < s.len() {
        out.push(u8::from_str_radix(&s[i..i + 2], 16).ok()?);
        i += 2;
    }
    Some(out)
}

#[test]
fn shared_profile_matches_the_ascii_hex_grammar() {
    let profile: Value = serde_json::from_str(PROFILE).unwrap();
    for (name, case) in profile.as_object().unwrap() {
        let input = case["input"].as_str().unwrap();
        let accepted = case["accepted"].as_bool().unwrap();
        let got = hex_to_bytes(input);
        assert_eq!(got.is_some(), accepted, "{name}");
        if accepted {
            let want: Vec<u8> = case["bytes"].as_array().unwrap().iter().map(|v| v.as_u64().unwrap() as u8).collect();
            assert_eq!(got.unwrap(), want, "{name}");
        }
    }
}

#[test]
fn from_str_radix_only_validation_must_fail_the_signed_hex_cases() {
    assert_eq!(u8::from_str_radix("+f", 16), Ok(15));
    assert_eq!(u8::from_str_radix("+0", 16), Ok(0));
    assert_eq!(from_str_radix_only("+f"), Some(vec![0x0f]));
    assert_eq!(from_str_radix_only("+0"), Some(vec![0x00]));
    assert_eq!(hex_to_bytes("+f"), None);
    assert_eq!(hex_to_bytes("+0"), None);
    assert_eq!(hex_to_bytes("-f"), None);
}
