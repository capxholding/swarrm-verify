// Apache-2.0 (public verifier repo)
//! Offline RFC 3161 timestamp-token verification — mirror of `verify/tsa.py`.
//! NO network, ever: the pinned PEM chain supplied with the record is the
//! trust anchor, exactly as in the Python verifier.
//!
//! Same checks, same order as `verify/tsa.py::verify_tst`:
//!   1. token parses; eContent is a TSTInfo
//!   2. messageImprint: SHA-256 and hashed_message == expected digest
//!   3. CMS message-digest attribute == hash(eContent) (signer's digest algo)
//!   4. signature over the signed attributes verifies with the signer cert
//!   5. signer cert chains to a SELF-SIGNED root inside the pinned chain
//!   6. genTime lies within the signer cert's validity window
//!
//! SCOPE LIMIT (weak claim, documented — not a hidden gap): signatures are
//! verified with ECDSA P-256 ONLY. The owner sanction (A_BUILD §0.2·3,
//! 2026-08-01) covers the RustCrypto crates `p256`/`der`/`x509-cert`/`cms`;
//! the `rsa` crate is NOT sanctioned, so RSA-signed tokens or chains return
//! false here — meaning "not verifiable within the sanctioned algorithm
//! scope", never "verified". The current freeTSA signer certificate is ECDSA
//! (A_BUILD §1) but uses a P-384 key with an RSA-signed chain, so the real
//! freeTSA token verifies only in the Python verifier; extend the §0.2·3
//! sanction with the `rsa` (and `p384`) crates to lift this. The shared
//! fixtures pin the divergence per case (tests/golden/bundles/
//! expected_tsa.json, `why_diverges`).
//!
//! Total function: this input is attacker-controlled, so malformed or
//! hostile bytes return false — no unwrap/expect on any parse path. The
//! `der` crate is strict DER where asn1crypto tolerates BER looseness
//! (unsorted SET OF, trailing bytes); such tokens fail closed here.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{AnyRef, GeneralizedTime, ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode, SliceReader, Tag, Tagged};
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::BTreeSet;
use x509_cert::attr::Attributes;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::Certificate;

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const OID_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
const OID_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.3");
const OID_ECDSA_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const OID_ECDSA_SHA384: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");
const OID_ECDSA_SHA512: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.4");
const OID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const OID_PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The TSTInfo fields the checks need; trailing optional fields (accuracy,
/// ordering, nonce, tsa, extensions) are skipped like the Python parser
/// leaves them untouched.
struct TstImprint {
    alg: ObjectIdentifier,
    digest: Vec<u8>,
    gen_time: GeneralizedTime,
}

fn hash_bytes(oid: &ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    if *oid == OID_SHA256 {
        Some(Sha256::digest(data).to_vec())
    } else if *oid == OID_SHA384 {
        Some(Sha384::digest(data).to_vec())
    } else if *oid == OID_SHA512 {
        Some(Sha512::digest(data).to_vec())
    } else {
        None
    }
}

/// Signature-algorithm OID -> hash OID. ECDSA only — RSA (and every other
/// family) is None: the `rsa` crate is outside the §0.2·3 sanction.
fn ecdsa_hash_oid(sig_alg: &ObjectIdentifier) -> Option<ObjectIdentifier> {
    if *sig_alg == OID_ECDSA_SHA256 {
        Some(OID_SHA256)
    } else if *sig_alg == OID_ECDSA_SHA384 {
        Some(OID_SHA384)
    } else if *sig_alg == OID_ECDSA_SHA512 {
        Some(OID_SHA512)
    } else {
        None
    }
}

/// ECDSA P-256 over the named hash; any other key type or curve is false
/// (module-level scope limit — the Python side also accepts RSA and other
/// curves via pyca/cryptography).
fn verify_sig_p256(
    spki: &SubjectPublicKeyInfoOwned,
    sig_der: &[u8],
    data: &[u8],
    hash_oid: &ObjectIdentifier,
) -> bool {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return false;
    }
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    if curve != Some(OID_PRIME256V1) {
        return false;
    }
    let key_bytes = match spki.subject_public_key.as_bytes() {
        Some(b) => b,
        None => return false,
    };
    let vk = match VerifyingKey::from_sec1_bytes(key_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let sig = match Signature::from_der(sig_der) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let digest = match hash_bytes(hash_oid, data) {
        Some(d) => d,
        None => return false,
    };
    vk.verify_prehash(&digest, &sig).is_ok()
}

/// messageImprint ::= SEQUENCE { hashAlgorithm, hashedMessage }
fn parse_imprint(r: &mut SliceReader) -> Option<(ObjectIdentifier, Vec<u8>)> {
    let imprint = AnyRef::decode(r).ok()?;
    if imprint.tag() != Tag::Sequence {
        return None;
    }
    let mut ir = SliceReader::new(imprint.value()).ok()?;
    let alg = x509_cert::spki::AlgorithmIdentifierOwned::decode(&mut ir).ok()?;
    let digest = OctetStringRef::decode(&mut ir).ok()?;
    Some((alg.oid, digest.as_bytes().to_vec()))
}

fn parse_tst_info(tst_der: &[u8]) -> Option<TstImprint> {
    let outer = AnyRef::from_der(tst_der).ok()?;
    if outer.tag() != Tag::Sequence {
        return None;
    }
    let mut r = SliceReader::new(outer.value()).ok()?;
    let version = AnyRef::decode(&mut r).ok()?;
    if version.tag() != Tag::Integer {
        return None;
    }
    let _policy = ObjectIdentifier::decode(&mut r).ok()?;
    let (alg, digest) = parse_imprint(&mut r)?;
    let _serial = AnyRef::decode(&mut r).ok()?;
    let gen_time = GeneralizedTime::decode(&mut r).ok()?;
    Some(TstImprint { alg, digest, gen_time })
}

fn parse_token(token_der: &[u8]) -> Option<(SignedData, Vec<u8>, TstImprint)> {
    let ci = ContentInfo::from_der(token_der).ok()?;
    if ci.content_type != OID_SIGNED_DATA {
        return None;
    }
    let sd: SignedData = ci.content.decode_as().ok()?;
    if sd.encap_content_info.econtent_type != OID_TST_INFO {
        return None;
    }
    // eContent is [0] EXPLICIT — the Any holds the OCTET STRING around the
    // raw TSTInfo DER, mirroring Python's `econtent.contents`
    let tst_der = sd
        .encap_content_info
        .econtent
        .as_ref()?
        .decode_as::<OctetStringRef>()
        .ok()?
        .as_bytes()
        .to_vec();
    let info = parse_tst_info(&tst_der)?;
    Some((sd, tst_der, info))
}

fn message_digest_matches(signed_attrs: &Attributes, want: &[u8]) -> bool {
    let md: Vec<_> = signed_attrs
        .iter()
        .filter(|a| a.oid == OID_MESSAGE_DIGEST)
        .collect();
    if md.len() != 1 {
        return false;
    }
    let value = match md[0].values.iter().next() {
        Some(v) => v,
        None => return false,
    };
    match value.decode_as::<OctetStringRef>() {
        Ok(o) => o.as_bytes() == want,
        Err(_) => false,
    }
}

/// Returns the single SignerInfo plus the hash OID for its signature after
/// the RFC 3161 structural checks (mirror of `_check_signer_info`).
fn check_signer_info<'a>(
    sd: &'a SignedData,
    tst_der: &[u8],
) -> Option<(&'a SignerInfo, ObjectIdentifier)> {
    let mut infos = sd.signer_infos.0.iter();
    let si = match (infos.next(), infos.next()) {
        (Some(si), None) => si, // exactly 1 SignerInfo
        _ => return None,
    };
    let signed_attrs = si.signed_attrs.as_ref()?;
    if signed_attrs.len() == 0 {
        return None; // RFC 3161 requires signed attributes
    }
    let want = hash_bytes(&si.digest_alg.oid, tst_der)?;
    if !message_digest_matches(signed_attrs, &want) {
        return None;
    }
    let hash_oid = ecdsa_hash_oid(&si.signature_algorithm.oid)?;
    Some((si, hash_oid))
}

fn find_signer_cert<'a>(sd: &'a SignedData, si: &SignerInfo) -> Option<&'a Certificate> {
    let ias = match &si.sid {
        SignerIdentifier::IssuerAndSerialNumber(i) => i,
        SignerIdentifier::SubjectKeyIdentifier(_) => return None,
    };
    let want_issuer = ias.issuer.to_der().ok()?;
    for choice in sd.certificates.as_ref()?.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            if cert.tbs_certificate.serial_number == ias.serial_number
                && cert.tbs_certificate.issuer.to_der().ok()? == want_issuer
            {
                return Some(cert);
            }
        }
    }
    None
}

fn cert_sig_valid(current: &Certificate, issuer: &Certificate, tbs_der: &[u8]) -> bool {
    let hash_oid = match ecdsa_hash_oid(&current.signature_algorithm.oid) {
        Some(h) => h,
        None => return false, // RSA-signed chain — outside the sanction scope
    };
    let sig = match current.signature.as_bytes() {
        Some(s) => s,
        None => return false,
    };
    verify_sig_p256(
        &issuer.tbs_certificate.subject_public_key_info,
        sig,
        tbs_der,
        &hash_oid,
    )
}

/// Chains the signer cert to a pinned self-signed root (`_verify_chain`).
fn verify_chain(signer: &Certificate, cert_chain_pem: &str) -> bool {
    let pinned = match Certificate::load_pem_chain(cert_chain_pem.as_bytes()) {
        Ok(p) if !p.is_empty() => p,
        _ => return false,
    };
    let mut current = signer;
    let mut seen: BTreeSet<Vec<u8>> = BTreeSet::new();
    loop {
        let tbs = match current.tbs_certificate.to_der() {
            Ok(t) => t,
            Err(_) => return false,
        };
        if !seen.insert(tbs.clone()) {
            return false; // certificate chain contains a loop
        }
        let issuer = match pinned
            .iter()
            .find(|c| c.tbs_certificate.subject == current.tbs_certificate.issuer)
        {
            Some(c) => c,
            None => return false, // does not chain to the pinned TSA root
        };
        if !cert_sig_valid(current, issuer, &tbs) {
            return false;
        }
        if issuer.tbs_certificate.subject == issuer.tbs_certificate.issuer {
            return true; // self-signed root reached
        }
        current = issuer;
    }
}

fn gen_time_in_validity(gen_time: &GeneralizedTime, cert: &Certificate) -> bool {
    let g = gen_time.to_unix_duration();
    let v = &cert.tbs_certificate.validity;
    v.not_before.to_unix_duration() <= g && g <= v.not_after.to_unix_duration()
}

/// Verify an RFC 3161 TimeStampToken (DER) against an expected SHA-256
/// digest (lowercase hex) and a pinned PEM certificate chain. Boolean-only
/// mirror of `verify/tsa.py::verify_tst` (detail strings and genTime
/// extraction are a Python-report concern) under the module-level ECDSA
/// P-256 scope limit. Malformed or hostile input is false, never a panic.
pub fn verify_tst(token_der: &[u8], expected_digest_hex: &str, cert_chain_pem: &str) -> bool {
    let (sd, tst_der, tst) = match parse_token(token_der) {
        Some(t) => t,
        None => return false,
    };
    // 2. message imprint: SHA-256 over exactly the expected digest (string
    // compare on lowercase hex, exactly like the Python verifier)
    if tst.alg != OID_SHA256 || crate::hex(&tst.digest) != expected_digest_hex {
        return false;
    }
    // 3. signer info + message-digest attribute
    let (si, hash_oid) = match check_signer_info(&sd, &tst_der) {
        Some(t) => t,
        None => return false,
    };
    let signer = match find_signer_cert(&sd, si) {
        Some(c) => c,
        None => return false,
    };
    // 4. signature over the signed attributes (re-encoded as DER SET OF —
    // Python's `signed_attrs.untag().dump()`)
    let attrs_der = match si.signed_attrs.as_ref().and_then(|a| a.to_der().ok()) {
        Some(a) => a,
        None => return false,
    };
    let spki = &signer.tbs_certificate.subject_public_key_info;
    if !verify_sig_p256(spki, si.signature.as_bytes(), &attrs_der, &hash_oid) {
        return false;
    }
    // 5. chain to a pinned self-signed root
    if !verify_chain(signer, cert_chain_pem) {
        return false;
    }
    // 6. genTime within the signer certificate's validity window
    gen_time_in_validity(&tst.gen_time, signer)
}
