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
//! Algorithm coverage:
//! signatures verify under ECDSA P-256 / P-384 (`p256`/`p384`) and RSASSA-
//! PKCS1-v1_5 (`rsa`) — the same set pyca/cryptography accepts on the Python
//! side, so the real freeTSA token (P-384 signer key, RSA-signed chain) and
//! RSA-signed qualified tokens verify in BOTH engines. A curve, key type, or
//! signature family outside this set returns false — "not verifiable within the
//! sanctioned scope", never "verified". Exact pins + sha256 digests live in
//! ci/architecture_policy.json (`approved_rust_crates`), enforced by
//! scripts/check_architecture.py; transitives are witnessed by the committed
//! Cargo.lock. (verify-only: no private-key operations, so the `rsa` crate's
//! Marvin decryption advisory RUSTSEC-2023-0071 does not apply.)
//!
//! Total function: this input is attacker-controlled, so malformed or hostile
//! bytes return false — no unwrap/expect on any parse path. The `der` crate is
//! strict DER where asn1crypto tolerates BER looseness (unsorted SET OF,
//! trailing bytes); such tokens fail closed here.

use cms::cert::CertificateChoices;
use cms::content_info::ContentInfo;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use der::asn1::{AnyRef, GeneralizedTime, ObjectIdentifier, OctetStringRef};
use der::{Decode, Encode, SliceReader, Tag, Tagged};
use p256::ecdsa::signature::hazmat::PrehashVerifier; // shared trait; p384 keys implement it too
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, BTreeSet};
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
const OID_SECP384R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.132.0.34");
const OID_RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const OID_SHA256_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
const OID_SHA384_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12");
const OID_SHA512_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13");
const OID_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.15");
const OID_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const OID_BASIC_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.19");
const OID_NAME_CONSTRAINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.30");
const OID_EXTENDED_KEY_USAGE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.37");

/// The TSTInfo fields the checks need; trailing optional fields (accuracy,
/// ordering, nonce, tsa, extensions) are skipped like the Python parser
/// leaves them untouched.
struct TstImprint {
    alg: ObjectIdentifier,
    digest: Vec<u8>,
    gen_time: GeneralizedTime,
}

fn hash_bytes(oid: &ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    match *oid {
        OID_SHA256 => Some(Sha256::digest(data).to_vec()),
        OID_SHA384 => Some(Sha384::digest(data).to_vec()),
        OID_SHA512 => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

/// Verify `sig` over `data` with the signer's SPKI. The FAMILY is chosen by the
/// public KEY type (RSA vs ECDSA) — exactly like pyca on the Python side — so a
/// signature under the BARE `rsaEncryption` OID (the AlfaSign / qtsa.eu
/// qualified-TSP pattern, which carries no hash in the sig alg) still resolves
/// to RSASSA-PKCS1-v1_5. The hash is the sig-alg's own when it carries one
/// (ecdsa-with-shaXXX, shaXXXWithRSA), else `digest_hint` (the separate digest
/// algorithm). ECDSA backends truncate an over-long prehash to the field size
/// (bits2field) as pyca does. Any unsupported key / curve / hash is false.
fn verify_sig(spki: &SubjectPublicKeyInfoOwned, sig_alg: &ObjectIdentifier, digest_hint: &ObjectIdentifier, sig: &[u8], data: &[u8]) -> bool {
    let hash_oid = match *sig_alg {
        OID_ECDSA_SHA256 | OID_SHA256_RSA => OID_SHA256,
        OID_ECDSA_SHA384 | OID_SHA384_RSA => OID_SHA384,
        OID_ECDSA_SHA512 | OID_SHA512_RSA => OID_SHA512,
        _ => *digest_hint,
    };
    let Some(digest) = hash_bytes(&hash_oid, data) else { return false };
    if spki.algorithm.oid == OID_RSA_ENCRYPTION {
        matches!(*sig_alg, OID_RSA_ENCRYPTION | OID_SHA256_RSA | OID_SHA384_RSA | OID_SHA512_RSA) && verify_rsa(spki, sig, &digest, &hash_oid)
    } else if spki.algorithm.oid == OID_EC_PUBLIC_KEY {
        matches!(*sig_alg, OID_ECDSA_SHA256 | OID_ECDSA_SHA384 | OID_ECDSA_SHA512) && verify_ecdsa(spki, sig, &digest)
    } else {
        false
    }
}

// P-256 and P-384 differ only in concrete types; keep their parse/fail-closed
// path in one place so supported curves cannot drift.
macro_rules! verify_ecdsa_curve {
    ($curve:ident, $key:expr, $sig:expr, $digest:expr) => {{
        let Ok(key) = $curve::ecdsa::VerifyingKey::from_sec1_bytes($key) else { return false };
        let Ok(sig) = $curve::ecdsa::Signature::from_der($sig) else { return false };
        key.verify_prehash($digest, &sig).is_ok()
    }};
}

/// ECDSA over the SPKI's named curve (P-256 or P-384). `sig` is a DER
/// ECDSA-Sig-Value; `digest` is the prehash.
fn verify_ecdsa(spki: &SubjectPublicKeyInfoOwned, sig: &[u8], digest: &[u8]) -> bool {
    if spki.algorithm.oid != OID_EC_PUBLIC_KEY {
        return false;
    }
    let curve = spki.algorithm.parameters.as_ref().and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
    let Some(key_bytes) = spki.subject_public_key.as_bytes() else { return false };
    match curve {
        Some(c) if c == OID_PRIME256V1 => verify_ecdsa_curve!(p256, key_bytes, sig, digest),
        Some(c) if c == OID_SECP384R1 => verify_ecdsa_curve!(p384, key_bytes, sig, digest),
        _ => false,
    }
}

/// RSASSA-PKCS1-v1_5 with the SPKI's RSA key over the prehash `digest`.
fn verify_rsa(spki: &SubjectPublicKeyInfoOwned, sig: &[u8], digest: &[u8], hash_oid: &ObjectIdentifier) -> bool {
    if spki.algorithm.oid != OID_RSA_ENCRYPTION {
        return false;
    }
    let Some(key_bytes) = spki.subject_public_key.as_bytes() else { return false };
    let key = match RsaPublicKey::from_pkcs1_der(key_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let scheme = match *hash_oid {
        OID_SHA256 => Pkcs1v15Sign::new::<Sha256>(),
        OID_SHA384 => Pkcs1v15Sign::new::<Sha384>(),
        OID_SHA512 => Pkcs1v15Sign::new::<Sha512>(),
        _ => return false,
    };
    key.verify(scheme, digest, sig).is_ok()
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
    let tst_der = sd.encap_content_info.econtent.as_ref()?.decode_as::<OctetStringRef>().ok()?.as_bytes().to_vec();
    let info = parse_tst_info(&tst_der)?;
    Some((sd, tst_der, info))
}

fn message_digest_matches(signed_attrs: &Attributes, want: &[u8]) -> bool {
    let md: Vec<_> = signed_attrs.iter().filter(|a| a.oid == OID_MESSAGE_DIGEST).collect();
    if md.len() != 1 {
        return false;
    }
    let Some(value) = md[0].values.iter().next() else { return false };
    match value.decode_as::<OctetStringRef>() {
        Ok(o) => o.as_bytes() == want,
        Err(_) => false,
    }
}

/// Returns the single SignerInfo after the RFC 3161 structural checks (mirror
/// of `_check_signer_info`). The signature hash is resolved in verify_sig (from
/// the sig alg, or the digest algorithm for the bare rsaEncryption OID).
fn check_signer_info<'a>(sd: &'a SignedData, tst_der: &[u8]) -> Option<&'a SignerInfo> {
    let mut infos = sd.signer_infos.0.iter();
    let (Some(si), None) = (infos.next(), infos.next()) else {
        return None;
    }; // exactly one
    let signed_attrs = si.signed_attrs.as_ref()?;
    if signed_attrs.is_empty() {
        return None; // RFC 3161 requires signed attributes
    }
    let want = hash_bytes(&si.digest_alg.oid, tst_der)?;
    if !message_digest_matches(signed_attrs, &want) {
        return None;
    }
    Some(si)
}

fn find_signer_cert<'a>(sd: &'a SignedData, si: &SignerInfo) -> Option<&'a Certificate> {
    let SignerIdentifier::IssuerAndSerialNumber(ias) = &si.sid else { return None };
    let want_issuer = ias.issuer.to_der().ok()?;
    for choice in sd.certificates.as_ref()?.0.iter() {
        if let CertificateChoices::Certificate(cert) = choice {
            if cert.tbs_certificate.serial_number == ias.serial_number && cert.tbs_certificate.issuer.to_der().ok()? == want_issuer {
                return Some(cert);
            }
        }
    }
    None
}

fn cert_sig_valid(current: &Certificate, issuer: &Certificate, tbs_der: &[u8]) -> bool {
    if current.signature_algorithm != current.tbs_certificate.signature {
        return false;
    }
    let Some(sig) = current.signature.as_bytes() else { return false };
    verify_sig(&issuer.tbs_certificate.subject_public_key_info, &current.signature_algorithm.oid, &current.signature_algorithm.oid, sig, tbs_der)
}

const OID_ID_KP_TIME_STAMPING: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.8");

/// RFC 5280 path constraint: a cert may sign another only if basicConstraints
/// cA is TRUE and keyUsage asserts keyCertSign. Without this, a subject holding
/// ANY end-entity leaf under a supplied root could mint its own TSA signer and
/// forge the timestamp. A missing extension is not a CA. Mirror of
/// verify/tsa.py::_is_ca.
fn ca_constraint(cert: &Certificate) -> Option<Option<u8>> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let Ok(Some((_, bc))) = cert.tbs_certificate.get::<BasicConstraints>() else { return None };
    let Ok(Some((_, ku))) = cert.tbs_certificate.get::<KeyUsage>() else { return None };
    (bc.ca && ku.key_cert_sign()).then_some(bc.path_len_constraint)
}

/// RFC 3161 §2.3: the TST signer cert MUST carry EKU id-kp-timeStamping.
/// Mirror of verify/tsa.py::_is_timestamping_signer.
fn is_timestamping_signer(cert: &Certificate) -> bool {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    matches!(cert.tbs_certificate.get::<ExtendedKeyUsage>(), Ok(Some((true, eku))) if eku.0.as_slice() == [OID_ID_KP_TIME_STAMPING])
}

fn path_candidate_ok(current: &Certificate, issuer: &Certificate, tbs: &[u8], supplied: bool, at: Option<&GeneralizedTime>, below: usize) -> bool {
    let constraint = if supplied { ca_constraint(issuer) } else { Some(None) };
    let profile_ok = |cert: &Certificate| cert.tbs_certificate.extensions.as_ref().is_none_or(|extensions| extensions.iter().all(|ext| ext.extn_id != OID_NAME_CONSTRAINTS && (!ext.critical || matches!(ext.extn_id, OID_KEY_USAGE | OID_SUBJECT_ALT_NAME | OID_BASIC_CONSTRAINTS | OID_EXTENDED_KEY_USAGE))));
    (!supplied || profile_ok(current) && profile_ok(issuer)) && constraint.is_some() && at.is_none_or(|time| gen_time_in_validity(time, issuer)) && constraint.flatten().is_none_or(|limit| below <= usize::from(limit)) && cert_sig_valid(current, issuer, tbs)
}

/// Shared path builder for the carried-chain gate and supplied-root upgrade.
/// The gate preserves first-subject-match semantics and ends at a self-signed
/// carried issuer. The upgrade tries every CA candidate, roots first, and ends
/// only at a certificate byte-identical to a relying-party-supplied root.
fn walk_chain<'a>(signer: &'a Certificate, pool: &'a [Certificate], roots: Option<&'a [Certificate]>, at: Option<&GeneralizedTime>) -> bool {
    let supplied = roots.is_some();
    let roots = roots.unwrap_or(&[]);
    let root_ders: BTreeSet<Vec<u8>> = roots.iter().filter_map(|c| c.to_der().ok()).collect();
    let (mut stack, mut seen) = (vec![(signer, 0usize)], BTreeMap::<Vec<u8>, usize>::new());
    while let Some((current, ca_below)) = stack.pop() {
        let Ok(current_der) = current.to_der() else { continue };
        if supplied && root_ders.contains(&current_der) {
            return true;
        }
        if seen.get(&current_der).is_some_and(|best| *best <= ca_below) {
            continue;
        }
        seen.insert(current_der, ca_below);
        let below = ca_below + usize::from(ca_constraint(current).is_some() && current.tbs_certificate.subject != current.tbs_certificate.issuer);
        let Ok(tbs) = current.tbs_certificate.to_der() else { return false };
        let subject_matches = |c: &&Certificate| c.tbs_certificate.subject == current.tbs_certificate.issuer;
        let mut candidates: Vec<_> = roots.iter().chain(pool).filter(subject_matches).filter_map(|cert| cert.to_der().ok().map(|der| (cert, der))).collect();
        candidates.sort_by(|a, b| a.1.cmp(&b.1));
        for (issuer, _) in candidates.into_iter().rev() {
            if !path_candidate_ok(current, issuer, &tbs, supplied, at, below) {
                continue;
            }
            if !supplied && issuer.tbs_certificate.subject == issuer.tbs_certificate.issuer {
                return true;
            }
            stack.push((issuer, below));
        }
    }
    false
}

fn gen_time_in_validity(gen_time: &GeneralizedTime, cert: &Certificate) -> bool {
    let g = gen_time.to_unix_duration();
    let v = &cert.tbs_certificate.validity;
    v.not_before.to_unix_duration() <= g && g <= v.not_after.to_unix_duration()
}

/// Verify an RFC 3161 TimeStampToken (DER) against an expected SHA-256
/// digest (lowercase hex) and a pinned PEM certificate chain. Boolean-only
/// mirror of `verify/tsa.py::verify_tst` (detail strings and genTime
/// extraction are a Python-report concern). Signatures verify under ECDSA
/// P-256/P-384 and RSASSA-PKCS1-v1_5. Malformed or hostile input is false,
/// never a panic.
pub(crate) fn verified_tst(token_der: &[u8], expected_digest_hex: &str, cert_chain_pem: &str, roots_pem: Option<&str>) -> Option<(GeneralizedTime, bool)> {
    let (sd, tst_der, tst) = parse_token(token_der)?;
    // 2. message imprint: SHA-256 over exactly the expected digest (string
    // compare on lowercase hex, exactly like the Python verifier)
    if tst.alg != OID_SHA256 || crate::hex(&tst.digest) != expected_digest_hex {
        return None;
    }
    // 3. signer info + message-digest attribute
    let si = check_signer_info(&sd, &tst_der)?;
    let signer = find_signer_cert(&sd, si)?;
    // 4. signature over the signed attributes (re-encoded as DER SET OF —
    // Python's `signed_attrs.untag().dump()`)
    let attrs_der = si.signed_attrs.as_ref().and_then(|a| a.to_der().ok())?;
    let spki = &signer.tbs_certificate.subject_public_key_info;
    if !verify_sig(spki, &si.signature_algorithm.oid, &si.digest_alg.oid, si.signature.as_bytes(), &attrs_der) {
        return None;
    }
    let pool = Certificate::load_pem_chain(cert_chain_pem.as_bytes()).ok()?;
    let trusted = roots_pem.and_then(|pem| Certificate::load_pem_chain(pem.as_bytes()).ok()).is_some_and(|roots| is_timestamping_signer(signer) && walk_chain(signer, &pool, Some(&roots), Some(&tst.gen_time)));
    // 5. chain to a carried self-signed root
    if !walk_chain(signer, &pool, None, None) {
        return None;
    }
    // 6. genTime within the signer certificate's validity window
    gen_time_in_validity(&tst.gen_time, signer).then_some((tst.gen_time, trusted))
}

pub fn verify_tst(token_der: &[u8], expected_digest_hex: &str, cert_chain_pem: &str) -> bool {
    verified_tst(token_der, expected_digest_hex, cert_chain_pem, None).is_some()
}
