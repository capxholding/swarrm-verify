// Apache-2.0 (public verifier repo)
use cms::cert::CertificateChoices;
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{CertificateSet, DigestAlgorithmIdentifiers, EncapsulatedContentInfo, SignerIdentifier, SignerInfo, SignerInfos};
use der::asn1::{Any, AnyRef, GeneralizedTime, IntRef, ObjectIdentifier, OctetString, OctetStringRef, SetOfVec};
use der::{Decode, Encode, Reader, SliceReader, Tag, TagNumber, Tagged};
use p256::ecdsa::signature::hazmat::PrehashVerifier; // shared trait; p384 keys implement it too
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::{Pkcs1v15Sign, RsaPublicKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::collections::{BTreeMap, BTreeSet};
use x509_cert::attr::Attributes;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::certpolicy::PolicyInformation;
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::Certificate;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};

const OID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const OID_TST_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.1.4");
const OID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const OID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const OID_SIGNING_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");
const OID_SIGNING_CERTIFICATE_V2: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
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
const OID_BASIC_OCSP_RESPONSE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.1");

struct TstImprint {
    alg: ObjectIdentifier,
    digest: Vec<u8>,
    gen_time: GeneralizedTime,
}

#[derive(der::Sequence)]
struct TimestampSignedData {
    version: CmsVersion,
    digest_algorithms: DigestAlgorithmIdentifiers,
    encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<CertificateSet>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    crls: Option<SetOfVec<Any>>,
    signer_infos: SignerInfos,
}

#[derive(der::Sequence)]
struct IssuerSerial {
    issuer: GeneralNames,
    serial_number: SerialNumber,
}

#[derive(der::Sequence)]
struct EssCertIdV2 {
    hash_algorithm: Option<AlgorithmIdentifierOwned>,
    cert_hash: OctetString,
    issuer_serial: Option<IssuerSerial>,
}

#[derive(der::Sequence)]
struct SigningCertificateV2 {
    certs: Vec<EssCertIdV2>,
    policies: Option<Vec<PolicyInformation>>,
}

fn other_revocation_present(crls: Option<&SetOfVec<Any>>) -> Option<bool> {
    let mut other = false;
    for item in crls.into_iter().flat_map(|items| items.iter()) {
        match item.tag() {
            Tag::Sequence => {
                x509_cert::crl::CertificateList::from_der(&item.to_der().ok()?).ok()?;
            }
            Tag::ContextSpecific { constructed: true, number: TagNumber::N1 } => {
                let mut reader = SliceReader::new(item.value()).ok()?;
                ObjectIdentifier::decode(&mut reader).ok()?;
                Any::decode(&mut reader).ok()?;
                if !reader.is_finished() {
                    return None;
                }
                other = true;
            }
            _ => return None,
        }
    }
    Some(other)
}

fn hash_bytes(oid: &ObjectIdentifier, data: &[u8]) -> Option<Vec<u8>> {
    match *oid {
        OID_SHA256 => Some(Sha256::digest(data).to_vec()),
        OID_SHA384 => Some(Sha384::digest(data).to_vec()),
        OID_SHA512 => Some(Sha512::digest(data).to_vec()),
        _ => None,
    }
}

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

macro_rules! verify_ecdsa_curve {
    ($curve:ident, $key:expr, $sig:expr, $digest:expr) => {{
        let Ok(key) = $curve::ecdsa::VerifyingKey::from_sec1_bytes($key) else { return false };
        let Ok(sig) = $curve::ecdsa::Signature::from_der($sig) else { return false };
        key.verify_prehash($digest, &sig).is_ok()
    }};
}

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

fn verify_rsa(spki: &SubjectPublicKeyInfoOwned, sig: &[u8], digest: &[u8], hash_oid: &ObjectIdentifier) -> bool {
    if spki.algorithm.oid != OID_RSA_ENCRYPTION {
        return false;
    }
    let Some(key_bytes) = spki.subject_public_key.as_bytes() else { return false };
    let Ok(key) = RsaPublicKey::from_pkcs1_der(key_bytes) else { return false };
    let scheme = match *hash_oid {
        OID_SHA256 => Pkcs1v15Sign::new::<Sha256>(),
        OID_SHA384 => Pkcs1v15Sign::new::<Sha384>(),
        OID_SHA512 => Pkcs1v15Sign::new::<Sha512>(),
        _ => return false,
    };
    key.verify(scheme, digest, sig).is_ok()
}

fn parse_imprint(r: &mut SliceReader) -> Option<(ObjectIdentifier, Vec<u8>)> {
    let imprint = AnyRef::decode(r).ok()?;
    (imprint.tag() == Tag::Sequence).then_some(())?;
    let mut ir = SliceReader::new(imprint.value()).ok()?;
    let alg = x509_cert::spki::AlgorithmIdentifierOwned::decode(&mut ir).ok()?;
    let digest = OctetStringRef::decode(&mut ir).ok()?;
    Some((alg.oid, digest.as_bytes().to_vec()))
}

fn parse_tst_info(tst_der: &[u8]) -> Option<TstImprint> {
    let outer = AnyRef::from_der(tst_der).ok()?;
    (outer.tag() == Tag::Sequence).then_some(())?;
    let mut r = SliceReader::new(outer.value()).ok()?;
    (u8::decode(&mut r).ok()? == 1).then_some(())?;
    let _policy = ObjectIdentifier::decode(&mut r).ok()?;
    let (alg, digest) = parse_imprint(&mut r)?;
    let _serial = IntRef::decode(&mut r).ok()?;
    let gen_time = GeneralizedTime::decode(&mut r).ok()?;
    Some(TstImprint { alg, digest, gen_time })
}

fn parse_token(token_der: &[u8]) -> Option<(TimestampSignedData, Vec<u8>, TstImprint)> {
    let ci = ContentInfo::from_der(token_der).ok()?;
    (ci.content_type == OID_SIGNED_DATA).then_some(())?;
    let sd: TimestampSignedData = ci.content.decode_as().ok()?;
    (sd.encap_content_info.econtent_type == OID_TST_INFO).then_some(())?;
    let other_cert = sd.certificates.as_ref().is_some_and(|cs| cs.0.iter().any(|c| matches!(c, CertificateChoices::Other(_))));
    let other_revocation = other_revocation_present(sd.crls.as_ref())?;
    (sd.version == if other_cert || other_revocation { CmsVersion::V5 } else { CmsVersion::V3 }).then_some(())?;
    let tst_der = sd.encap_content_info.econtent.as_ref()?.decode_as::<OctetStringRef>().ok()?.as_bytes().to_vec();
    let info = parse_tst_info(&tst_der)?;
    Some((sd, tst_der, info))
}

fn signed_attribute(attrs: &Attributes, oid: ObjectIdentifier) -> Option<&Any> {
    let mut matches = attrs.iter().filter(|a| a.oid == oid);
    let (Some(attr), None) = (matches.next(), matches.next()) else { return None };
    (attr.values.len() == 1).then_some(())?;
    attr.values.iter().next()
}

fn ess_cert_id_v2_matches(attrs: &Attributes, signer: &Certificate) -> bool {
    if attrs.iter().any(|attr| attr.oid == OID_SIGNING_CERTIFICATE) {
        return false;
    }
    let Some(binding) = signed_attribute(attrs, OID_SIGNING_CERTIFICATE_V2) else { return false };
    let Ok(binding) = binding.decode_as::<SigningCertificateV2>() else { return false };
    let Some(identifier) = binding.certs.first() else { return false };
    let Ok(signer_der) = signer.to_der() else { return false };
    let algorithm = identifier.hash_algorithm.as_ref().map_or(OID_SHA256, |value| value.oid);
    if hash_bytes(&algorithm, &signer_der).as_deref() != Some(identifier.cert_hash.as_bytes()) {
        return false;
    }
    identifier.issuer_serial.as_ref().is_none_or(|id| id.serial_number == signer.tbs_certificate.serial_number && id.issuer.iter().any(|name| matches!(name, GeneralName::DirectoryName(value) if value == &signer.tbs_certificate.issuer)))
}

fn ess_requirement_met(sd: &TimestampSignedData, si: &SignerInfo, required: bool) -> bool {
    !required || si.signed_attrs.as_ref().is_some_and(|attrs| find_signer_cert(sd, si).is_some_and(|signer| ess_cert_id_v2_matches(attrs, signer)))
}

fn check_signer_info<'a>(sd: &'a TimestampSignedData, tst_der: &[u8], require_ess: bool) -> Option<&'a SignerInfo> {
    let mut infos = sd.signer_infos.0.iter();
    let (Some(si), None) = (infos.next(), infos.next()) else {
        return None;
    }; // exactly one
    (si.version == CmsVersion::V1 && matches!(si.sid, SignerIdentifier::IssuerAndSerialNumber(_))).then_some(())?;
    let signed_attrs = si.signed_attrs.as_ref()?;
    (!signed_attrs.is_empty()).then_some(())?;
    let want = hash_bytes(&si.digest_alg.oid, tst_der)?;
    (signed_attribute(signed_attrs, OID_CONTENT_TYPE)?.decode_as::<ObjectIdentifier>().ok()? == OID_TST_INFO && signed_attribute(signed_attrs, OID_MESSAGE_DIGEST)?.decode_as::<OctetStringRef>().ok()?.as_bytes() == want).then_some(())?;
    ess_requirement_met(sd, si, require_ess).then_some(si)
}

fn find_signer_cert<'a>(sd: &'a TimestampSignedData, si: &SignerInfo) -> Option<&'a Certificate> {
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

fn ca_constraint(cert: &Certificate) -> Option<Option<u8>> {
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage};
    let Ok(Some((_, bc))) = cert.tbs_certificate.get::<BasicConstraints>() else { return None };
    let Ok(Some((_, ku))) = cert.tbs_certificate.get::<KeyUsage>() else { return None };
    (bc.ca && ku.key_cert_sign()).then_some(bc.path_len_constraint)
}

fn is_timestamping_signer(cert: &Certificate) -> bool {
    use x509_cert::ext::pkix::ExtendedKeyUsage;
    matches!(cert.tbs_certificate.get::<ExtendedKeyUsage>(), Ok(Some((true, eku))) if eku.0.as_slice() == [OID_ID_KP_TIME_STAMPING])
}

fn path_candidate_ok(current: &Certificate, issuer: &Certificate, tbs: &[u8], supplied: bool, at: Option<&GeneralizedTime>, below: usize) -> bool {
    let constraint = if supplied { ca_constraint(issuer) } else { Some(None) };
    let profile_ok = |cert: &Certificate| cert.tbs_certificate.extensions.as_ref().is_none_or(|extensions| extensions.iter().all(|ext| ext.extn_id != OID_NAME_CONSTRAINTS && (!ext.critical || matches!(ext.extn_id, OID_KEY_USAGE | OID_SUBJECT_ALT_NAME | OID_BASIC_CONSTRAINTS | OID_EXTENDED_KEY_USAGE))));
    (!supplied || profile_ok(current) && profile_ok(issuer)) && constraint.is_some() && at.is_none_or(|time| gen_time_in_validity(time, issuer)) && constraint.flatten().is_none_or(|limit| below <= usize::from(limit)) && cert_sig_valid(current, issuer, tbs)
}

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

fn status_issuer<'a>(signer: &Certificate, pool: &'a [Certificate]) -> Option<&'a Certificate> {
    let tbs = signer.tbs_certificate.to_der().ok()?;
    pool.iter().find(|candidate| candidate.tbs_certificate.subject == signer.tbs_certificate.issuer && cert_sig_valid(signer, candidate, &tbs))
}

fn crl_status_ok(raw: &[u8], signer: &Certificate, issuer: &Certificate, at: &GeneralizedTime) -> bool {
    use x509_cert::ext::pkix::KeyUsage;
    let Ok(crl) = CertificateList::from_der(raw) else { return false };
    let tbs = &crl.tbs_cert_list;
    let Some(next) = tbs.next_update.as_ref() else { return false };
    let extensions_ok = tbs.crl_extensions.as_ref().is_none_or(|extensions| extensions.iter().all(|ext| !ext.critical && !matches!(ext.extn_id.to_string().as_str(), "2.5.29.27" | "2.5.29.28")));
    let usage_ok = matches!(issuer.tbs_certificate.get::<KeyUsage>(), Ok(Some((_, usage))) if usage.crl_sign());
    let Some(signature) = crl.signature.as_bytes() else { return false };
    let Ok(tbs_der) = tbs.to_der() else { return false };
    let instant = at.to_unix_duration();
    let time_ok = tbs.this_update.to_unix_duration() <= instant && instant <= next.to_unix_duration();
    let not_revoked = tbs.revoked_certificates.as_ref().is_none_or(|items| items.iter().all(|entry| entry.serial_number != signer.tbs_certificate.serial_number || entry.revocation_date.to_unix_duration() > instant));
    tbs.issuer == issuer.tbs_certificate.subject && crl.signature_algorithm == tbs.signature && extensions_ok && usage_ok && time_ok && not_revoked && verify_sig(&issuer.tbs_certificate.subject_public_key_info, &crl.signature_algorithm.oid, &crl.signature_algorithm.oid, signature, &tbs_der)
}

fn ocsp_status_ok(raw: &[u8], signer: &Certificate, issuer: &Certificate, at: &GeneralizedTime) -> bool {
    let Ok(response) = OcspResponse::from_der(raw) else { return false };
    if response.response_status != OcspResponseStatus::Successful {
        return false;
    }
    let Some(bytes) = response.response_bytes.filter(|value| value.response_type == OID_BASIC_OCSP_RESPONSE) else { return false };
    let Ok(basic) = BasicOcspResponse::from_der(bytes.response.as_bytes()) else { return false };
    if basic.certs.as_ref().is_some_and(|certs| !certs.is_empty()) || basic.tbs_response_data.responses.len() != 1 || basic.tbs_response_data.responder_id != ResponderId::ByName(issuer.tbs_certificate.subject.clone()) {
        return false;
    }
    let single = &basic.tbs_response_data.responses[0];
    let id = &single.cert_id;
    let Ok(name_der) = issuer.tbs_certificate.subject.to_der() else { return false };
    let key = issuer.tbs_certificate.subject_public_key_info.subject_public_key.raw_bytes();
    let instant = at.to_unix_duration();
    let Some(next) = single.next_update.as_ref() else { return false };
    let time_ok = single.this_update.0.to_unix_duration() <= instant && instant <= next.0.to_unix_duration() && single.this_update.0.to_unix_duration() <= basic.tbs_response_data.produced_at.0.to_unix_duration();
    let identity_ok = id.serial_number == signer.tbs_certificate.serial_number && hash_bytes(&id.hash_algorithm.oid, &name_der).as_deref() == Some(id.issuer_name_hash.as_bytes()) && hash_bytes(&id.hash_algorithm.oid, key).as_deref() == Some(id.issuer_key_hash.as_bytes());
    let Some(signature) = basic.signature.as_bytes() else { return false };
    let Ok(tbs_der) = basic.tbs_response_data.to_der() else { return false };
    identity_ok && matches!(single.cert_status, CertStatus::Good(_)) && time_ok && verify_sig(&issuer.tbs_certificate.subject_public_key_info, &basic.signature_algorithm.oid, &basic.signature_algorithm.oid, signature, &tbs_der)
}

fn offline_status_ok(trust: Option<&serde_json::Value>, signer: &Certificate, pool: &[Certificate], at: &GeneralizedTime) -> bool {
    let Ok(signer_der) = signer.to_der() else { return false };
    let Some((kind, raw)) = crate::trust::tsa_revocation_record(trust, &signer_der) else { return false };
    let Some(issuer) = status_issuer(signer, pool) else { return false };
    match kind {
        crate::trust::TsaStatusKind::Crl => crl_status_ok(&raw, signer, issuer, at),
        crate::trust::TsaStatusKind::Ocsp => ocsp_status_ok(&raw, signer, issuer, at),
    }
}

fn policy_status_ok(policy: crate::trust::TsaPolicy, trust: Option<&serde_json::Value>, signer: &Certificate, pool: &[Certificate], at: &GeneralizedTime) -> bool {
    !matches!(policy, crate::trust::TsaPolicy::OfflineLifecycle | crate::trust::TsaPolicy::OfflineRenewal) || offline_status_ok(trust, signer, pool, at)
}

fn imprint_matches(tst: &TstImprint, expected_digest_hex: &str, material: Option<&[u8]>) -> bool {
    match material {
        Some(value) => hash_bytes(&tst.alg, value).is_some_and(|digest| tst.digest == digest),
        None => tst.alg == OID_SHA256 && crate::hex(&tst.digest) == expected_digest_hex,
    }
}

fn verified_tst_inner(token_der: &[u8], expected_digest_hex: &str, renewal_material: Option<&[u8]>, cert_chain_pem: &str, roots_pem: Option<&str>, policy: crate::trust::TsaPolicy, trust: Option<&serde_json::Value>) -> Option<(GeneralizedTime, bool)> {
    let (sd, tst_der, tst) = parse_token(token_der)?;
    if !imprint_matches(&tst, expected_digest_hex, renewal_material) {
        return None;
    }
    let require_ess = matches!(policy, crate::trust::TsaPolicy::EssCertIdV2 | crate::trust::TsaPolicy::OfflineLifecycle | crate::trust::TsaPolicy::OfflineRenewal);
    let si = check_signer_info(&sd, &tst_der, require_ess)?;
    let signer = find_signer_cert(&sd, si)?;
    let attrs_der = si.signed_attrs.as_ref().and_then(|a| a.to_der().ok())?;
    let spki = &signer.tbs_certificate.subject_public_key_info;
    if !verify_sig(spki, &si.signature_algorithm.oid, &si.digest_alg.oid, si.signature.as_bytes(), &attrs_der) {
        return None;
    }
    let pool = Certificate::load_pem_chain(cert_chain_pem.as_bytes()).ok()?;
    if !policy_status_ok(policy, trust, signer, &pool, &tst.gen_time) {
        return None;
    }
    let trusted = roots_pem.and_then(|pem| Certificate::load_pem_chain(pem.as_bytes()).ok()).is_some_and(|roots| is_timestamping_signer(signer) && walk_chain(signer, &pool, Some(&roots), Some(&tst.gen_time)));
    if !walk_chain(signer, &pool, None, None) {
        return None;
    }
    gen_time_in_validity(&tst.gen_time, signer).then_some((tst.gen_time, trusted))
}

pub(crate) fn verified_tst(token_der: &[u8], expected_digest_hex: &str, cert_chain_pem: &str, roots_pem: Option<&str>, policy: crate::trust::TsaPolicy, trust: Option<&serde_json::Value>) -> Option<(GeneralizedTime, bool)> {
    verified_tst_inner(token_der, expected_digest_hex, None, cert_chain_pem, roots_pem, policy, trust)
}

fn frame(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
}

fn renewal_predecessor(token: &[u8], chain: &str, trust: Option<&serde_json::Value>) -> Option<Vec<u8>> {
    let (sd, tst_der, _) = parse_token(token)?;
    let si = check_signer_info(&sd, &tst_der, false)?;
    let signer = find_signer_cert(&sd, si)?;
    let signer_der = signer.to_der().ok()?;
    let (kind, status) = crate::trust::tsa_revocation_record(trust, &signer_der)?;
    let kind = match kind {
        crate::trust::TsaStatusKind::Crl => b"crl".as_slice(),
        crate::trust::TsaStatusKind::Ocsp => b"ocsp".as_slice(),
    };
    if chain.is_empty() {
        return None;
    }
    let mut out = b"evd/tsa-renewal-predecessor/v1\0".to_vec();
    for field in [token, chain.as_bytes(), kind, status.as_slice()] {
        frame(&mut out, field);
    }
    Some(out)
}

pub(crate) fn verify_renewal_chain(original_token: &[u8], original_chain: &str, original_time: &GeneralizedTime, renewals: &[(Vec<u8>, String)], roots: Option<&str>, trust: Option<&serde_json::Value>) -> bool {
    let Some(roots) = roots else { return false };
    let Some(mut material) = renewal_predecessor(original_token, original_chain, trust) else { return false };
    let mut previous = original_time.to_unix_duration();
    for (token, chain) in renewals {
        let Some((current, trusted)) = verified_tst_inner(token, "", Some(&material), chain, Some(roots), crate::trust::TsaPolicy::OfflineRenewal, trust) else { return false };
        if !trusted || current.to_unix_duration() <= previous {
            return false;
        }
        let Some(next) = renewal_predecessor(token, chain, trust) else { return false };
        material = next;
        previous = current.to_unix_duration();
    }
    true
}

pub fn verify_tst(token_der: &[u8], expected_digest_hex: &str, cert_chain_pem: &str) -> bool {
    verified_tst(token_der, expected_digest_hex, cert_chain_pem, None, crate::trust::TsaPolicy::Absent, None).is_some()
}
