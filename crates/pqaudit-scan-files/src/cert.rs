//! Read X.509 certificates from PEM and DER data.
//!
//! The code reads only `CERTIFICATE` blocks. It never decodes other blocks, for example private keys.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use pqaudit_core::{Algorithm, CertInfo};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::public_key::{PublicKey, RSAPublicKey};

use crate::messages;

/// The start of every PEM block.
const PEM_ANY_BEGIN: &[u8] = b"-----BEGIN ";
/// The end of a PEM label.
const PEM_DASHES: &[u8] = b"-----";
/// The PEM labels that hold an X.509 certificate.
const CERT_LABELS: [&[u8]; 3] = [b"CERTIFICATE", b"TRUSTED CERTIFICATE", b"X509 CERTIFICATE"];
/// The longest subject or issuer text that the tool keeps, in characters.
const MAX_NAME_CHARS: usize = 512;

/// One certificate from a file.
#[derive(Debug)]
pub struct Found {
    /// The facts about the certificate.
    pub info: CertInfo,
    /// The line of the start line of the PEM block. A DER file has no line.
    pub line: Option<u32>,
}

/// The result of the read of PEM data.
#[derive(Debug, Default)]
pub struct PemResult {
    /// The valid certificates.
    pub certs: Vec<Found>,
    /// The number of certificate blocks that are not valid.
    pub bad: usize,
    /// The number of PEM blocks of other types, for example keys. The tool does not read them.
    pub other: usize,
    /// The reason for the first bad block.
    pub first_problem: Option<String>,
}

/// Return true if the data has the start line of a certificate block.
pub fn has_pem_certificate(data: &[u8]) -> bool {
    CERT_LABELS.iter().any(|label| {
        let mut marker = PEM_ANY_BEGIN.to_vec();
        marker.extend_from_slice(label);
        marker.extend_from_slice(PEM_DASHES);
        find(data, &marker, 0).is_some()
    })
}

/// Return true if the data has the start line of any PEM block.
pub fn has_any_pem(data: &[u8]) -> bool {
    find(data, PEM_ANY_BEGIN, 0).is_some()
}

fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|index| index + from)
}

/// Read all certificate blocks of PEM data.
pub fn parse_pem(data: &[u8]) -> PemResult {
    let mut result = PemResult::default();
    let mut cursor = 0;
    let mut line = 1u32;
    let mut counted = 0;
    while let Some(start) = find(data, PEM_ANY_BEGIN, cursor) {
        let label_start = start + PEM_ANY_BEGIN.len();
        let Some(label_end) = find(data, PEM_DASHES, label_start) else {
            break;
        };
        let label = &data[label_start..label_end];
        let body_start = label_end + PEM_DASHES.len();
        if !CERT_LABELS.contains(&label) {
            result.other += 1;
            cursor = body_start;
            continue;
        }
        // Count the line breaks between the last counted place and this block.
        line = line.saturating_add(count_lines(&data[counted..start]));
        counted = start;
        let mut end_marker = b"-----END ".to_vec();
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(PEM_DASHES);
        let Some(end) = find(data, &end_marker, body_start) else {
            result.problem(messages::PEM_NOT_CLOSED.to_string());
            break;
        };
        let index = result.certs.len() + result.bad;
        match decode_block(&data[body_start..end]) {
            Some(der) => match parse_certificate(&der, index) {
                Ok(info) => result.certs.push(Found {
                    info,
                    line: Some(line),
                }),
                Err(error) => result.problem(error.reason()),
            },
            None => result.problem(messages::PEM_BAD_BASE64.to_string()),
        }
        cursor = end + end_marker.len();
    }
    result
}

impl PemResult {
    fn problem(&mut self, reason: String) {
        self.bad += 1;
        self.first_problem.get_or_insert(reason);
    }
}

fn count_lines(data: &[u8]) -> u32 {
    u32::try_from(data.iter().filter(|byte| **byte == b'\n').count()).unwrap_or(u32::MAX)
}

/// Decode the base64 text between the start line and the end line.
fn decode_block(body: &[u8]) -> Option<Vec<u8>> {
    let text: Vec<u8> = body
        .iter()
        .copied()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    STANDARD.decode(text).ok()
}

/// Why the tool cannot read a certificate.
#[derive(Debug)]
pub enum CertError {
    /// The data is not a valid certificate.
    Invalid,
    /// The public key type is not known. The value is the OID text.
    UnknownKey(String),
}

impl CertError {
    /// The text for the user. It never holds certificate bytes.
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid => messages::CERT_INVALID.to_string(),
            Self::UnknownKey(oid) => messages::UNKNOWN_KEY.replace("{oid}", oid),
        }
    }
}

/// Read one DER certificate.
pub fn parse_der(data: &[u8]) -> Result<CertInfo, String> {
    parse_certificate(data, 0).map_err(|error| match error {
        CertError::Invalid => messages::DER_INVALID.to_string(),
        other => other.reason(),
    })
}

/// Read the facts of one certificate. The `position` is the place in the file.
///
/// The data can have bytes after the certificate, for example OpenSSL trust data.
/// The hash covers the certificate only.
pub(crate) fn parse_certificate(der: &[u8], position: usize) -> Result<CertInfo, CertError> {
    let (rest, cert) = X509Certificate::from_der(der).map_err(|_| CertError::Invalid)?;
    let der = &der[..der.len() - rest.len()];
    let spki = cert.public_key();
    let public_key = public_key_algorithm(spki)?;
    let signature_algorithm = signature_name(&cert.signature_algorithm.algorithm.to_id_string());

    let (key_usage, is_ca) = key_usage_and_ca(&cert);
    let ext_key_usage = ext_key_usage(&cert);

    Ok(CertInfo {
        sha256: sha256_hex(der),
        subject: limit(cert.subject().to_string()),
        issuer: limit(cert.issuer().to_string()),
        not_before: to_utc(cert.validity().not_before.timestamp()),
        not_after: to_utc(cert.validity().not_after.timestamp()),
        is_ca,
        key_usage,
        ext_key_usage,
        public_key,
        signature_algorithm,
        chain_position: Some(u8::try_from(position).unwrap_or(u8::MAX)),
    })
}

fn limit(text: String) -> String {
    if text.chars().count() > MAX_NAME_CHARS {
        text.chars().take(MAX_NAME_CHARS).collect()
    } else {
        text
    }
}

fn to_utc(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap_or_default()
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(64);
    for byte in Sha256::digest(data) {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn key_usage_and_ca(cert: &X509Certificate<'_>) -> (Vec<String>, bool) {
    let mut names = Vec::new();
    if let Ok(Some(usage)) = cert.key_usage() {
        let usage = usage.value;
        for (set, name) in [
            (usage.digital_signature(), "digitalSignature"),
            (usage.non_repudiation(), "nonRepudiation"),
            (usage.key_encipherment(), "keyEncipherment"),
            (usage.data_encipherment(), "dataEncipherment"),
            (usage.key_agreement(), "keyAgreement"),
            (usage.key_cert_sign(), "keyCertSign"),
            (usage.crl_sign(), "cRLSign"),
            (usage.encipher_only(), "encipherOnly"),
            (usage.decipher_only(), "decipherOnly"),
        ] {
            if set {
                names.push(name.to_string());
            }
        }
    }
    let is_ca = matches!(cert.basic_constraints(), Ok(Some(constraints)) if constraints.value.ca);
    (names, is_ca)
}

fn ext_key_usage(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut names = Vec::new();
    if let Ok(Some(usage)) = cert.extended_key_usage() {
        let usage = usage.value;
        for (set, name) in [
            (usage.any, "any"),
            (usage.server_auth, "serverAuth"),
            (usage.client_auth, "clientAuth"),
            (usage.code_signing, pqaudit_core::classify::EKU_CODE_SIGNING),
            (usage.email_protection, "emailProtection"),
            (usage.time_stamping, "timeStamping"),
            (usage.ocsp_signing, "ocspSigning"),
        ] {
            if set {
                names.push(name.to_string());
            }
        }
        names.extend(usage.other.iter().take(32).map(|oid| oid.to_id_string()));
    }
    names
}

/// Return the algorithm of the public key.
fn public_key_algorithm(spki: &SubjectPublicKeyInfo<'_>) -> Result<Algorithm, CertError> {
    let oid = spki.algorithm.algorithm.to_id_string();
    let plain = |name: &str, key_bits: Option<u32>| Algorithm {
        name: name.to_string(),
        key_bits,
        curve: None,
    };
    Ok(match oid.as_str() {
        // The key of an RSA-PSS certificate has the same format as an RSA key.
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
            let bits = RSAPublicKey::from_der(&spki.subject_public_key.data)
                .ok()
                .and_then(|(_, rsa)| bit_length(rsa.modulus));
            plain("RSA", bits)
        }
        "1.2.840.10040.4.1" => {
            let bits = match spki.parsed() {
                Ok(PublicKey::DSA(y)) => bit_length(y),
                _ => None,
            };
            plain("DSA", bits)
        }
        "1.2.840.10045.2.1" => {
            let curve_oid = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|parameters| parameters.as_oid().ok())
                .map(|oid| oid.to_id_string());
            let (curve, bits) = match curve_oid.as_deref() {
                Some("1.2.840.10045.3.1.1") => (Some("P-192"), Some(192)),
                Some("1.3.132.0.33") => (Some("P-224"), Some(224)),
                Some("1.2.840.10045.3.1.7") => (Some("P-256"), Some(256)),
                Some("1.3.132.0.34") => (Some("P-384"), Some(384)),
                Some("1.3.132.0.35") => (Some("P-521"), Some(521)),
                Some("1.3.132.0.10") => (Some("secp256k1"), Some(256)),
                _ => (None, None),
            };
            Algorithm {
                name: "ECDSA".to_string(),
                key_bits: bits,
                curve: curve.map(str::to_string).or(curve_oid),
            }
        }
        "1.3.101.112" => plain("Ed25519", Some(256)),
        "1.3.101.113" => plain("Ed448", Some(456)),
        "1.3.101.110" => plain("X25519", Some(256)),
        "1.3.101.111" => plain("X448", Some(448)),
        "2.16.840.1.101.3.4.3.17" => plain("ML-DSA-44", None),
        "2.16.840.1.101.3.4.3.18" => plain("ML-DSA-65", None),
        "2.16.840.1.101.3.4.3.19" => plain("ML-DSA-87", None),
        other if is_slh_dsa(other) => plain("SLH-DSA", None),
        other => return Err(CertError::UnknownKey(other.to_string())),
    })
}

/// SLH-DSA has 12 parameter sets. Their last OID numbers are 20 to 31.
fn is_slh_dsa(oid: &str) -> bool {
    oid.strip_prefix("2.16.840.1.101.3.4.3.")
        .and_then(|last| last.parse::<u8>().ok())
        .is_some_and(|last| (20..=31).contains(&last))
}

/// Return the number of bits of a big-endian number without leading zero bits.
fn bit_length(bytes: &[u8]) -> Option<u32> {
    let skip = bytes.iter().take_while(|byte| **byte == 0).count();
    let rest = &bytes[skip..];
    let first = *rest.first()?;
    let bits = rest.len() * 8 - first.leading_zeros() as usize;
    u32::try_from(bits).ok()
}

/// Return the name of a signature algorithm. Use the OID text if the name is not known.
fn signature_name(oid: &str) -> String {
    let name = match oid {
        "1.2.840.113549.1.1.2" => "md2WithRSAEncryption",
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" | "1.3.14.3.2.29" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.14" => "sha224WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10040.4.3" => "dsa-with-sha1",
        "2.16.840.1.101.3.4.3.2" => "dsa-with-sha256",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        "2.16.840.1.101.3.4.3.17" => "ML-DSA-44",
        "2.16.840.1.101.3.4.3.18" => "ML-DSA-65",
        "2.16.840.1.101.3.4.3.19" => "ML-DSA-87",
        other if is_slh_dsa(other) => "SLH-DSA",
        other => other,
    };
    name.to_string()
}
