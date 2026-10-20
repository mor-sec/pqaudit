//! Read X.509 certificates from PEM and DER data.
//!
//! The code reads only `CERTIFICATE` blocks. It never decodes other blocks, for example private keys.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use pqaudit_core::{Algorithm, CertInfo};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use crate::messages;

/// The start line of a PEM certificate block.
const PEM_BEGIN: &[u8] = b"-----BEGIN CERTIFICATE-----";
/// The end line of a PEM certificate block.
const PEM_END: &[u8] = b"-----END CERTIFICATE-----";
/// The start of every PEM block.
const PEM_ANY_BEGIN: &[u8] = b"-----BEGIN ";
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
    /// The number of blocks that are not valid.
    pub bad: usize,
    /// The reason for the first bad block.
    pub first_problem: Option<&'static str>,
}

/// Return true if the data has the start line of a certificate block.
pub fn has_pem_certificate(data: &[u8]) -> bool {
    find(data, PEM_BEGIN, 0).is_some()
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
    while let Some(start) = find(data, PEM_BEGIN, cursor) {
        // Count the line breaks between the last counted place and this block.
        line = line.saturating_add(count_lines(&data[counted..start]));
        counted = start;
        let body_start = start + PEM_BEGIN.len();
        let Some(end) = find(data, PEM_END, body_start) else {
            result.problem(messages::PEM_NOT_CLOSED);
            break;
        };
        let index = result.certs.len() + result.bad;
        match decode_block(&data[body_start..end]) {
            Some(der) => match parse_certificate(&der, index) {
                Ok(info) => result.certs.push(Found {
                    info,
                    line: Some(line),
                }),
                Err(reason) => result.problem(reason),
            },
            None => result.problem(messages::PEM_BAD_BASE64),
        }
        cursor = end + PEM_END.len();
    }
    result
}

impl PemResult {
    fn problem(&mut self, reason: &'static str) {
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

/// Read one DER certificate.
pub fn parse_der(data: &[u8]) -> Result<CertInfo, &'static str> {
    parse_certificate(data, 0).map_err(|_| messages::DER_INVALID)
}

/// Read the facts of one certificate. The `position` is the place in the file.
fn parse_certificate(der: &[u8], position: usize) -> Result<CertInfo, &'static str> {
    let (_, cert) = X509Certificate::from_der(der).map_err(|_| messages::CERT_INVALID)?;
    let spki = cert.public_key();
    let public_key = public_key_algorithm(spki);
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

fn sha256_hex(data: &[u8]) -> String {
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
fn public_key_algorithm(spki: &SubjectPublicKeyInfo<'_>) -> Algorithm {
    let oid = spki.algorithm.algorithm.to_id_string();
    let plain = |name: &str, key_bits: Option<u32>| Algorithm {
        name: name.to_string(),
        key_bits,
        curve: None,
    };
    match oid.as_str() {
        "1.2.840.113549.1.1.1" => {
            let bits = match spki.parsed() {
                Ok(PublicKey::RSA(rsa)) => bit_length(rsa.modulus),
                _ => None,
            };
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
        other => plain(other, None),
    }
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
