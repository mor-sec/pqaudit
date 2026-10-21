//! Read X.509 certificates and map key identifiers to rules pack names.
//!
//! The file scanner and the network scanner share this code.

use crate::finding::{Algorithm, CertInfo};
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;
use x509_parser::public_key::{PublicKey, RSAPublicKey};

use crate::messages;

/// The longest subject or issuer text that the tool keeps, in characters.
const MAX_NAME_CHARS: usize = 512;

/// Return the number of bits of a big-endian number without leading zero bits.
pub fn bit_length(bytes: &[u8]) -> Option<u32> {
    let skip = bytes.iter().take_while(|byte| **byte == 0).count();
    let rest = &bytes[skip..];
    let first = *rest.first()?;
    let bits = rest.len() * 8 - first.leading_zeros() as usize;
    u32::try_from(bits).ok()
}

/// Facts that depend on the algorithm, from the key or from its parameters.
#[derive(Default)]
pub struct Parts<'a> {
    /// The OID text of the curve of an elliptic curve key.
    pub curve_oid: Option<String>,
    /// The modulus of an RSA key. Big-endian.
    pub rsa_modulus: Option<&'a [u8]>,
    /// A number that gives the size of a DSA key. Big-endian.
    pub dsa_number: Option<&'a [u8]>,
}

fn plain(name: &str, key_bits: Option<u32>) -> Algorithm {
    Algorithm {
        name: name.to_string(),
        key_bits,
        curve: None,
    }
}

/// Return the name and the size of a known curve.
fn known_curve(oid: &str) -> Option<(&'static str, u32)> {
    Some(match oid {
        "1.2.840.10045.3.1.1" => ("P-192", 192),
        "1.3.132.0.33" => ("P-224", 224),
        "1.2.840.10045.3.1.7" => ("P-256", 256),
        "1.3.132.0.34" => ("P-384", 384),
        "1.3.132.0.35" => ("P-521", 521),
        "1.3.132.0.10" => ("secp256k1", 256),
        _ => return None,
    })
}

/// Make the algorithm of an elliptic curve key. The `name` is "ECDSA" or "ECDH".
///
/// The curve is the name of a known curve, or the OID text of an unknown curve.
pub fn elliptic(name: &str, curve_oid: Option<String>) -> Algorithm {
    let known = curve_oid.as_deref().and_then(known_curve);
    Algorithm {
        name: name.to_string(),
        key_bits: known.map(|(_, bits)| bits),
        curve: known.map(|(curve, _)| curve.to_string()).or(curve_oid),
    }
}

/// Make the algorithm of a key from its OID. Return the OID text if the OID is not known.
pub fn from_oid(oid: &str, parts: &Parts<'_>) -> Result<Algorithm, String> {
    Ok(match oid {
        // The key of an RSA-PSS certificate has the same format as an RSA key.
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => {
            plain("RSA", parts.rsa_modulus.and_then(bit_length))
        }
        "1.2.840.10040.4.1" => plain("DSA", parts.dsa_number.and_then(bit_length)),
        "1.2.840.10045.2.1" => elliptic("ECDSA", parts.curve_oid.clone()),
        "1.3.101.112" => plain("Ed25519", Some(256)),
        "1.3.101.113" => plain("Ed448", Some(456)),
        "1.3.101.110" => plain("X25519", Some(256)),
        "1.3.101.111" => plain("X448", Some(448)),
        "2.16.840.1.101.3.4.4.1" => plain("ML-KEM-512", None),
        "2.16.840.1.101.3.4.4.2" => plain("ML-KEM-768", None),
        "2.16.840.1.101.3.4.4.3" => plain("ML-KEM-1024", None),
        "2.16.840.1.101.3.4.3.17" => plain("ML-DSA-44", None),
        "2.16.840.1.101.3.4.3.18" => plain("ML-DSA-65", None),
        "2.16.840.1.101.3.4.3.19" => plain("ML-DSA-87", None),
        other if is_slh_dsa(other) => plain("SLH-DSA", None),
        other => return Err(other.to_string()),
    })
}

/// SLH-DSA has 12 parameter sets. Their last OID numbers are 20 to 31.
pub fn is_slh_dsa(oid: &str) -> bool {
    oid.strip_prefix("2.16.840.1.101.3.4.3.")
        .and_then(|last| last.parse::<u8>().ok())
        .is_some_and(|last| (20..=31).contains(&last))
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

/// Read the facts of one certificate. The `position` is the place in the file.
///
/// The data can have bytes after the certificate, for example OpenSSL trust data.
/// The hash covers the certificate only.
pub fn parse_certificate(der: &[u8], position: usize) -> Result<CertInfo, CertError> {
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

/// Clean a name from a certificate and cut it if it is too long.
fn limit(text: String) -> String {
    crate::text::clean(&text)
        .chars()
        .take(MAX_NAME_CHARS)
        .collect()
}

fn to_utc(seconds: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(seconds, 0).unwrap_or_default()
}

pub fn sha256_hex(data: &[u8]) -> String {
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
            (usage.code_signing, crate::classify::EKU_CODE_SIGNING),
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
    let rsa = RSAPublicKey::from_der(&spki.subject_public_key.data).ok();
    let dsa = match spki.parsed() {
        Ok(PublicKey::DSA(y)) => Some(y),
        _ => None,
    };
    let parts = Parts {
        curve_oid: spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|parameters| parameters.as_oid().ok())
            .map(|oid| oid.to_id_string()),
        rsa_modulus: rsa.as_ref().map(|(_, key)| key.modulus),
        dsa_number: dsa,
    };
    from_oid(&oid, &parts).map_err(CertError::UnknownKey)
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
