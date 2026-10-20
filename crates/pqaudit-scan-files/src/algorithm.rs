//! Map the algorithm identifier of a key to the name that the rules pack uses.
//!
//! Certificates, PEM keys, and SSH keys share this code.

use pqaudit_core::Algorithm;

use crate::der::bit_length;

/// Facts that depend on the algorithm, from the key or from its parameters.
#[derive(Default)]
pub(crate) struct Parts<'a> {
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
pub(crate) fn elliptic(name: &str, curve_oid: Option<String>) -> Algorithm {
    let known = curve_oid.as_deref().and_then(known_curve);
    Algorithm {
        name: name.to_string(),
        key_bits: known.map(|(_, bits)| bits),
        curve: known.map(|(curve, _)| curve.to_string()).or(curve_oid),
    }
}

/// Make the algorithm of a key from its OID. Return the OID text if the OID is not known.
pub(crate) fn from_oid(oid: &str, parts: &Parts<'_>) -> Result<Algorithm, String> {
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
pub(crate) fn is_slh_dsa(oid: &str) -> bool {
    oid.strip_prefix("2.16.840.1.101.3.4.3.")
        .and_then(|last| last.parse::<u8>().ok())
        .is_some_and(|last| (20..=31).contains(&last))
}
