//! Read the algorithm and the size of a key in a PEM block.
//!
//! The code reads these labels: `PRIVATE KEY` (PKCS#8), `RSA PRIVATE KEY` (PKCS#1),
//! `EC PRIVATE KEY` (SEC1), `ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`,
//! `PUBLIC KEY`, and `RSA PUBLIC KEY`.
//!
//! The rule for a private key: read the algorithm identifier and the public key size.
//! Read the public key too, if the file has it. Read nothing else.
//! The code reads the header of each other field to skip it. It never reads the bytes.
//!
//! The buffers with decoded data wipe themselves on drop.
//! An error never holds bytes from the file.
//! The code does not decrypt a key.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pqaudit_core::KeyKind;
use zeroize::Zeroizing;

use crate::algorithm::{self, Parts};
use crate::der::{self, Tlv, BIT_STRING, INTEGER, NULL, OCTET_STRING, OID, SEQUENCE};
use crate::derive;
use crate::keys::{FoundKey, KeyProblem};
use crate::messages;
use crate::pem::{self, Block};
use crate::ssh;

/// The OID of an RSA key.
const OID_RSA: &str = "1.2.840.113549.1.1.1";
/// The OID of an RSA-PSS key.
const OID_RSA_PSS: &str = "1.2.840.113549.1.1.10";
/// The OID of an elliptic curve key.
const OID_EC: &str = "1.2.840.10045.2.1";
/// The content bytes of the OID of an elliptic curve key.
const OID_EC_BYTES: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
/// The content bytes of the OID of an RSA key.
const OID_RSA_BYTES: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// The context tag of the curve in an SEC1 key.
const SEC1_PARAMETERS: u8 = 0xa0;
/// The context tag of the public key in an SEC1 key.
const SEC1_PUBLIC: u8 = 0xa1;

/// Return true if the tool reads blocks with this label.
pub fn is_key_label(label: &[u8]) -> bool {
    matches!(
        label,
        b"PRIVATE KEY"
            | b"RSA PRIVATE KEY"
            | b"EC PRIVATE KEY"
            | b"ENCRYPTED PRIVATE KEY"
            | b"OPENSSH PRIVATE KEY"
            | b"PUBLIC KEY"
            | b"RSA PUBLIC KEY"
    )
}

/// Read one key block. The `place` names the file and the block. It is for hashes only.
pub fn parse_block(block: &Block<'_>, place: &str) -> Result<FoundKey, KeyProblem> {
    let found = match block.label {
        b"ENCRYPTED PRIVATE KEY" => encrypted(block),
        b"RSA PRIVATE KEY" | b"EC PRIVATE KEY" if pem::has_encryption_header(block.body) => {
            encrypted(block)
        }
        label => {
            let bytes = pem::decode(block.body, false).ok_or(KeyProblem::Invalid)?;
            match label {
                b"PRIVATE KEY" => pkcs8(&bytes, place)?,
                b"RSA PRIVATE KEY" => pkcs1_private(&bytes)?,
                b"EC PRIVATE KEY" => sec1(&bytes)?,
                b"OPENSSH PRIVATE KEY" => ssh::from_openssh_private(&bytes)?,
                b"PUBLIC KEY" => spki(&bytes)?,
                b"RSA PUBLIC KEY" => pkcs1_public(&bytes)?,
                _ => return Err(KeyProblem::Unsupported),
            }
        }
    };
    Ok(found.at_line(block.line))
}

/// Read one key from DER bytes. The `place` names the file. It is for hashes only.
///
/// The code tries these forms in order: SPKI, PKCS#8, encrypted PKCS#8, PKCS#1 private,
/// SEC1, and PKCS#1 public. A form with a known structure and a bad content gives its own error.
/// If no form fits, the error is `Invalid`.
pub fn parse_der(data: &[u8], place: &str) -> Result<FoundKey, KeyProblem> {
    parse_der_forms(data, place, true)
}

/// Return true if the bytes are one whole key in DER form. The bytes come from a file with no key name.
///
/// This test is stricter than `parse_der`. It does not accept a PKCS#1 public key, because a
/// signature has the same shape. The key must fill all the bytes, unless the bytes are a cut head.
pub fn is_whole_der_key(head: &[u8], head_is_cut: bool) -> bool {
    let Some((outer, rest)) = der::read_tag(head, SEQUENCE) else {
        return false;
    };
    (head_is_cut || rest.is_empty())
        && outer.whole.len() == head.len() - rest.len()
        && parse_der_forms(outer.whole, "", false)
            .is_ok_and(|key| key.info.algorithm.is_some_and(plausible_algorithm))
}

/// Return true if a file with no key name can hold a key of this algorithm.
///
/// An RSA key of less than 512 bits is real, but a file with no key name is more likely not a key.
fn plausible_algorithm(algorithm: pqaudit_core::Algorithm) -> bool {
    algorithm.name != "RSA" || algorithm.key_bits.is_some_and(|bits| bits >= 512)
}

/// Try the DER forms in order. The flag says if the tool tries a PKCS#1 public key.
fn parse_der_forms(
    data: &[u8],
    place: &str,
    pkcs1_public_allowed: bool,
) -> Result<FoundKey, KeyProblem> {
    let results = [
        spki(data),
        pkcs8(data, place),
        encrypted_der(data),
        pkcs1_private(data),
        sec1(data),
        if pkcs1_public_allowed {
            pkcs1_public(data)
        } else {
            Err(KeyProblem::Invalid)
        },
    ];
    results
        .into_iter()
        .find(|result| !matches!(result, Err(KeyProblem::Invalid)))
        .unwrap_or(Err(KeyProblem::Invalid))
}

/// Read an encrypted PKCS#8 key in DER form. The code does not read the encrypted bytes.
///
/// The ID is the hash of the base64 text, the same as for the PEM form of the key.
fn encrypted_der(data: &[u8]) -> Result<FoundKey, KeyProblem> {
    let invalid = || KeyProblem::Invalid;
    let (outer, after_outer) = der::read_tag(data, SEQUENCE).ok_or_else(invalid)?;
    let (id, rest) = der::read_tag(outer.content, SEQUENCE).ok_or_else(invalid)?;
    algorithm_id(id).ok_or_else(invalid)?;
    let (_, after_key) = der::read_tag(rest, OCTET_STRING).ok_or_else(invalid)?;
    if !after_key.is_empty() || !after_outer.is_empty() {
        return Err(invalid());
    }
    let text = Zeroizing::new(STANDARD.encode(data).into_bytes());
    Ok(FoundKey::encrypted(&text))
}

/// Make the item for an encrypted key. The code does not decode the text.
fn encrypted(block: &Block<'_>) -> FoundKey {
    FoundKey::encrypted(&pem::base64_text(block.body, false))
}

/// The algorithm identifier of a key.
struct AlgorithmId<'a> {
    /// The OID text.
    oid: String,
    /// The parameters, if there are any.
    parameters: Option<Tlv<'a>>,
    /// The whole identifier. It is public data.
    whole: &'a [u8],
}

fn algorithm_id(tlv: Tlv<'_>) -> Option<AlgorithmId<'_>> {
    if tlv.tag != SEQUENCE {
        return None;
    }
    let (oid, rest) = der::read_tag(tlv.content, OID)?;
    let parameters = der::read(rest).map(|(parameters, _)| parameters);
    Some(AlgorithmId {
        oid: der::oid_text(oid.content)?,
        parameters,
        whole: tlv.whole,
    })
}

impl AlgorithmId<'_> {
    /// The OID of the curve, if the parameters are an OID.
    fn curve(&self) -> Option<String> {
        self.parameters
            .filter(|parameters| parameters.tag == OID)
            .and_then(|parameters| der::oid_text(parameters.content))
    }

    /// The first number of the parameters, if they are a sequence. For DSA this is `p`.
    fn first_number(&self) -> Option<&[u8]> {
        let parameters = self.parameters.filter(|p| p.tag == SEQUENCE)?;
        der::read_tag(parameters.content, INTEGER).map(|(number, _)| number.content)
    }
}

/// Read `n` and `e` of an RSA key. A private key has a version number before them.
fn rsa_numbers(sequence: &[u8], private: bool) -> Option<(Tlv<'_>, Tlv<'_>)> {
    let (outer, _) = der::read_tag(sequence, SEQUENCE)?;
    let mut rest = outer.content;
    if private {
        rest = der::read_tag(rest, INTEGER)?.1;
    }
    let (n, rest) = der::read_tag(rest, INTEGER)?;
    let (e, _) = der::read_tag(rest, INTEGER)?;
    plausible_exponent(e.content).then_some((n, e))
}

/// Return true if the number can be an RSA public exponent: 1 to 4 bytes, odd, and 3 or more.
///
/// A signature has the same shape as an RSA public key. Its second number is big.
fn plausible_exponent(exponent: &[u8]) -> bool {
    let start = exponent.iter().take_while(|byte| **byte == 0).count();
    let exponent = &exponent[start..];
    (1..=4).contains(&exponent.len())
        && exponent.last().is_some_and(|byte| byte & 1 == 1)
        && exponent != [1]
}

/// Make the SPKI bytes of a public key.
fn make_spki(algorithm_id: &[u8], public_bit_string_content: &[u8]) -> Vec<u8> {
    let mut content = algorithm_id.to_vec();
    content.extend_from_slice(&der::write(BIT_STRING, public_bit_string_content));
    der::write(SEQUENCE, &content)
}

/// Make the SPKI bytes of an RSA key from `n` and `e`.
fn rsa_spki(algorithm_id: &[u8], n: Tlv<'_>, e: Tlv<'_>) -> Vec<u8> {
    let mut numbers = n.whole.to_vec();
    numbers.extend_from_slice(e.whole);
    let mut bits = vec![0u8];
    bits.extend_from_slice(&der::write(SEQUENCE, &numbers));
    make_spki(algorithm_id, &bits)
}

fn unknown(oid: String) -> KeyProblem {
    KeyProblem::UnknownAlgorithm(oid)
}

/// Read an unencrypted PKCS#8 private key.
fn pkcs8(data: &[u8], place: &str) -> Result<FoundKey, KeyProblem> {
    let invalid = || KeyProblem::Invalid;
    let (outer, _) = der::read_tag(data, SEQUENCE).ok_or_else(invalid)?;
    let (_version, rest) = der::read_tag(outer.content, INTEGER).ok_or_else(invalid)?;
    let (id, rest) = der::read_tag(rest, SEQUENCE).ok_or_else(invalid)?;
    let id = algorithm_id(id).ok_or_else(invalid)?;
    // The header of the key field. The code does not read the content of a key it cannot use.
    let (key_field, after_key) = der::read_tag(rest, OCTET_STRING).ok_or_else(invalid)?;

    let mut parts = Parts {
        curve_oid: id.curve(),
        dsa_number: id.first_number(),
        ..Parts::default()
    };
    let mut public_spki = None;
    match id.oid.as_str() {
        OID_RSA | OID_RSA_PSS => {
            let (n, e) = rsa_numbers(key_field.content, true).ok_or_else(invalid)?;
            parts.rsa_modulus = Some(n.content);
            if id.oid == OID_RSA {
                public_spki = Some(rsa_spki(id.whole, n, e));
            }
        }
        OID_EC => {
            public_spki =
                sec1_public(key_field.content).map(|point| make_spki_from_bits(id.whole, point));
        }
        // The public key of a version 2 key (RFC 5958) is in the field [1].
        _ => {
            public_spki = embedded_public(after_key)
                .or_else(|| derived_public(&id.oid, key_field.content))
                .map(|public| make_spki(id.whole, &public));
        }
    }
    let algorithm = algorithm::from_oid(&id.oid, &parts).map_err(unknown)?;
    Ok(match public_spki {
        Some(spki) => FoundKey::public(
            &spki,
            KeyKind::Pkcs8Private,
            algorithm,
            None,
            messages::EVIDENCE_PRIVATE_KEY,
        ),
        None => FoundKey::private_without_public(algorithm, place),
    })
}

/// The context tag of the public key in a version 2 PKCS#8 key.
const PKCS8_PUBLIC: u8 = 0x81;
/// The context tag of a seed in a post-quantum PKCS#8 key.
const PQ_SEED: u8 = 0x80;

/// Find the public key in the fields after the private key of a PKCS#8 key.
///
/// Return the BIT STRING content: the unused-bits byte and the key.
fn embedded_public(mut fields: &[u8]) -> Option<Vec<u8>> {
    while let Some((field, next)) = der::read(fields) {
        if field.tag == PKCS8_PUBLIC {
            return Some(field.content.to_vec());
        }
        fields = next;
    }
    None
}

/// Find the seed in the private key field of a post-quantum key.
///
/// The field is a seed `[0]`, an expanded key, or a sequence with both.
/// Return the seed and the expanded key. Each can be missing.
fn pq_fields(field: &[u8]) -> (Option<&[u8]>, Option<&[u8]>) {
    match der::read(field) {
        Some((tlv, _)) if tlv.tag == PQ_SEED => (Some(tlv.content), None),
        Some((tlv, _)) if tlv.tag == OCTET_STRING => (None, Some(tlv.content)),
        Some((tlv, _)) if tlv.tag == SEQUENCE => {
            let seed = der::read_tag(tlv.content, OCTET_STRING);
            match seed {
                Some((seed, rest)) => (
                    Some(seed.content),
                    der::read_tag(rest, OCTET_STRING).map(|(expanded, _)| expanded.content),
                ),
                None => (None, None),
            }
        }
        _ => (None, None),
    }
}

/// Compute the public key of a key that has a seed. Return the BIT STRING content.
///
/// The seed stays in the buffer of the caller. The result is public.
fn derived_public(oid: &str, key_field: &[u8]) -> Option<Vec<u8>> {
    let public = match oid {
        "1.3.101.112" => {
            let (seed, _) = der::read_tag(key_field, OCTET_STRING)?;
            derive::ed25519(seed.content)?
        }
        "1.3.101.110" => {
            let (seed, _) = der::read_tag(key_field, OCTET_STRING)?;
            derive::x25519(seed.content)?
        }
        "2.16.840.1.101.3.4.4.1" | "2.16.840.1.101.3.4.4.2" | "2.16.840.1.101.3.4.4.3" => {
            let level = match oid {
                "2.16.840.1.101.3.4.4.1" => 512,
                "2.16.840.1.101.3.4.4.2" => 768,
                _ => 1024,
            };
            let (seed, expanded) = pq_fields(key_field);
            match (seed, expanded) {
                (Some(seed), _) => derive::ml_kem(level, seed)?,
                // The expanded key holds the public key after the secret vector.
                (None, Some(expanded)) => {
                    let k = level / 256;
                    let start = usize::from(384 * k);
                    let end = start + usize::from(384 * k + 32);
                    if expanded.len() != usize::from(768 * k + 96) {
                        return None;
                    }
                    expanded.get(start..end)?.to_vec()
                }
                _ => return None,
            }
        }
        "2.16.840.1.101.3.4.3.17" | "2.16.840.1.101.3.4.3.18" | "2.16.840.1.101.3.4.3.19" => {
            let level = match oid {
                "2.16.840.1.101.3.4.3.17" => 44,
                "2.16.840.1.101.3.4.3.18" => 65,
                _ => 87,
            };
            // An expanded ML-DSA key does not hold the public key. The library function that
            // makes a key from the expanded form is on the deprecation list of the library.
            // Its documentation says that it can panic on a bad key. The tool does not call it. Such a key gets a place fingerprint.
            let (seed, _) = pq_fields(key_field);
            derive::ml_dsa(level, seed?)?
        }
        _ => return None,
    };
    let mut bits = vec![0u8];
    bits.extend_from_slice(&public);
    Some(bits)
}

/// Make the SPKI bytes from a BIT STRING element.
fn make_spki_from_bits(algorithm_id: &[u8], bit_string: Tlv<'_>) -> Vec<u8> {
    make_spki(algorithm_id, bit_string.content)
}

/// Find the public key in an SEC1 private key. Return the BIT STRING element.
///
/// The code skips the private scalar. It reads the header only.
fn sec1_public(data: &[u8]) -> Option<Tlv<'_>> {
    let (outer, _) = der::read_tag(data, SEQUENCE)?;
    let (_version, rest) = der::read_tag(outer.content, INTEGER)?;
    let (_scalar, mut rest) = der::read_tag(rest, OCTET_STRING)?;
    while let Some((field, next)) = der::read(rest) {
        if field.tag == SEC1_PUBLIC {
            return der::read_tag(field.content, BIT_STRING).map(|(bits, _)| bits);
        }
        rest = next;
    }
    None
}

/// Find the curve OID in an SEC1 private key.
fn sec1_curve(data: &[u8]) -> Option<String> {
    let (outer, _) = der::read_tag(data, SEQUENCE)?;
    let (_version, rest) = der::read_tag(outer.content, INTEGER)?;
    let (_scalar, mut rest) = der::read_tag(rest, OCTET_STRING)?;
    while let Some((field, next)) = der::read(rest) {
        if field.tag == SEC1_PARAMETERS {
            let (oid, _) = der::read_tag(field.content, OID)?;
            return der::oid_text(oid.content);
        }
        rest = next;
    }
    None
}

/// Read an unencrypted SEC1 `EC PRIVATE KEY`.
fn sec1(data: &[u8]) -> Result<FoundKey, KeyProblem> {
    let curve = sec1_curve(data).ok_or(KeyProblem::Invalid)?;
    let point = sec1_public(data).ok_or(KeyProblem::Invalid)?;
    let parts = Parts {
        curve_oid: Some(curve.clone()),
        ..Parts::default()
    };
    let algorithm = algorithm::from_oid(OID_EC, &parts).map_err(unknown)?;
    // The identifier that an SPKI of this key has.
    let curve_oid = der::write(OID, &oid_content(&curve).ok_or(KeyProblem::Invalid)?);
    let mut id = der::write(OID, &OID_EC_BYTES);
    id.extend_from_slice(&curve_oid);
    let id = der::write(SEQUENCE, &id);
    Ok(FoundKey::public(
        &make_spki_from_bits(&id, point),
        KeyKind::Pkcs8Private,
        algorithm,
        None,
        messages::EVIDENCE_PRIVATE_KEY,
    ))
}

/// Write the content bytes of an OID from its text.
fn oid_content(text: &str) -> Option<Vec<u8>> {
    let mut numbers = text.split('.').map(|part| part.parse::<u64>().ok());
    let first = numbers.next()??;
    let second = numbers.next()??;
    let mut out = vec![u8::try_from(first * 40 + second).ok()?];
    for number in numbers {
        let number = number?;
        let mut groups = vec![(number & 0x7f) as u8];
        let mut rest = number >> 7;
        while rest > 0 {
            groups.push((rest & 0x7f) as u8 | 0x80);
            rest >>= 7;
        }
        out.extend(groups.iter().rev());
    }
    Some(out)
}

/// The algorithm identifier of an RSA key: the OID and a NULL.
fn rsa_algorithm_id() -> Vec<u8> {
    let mut id = der::write(OID, &OID_RSA_BYTES);
    id.extend_from_slice(&der::write(NULL, &[]));
    der::write(SEQUENCE, &id)
}

/// Read an unencrypted PKCS#1 `RSA PRIVATE KEY`.
fn pkcs1_private(data: &[u8]) -> Result<FoundKey, KeyProblem> {
    let (n, e) = rsa_numbers(data, true).ok_or(KeyProblem::Invalid)?;
    let parts = Parts {
        rsa_modulus: Some(n.content),
        ..Parts::default()
    };
    let algorithm = algorithm::from_oid(OID_RSA, &parts).map_err(unknown)?;
    Ok(FoundKey::public(
        &rsa_spki(&rsa_algorithm_id(), n, e),
        KeyKind::Pkcs8Private,
        algorithm,
        None,
        messages::EVIDENCE_PRIVATE_KEY,
    ))
}

/// Read a PKCS#1 `RSA PUBLIC KEY`.
fn pkcs1_public(data: &[u8]) -> Result<FoundKey, KeyProblem> {
    let (n, e) = rsa_numbers(data, false).ok_or(KeyProblem::Invalid)?;
    let parts = Parts {
        rsa_modulus: Some(n.content),
        ..Parts::default()
    };
    let algorithm = algorithm::from_oid(OID_RSA, &parts).map_err(unknown)?;
    Ok(FoundKey::public(
        &rsa_spki(&rsa_algorithm_id(), n, e),
        KeyKind::X509Spki,
        algorithm,
        None,
        messages::EVIDENCE_PUBLIC_KEY,
    ))
}

/// Read a `PUBLIC KEY` block: a SubjectPublicKeyInfo.
fn spki(data: &[u8]) -> Result<FoundKey, KeyProblem> {
    let invalid = || KeyProblem::Invalid;
    let (outer, _) = der::read_tag(data, SEQUENCE).ok_or_else(invalid)?;
    let (id, rest) = der::read_tag(outer.content, SEQUENCE).ok_or_else(invalid)?;
    let id = algorithm_id(id).ok_or_else(invalid)?;
    let (bits, _) = der::read_tag(rest, BIT_STRING).ok_or_else(invalid)?;
    let mut parts = Parts {
        curve_oid: id.curve(),
        dsa_number: id.first_number(),
        ..Parts::default()
    };
    if id.oid == OID_RSA || id.oid == OID_RSA_PSS {
        let key = bits.content.get(1..).ok_or_else(invalid)?;
        let (n, _) = rsa_numbers(key, false).ok_or_else(invalid)?;
        parts.rsa_modulus = Some(n.content);
    }
    let algorithm = algorithm::from_oid(&id.oid, &parts).map_err(unknown)?;
    Ok(FoundKey::public(
        outer.whole,
        KeyKind::X509Spki,
        algorithm,
        None,
        messages::EVIDENCE_PUBLIC_KEY,
    ))
}
