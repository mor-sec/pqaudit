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

use pqaudit_core::KeyKind;

use crate::algorithm::{self, Parts};
use crate::der::{self, Tlv, BIT_STRING, INTEGER, NULL, OCTET_STRING, OID, SEQUENCE};
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
    Some((n, e))
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
    let (key_field, _) = der::read_tag(rest, OCTET_STRING).ok_or_else(invalid)?;

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
        _ => {}
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
