//! Read OpenPGP keys from exported key files.
//!
//! The code reads binary packets and armored text. It supports version 4 keys.
//! This format is the output of `gpg --export` and the old `pubring.gpg` file.
//! The code does not read the newer key box (`.kbx`) format.
//!
//! The code reads the public part of each key packet: the algorithm and the public numbers.
//! A secret key packet holds the public part first. The code does not read the rest.
//! The fingerprint is the SHA-1 hash that OpenPGP defines for version 4 keys.
//! It is an identifier and not a security function here.

use pqaudit_core::{Algorithm, KeyKind};
use sha1::Sha1;
use sha2::Digest;

use crate::algorithm::{self, Parts};
use crate::der;
use crate::keys::{FoundKey, KeyProblem};
use crate::messages;
use crate::pem::{self, BlockKind};

/// The packet tag of a secret key.
const TAG_SECRET_KEY: u8 = 5;
/// The packet tag of a public key.
const TAG_PUBLIC_KEY: u8 = 6;
/// The packet tag of a secret subkey.
const TAG_SECRET_SUBKEY: u8 = 7;
/// The packet tag of a user ID.
const TAG_USER_ID: u8 = 13;
/// The packet tag of a public subkey.
const TAG_PUBLIC_SUBKEY: u8 = 14;
/// The OID of the Ed25519 curve in the old OpenPGP format. These are content bytes.
const CURVE_ED25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01];
/// The OID of the Curve25519 curve in the old OpenPGP format. These are content bytes.
const CURVE_X25519: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

/// The result of the read of OpenPGP data.
#[derive(Debug, Default)]
pub struct PgpScan {
    /// The keys: primary keys and subkeys.
    pub found: Vec<FoundKey>,
    /// The number of packets or armor blocks that the tool could not read.
    pub bad: usize,
    /// The number of key packets and bad parts.
    pub total: usize,
    /// The reason for the first bad part.
    pub first_problem: Option<KeyProblem>,
}

impl PgpScan {
    fn problem(&mut self, problem: KeyProblem) {
        self.bad += 1;
        self.total += 1;
        self.first_problem.get_or_insert(problem);
    }
}

/// Return true if the data has the start line of an OpenPGP armor block.
pub fn is_armored(data: &[u8]) -> bool {
    pem::has_kind(data, BlockKind::Pgp)
}

/// Read the header of a packet. Return the tag, the length of the body, and the header length.
///
/// The code does not read the partial length form.
fn header(data: &[u8]) -> Option<(u8, usize, usize)> {
    let first = *data.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    if first & 0x40 != 0 {
        let tag = first & 0x3f;
        let second = usize::from(*data.get(1)?);
        match second {
            0..=191 => Some((tag, second, 2)),
            192..=223 => {
                let third = usize::from(*data.get(2)?);
                Some((tag, ((second - 192) << 8) + third + 192, 3))
            }
            255 => {
                let bytes = data.get(2..6)?;
                let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some((tag, usize::try_from(length).ok()?, 6))
            }
            _ => None,
        }
    } else {
        let tag = (first >> 2) & 0x0f;
        match first & 3 {
            0 => Some((tag, usize::from(*data.get(1)?), 2)),
            1 => {
                let bytes = data.get(1..3)?;
                Some((
                    tag,
                    usize::from(u16::from_be_bytes([bytes[0], bytes[1]])),
                    3,
                ))
            }
            2 => {
                let bytes = data.get(1..5)?;
                let length = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                Some((tag, usize::try_from(length).ok()?, 5))
            }
            // The packet goes to the end of the data.
            _ => Some((tag, data.len() - 1, 1)),
        }
    }
}

/// Return true if the start of a file looks like binary OpenPGP key packets.
///
/// The first packet must be a key packet (tag 5, 6, 7, or 14) of version 2 to 6.
/// The reader reports a version or an algorithm that it does not read.
/// If `strict` is true, the algorithm must be one that OpenPGP defines.
/// A caller sets `strict` for files with no key-like name, to avoid false matches.
pub fn looks_like_packets(head: &[u8], strict: bool) -> bool {
    let Some((tag, length, header_length)) = header(head) else {
        return false;
    };
    if !matches!(
        tag,
        TAG_PUBLIC_KEY | TAG_SECRET_KEY | TAG_PUBLIC_SUBKEY | TAG_SECRET_SUBKEY
    ) || length < 6
    {
        return false;
    }
    let Some(&version) = head.get(header_length) else {
        return false;
    };
    if !(2..=6).contains(&version) {
        return false;
    }
    if !strict {
        return true;
    }
    // Versions 2 and 3 have a validity period of 2 bytes before the algorithm.
    let algorithm_at = if version < 4 { 7 } else { 5 };
    matches!(
        head.get(header_length + algorithm_at),
        Some(1..=3 | 16..=22 | 25..=28)
    )
}

/// A reader of the fields of a public key packet.
struct Fields<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Fields<'a> {
    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.position.checked_add(count)?;
        let bytes = self.data.get(self.position..end)?;
        self.position = end;
        Some(bytes)
    }

    /// Read a multi-precision integer. Return its bytes.
    fn mpi(&mut self) -> Option<&'a [u8]> {
        let bits = self.take(2)?;
        let bits = usize::from(u16::from_be_bytes([bits[0], bits[1]]));
        self.take(bits.div_ceil(8))
    }

    /// Read a curve OID with its length byte. Return the content bytes.
    fn curve(&mut self) -> Option<&'a [u8]> {
        let length = usize::from(*self.take(1)?.first()?);
        if length == 0 || length == 0xff {
            return None;
        }
        self.take(length)
    }
}

/// Read a version 4 key packet. The body of a secret key packet starts with the public part.
fn parse_key(body: &[u8], secret: bool) -> Result<FoundKey, KeyProblem> {
    if body.first() != Some(&4) {
        return Err(KeyProblem::Unsupported);
    }
    let mut fields = Fields {
        data: body,
        position: 6,
    };
    let algorithm_id = *body.get(5).ok_or(KeyProblem::Invalid)?;
    let invalid = || KeyProblem::Invalid;
    let algorithm = match algorithm_id {
        1..=3 => {
            let modulus = fields.mpi().ok_or_else(invalid)?;
            fields.mpi().ok_or_else(invalid)?;
            from_oid(
                "1.2.840.113549.1.1.1",
                &Parts {
                    rsa_modulus: Some(modulus),
                    ..Parts::default()
                },
            )?
        }
        // Elgamal. The tool treats it as finite-field Diffie-Hellman.
        16 => {
            let prime = fields.mpi().ok_or_else(invalid)?;
            fields.mpi().ok_or_else(invalid)?;
            fields.mpi().ok_or_else(invalid)?;
            Algorithm {
                name: "DH".to_string(),
                key_bits: der::bit_length(prime),
                curve: None,
            }
        }
        17 => {
            let prime = fields.mpi().ok_or_else(invalid)?;
            for _ in 0..3 {
                fields.mpi().ok_or_else(invalid)?;
            }
            from_oid(
                "1.2.840.10040.4.1",
                &Parts {
                    dsa_number: Some(prime),
                    ..Parts::default()
                },
            )?
        }
        18 => {
            let curve = fields.curve().ok_or_else(invalid)?;
            fields.mpi().ok_or_else(invalid)?;
            let kdf = usize::from(fields.take(1).ok_or_else(invalid)?[0]);
            fields.take(kdf).ok_or_else(invalid)?;
            if curve == CURVE_X25519 {
                from_oid("1.3.101.110", &Parts::default())?
            } else {
                algorithm::elliptic("ECDH", der::oid_text(curve))
            }
        }
        19 => {
            let curve = fields.curve().ok_or_else(invalid)?;
            fields.mpi().ok_or_else(invalid)?;
            algorithm::elliptic("ECDSA", der::oid_text(curve))
        }
        22 => {
            let curve = fields.curve().ok_or_else(invalid)?;
            fields.mpi().ok_or_else(invalid)?;
            if curve != CURVE_ED25519 {
                return Err(KeyProblem::Unsupported);
            }
            from_oid("1.3.101.112", &Parts::default())?
        }
        25 => {
            fields.take(32).ok_or_else(invalid)?;
            from_oid("1.3.101.110", &Parts::default())?
        }
        26 => {
            fields.take(56).ok_or_else(invalid)?;
            from_oid("1.3.101.111", &Parts::default())?
        }
        27 => {
            fields.take(32).ok_or_else(invalid)?;
            from_oid("1.3.101.112", &Parts::default())?
        }
        28 => {
            fields.take(57).ok_or_else(invalid)?;
            from_oid("1.3.101.113", &Parts::default())?
        }
        _ => return Err(KeyProblem::Unsupported),
    };
    // The public part ends here. A secret key packet has more bytes. The code ignores them.
    let public = &body[..fields.position];
    let length = u16::try_from(public.len()).map_err(|_| KeyProblem::Invalid)?;
    let mut prefix = vec![0x99];
    prefix.extend_from_slice(&length.to_be_bytes());
    prefix.extend_from_slice(public);

    let fingerprint = hex(&Sha1::digest(&prefix));
    let mut key = FoundKey::public(
        &prefix,
        KeyKind::Pgp,
        algorithm,
        None,
        if secret {
            messages::EVIDENCE_PGP_SECRET
        } else {
            messages::EVIDENCE_PGP_PUBLIC
        },
    );
    key.id = fingerprint;
    Ok(key)
}

fn from_oid(oid: &str, parts: &Parts<'_>) -> Result<Algorithm, KeyProblem> {
    algorithm::from_oid(oid, parts).map_err(KeyProblem::UnknownAlgorithm)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

/// Read binary OpenPGP packets and add the keys to the result.
fn scan_packets(data: &[u8], scan: &mut PgpScan) {
    let mut rest = data;
    // The index of the last primary key. A user ID that follows it names the key.
    let mut primary: Option<usize> = None;
    while !rest.is_empty() {
        let Some((tag, length, header_length)) = header(rest) else {
            scan.problem(KeyProblem::Invalid);
            return;
        };
        let Some(body) = rest.get(header_length..header_length.saturating_add(length)) else {
            scan.problem(KeyProblem::Invalid);
            return;
        };
        match tag {
            TAG_PUBLIC_KEY | TAG_SECRET_KEY | TAG_PUBLIC_SUBKEY | TAG_SECRET_SUBKEY => {
                scan.total += 1;
                let secret = matches!(tag, TAG_SECRET_KEY | TAG_SECRET_SUBKEY);
                match parse_key(body, secret) {
                    Ok(key) => {
                        scan.found.push(key);
                        if matches!(tag, TAG_PUBLIC_KEY | TAG_SECRET_KEY) {
                            primary = Some(scan.found.len() - 1);
                        }
                    }
                    Err(problem) => {
                        scan.bad += 1;
                        scan.first_problem.get_or_insert(problem);
                        primary = None;
                    }
                }
            }
            TAG_USER_ID => {
                if let Some(key) = primary.and_then(|index| scan.found.get_mut(index)) {
                    if key.info.comment.is_none() {
                        key.info.comment = Some(crate::keys::limit_comment(
                            String::from_utf8_lossy(body).into_owned(),
                        ));
                    }
                }
            }
            _ => {}
        }
        rest = &rest[header_length + length..];
    }
}

/// Read binary OpenPGP packets.
pub fn scan_binary(data: &[u8]) -> PgpScan {
    let mut scan = PgpScan::default();
    scan_packets(data, &mut scan);
    scan
}

/// Read the armor blocks of a text. Each block holds binary packets in base64.
pub fn scan_armored(data: &[u8]) -> PgpScan {
    let mut scan = PgpScan::default();
    let blocks = pem::blocks(data);
    for block in blocks.blocks.iter().filter(|b| b.kind == BlockKind::Pgp) {
        match pem::decode(block.body, true) {
            Some(packets) => scan_packets(&packets, &mut scan),
            None => scan.problem(KeyProblem::Invalid),
        }
    }
    if blocks.unclosed == Some(BlockKind::Pgp) {
        scan.problem(KeyProblem::Invalid);
    }
    scan
}
