//! Read SSH public keys and the public part of OpenSSH private key files.
//!
//! A public key line has this form: `[options] type base64-blob [comment]`.
//! The files `authorized_keys` and `known_hosts` use this form too.
//! A `known_hosts` line has a host field before the type. It can be a hash.
//! The code ignores the host field and the options.
//!
//! An OpenSSH private key file keeps its public key apart from the private part.
//! The code reads the public key only. It never reads the private part.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use pqaudit_core::KeyKind;

use crate::algorithm::{self, Parts};
use crate::keys::{FoundKey, KeyProblem};
use crate::messages;

/// The start of the binary data of an OpenSSH private key file.
const OPENSSH_MAGIC: &[u8] = b"openssh-key-v1\0";
/// The number of tokens on one line that the code looks at.
const MAX_TOKENS: usize = 64;
/// The number of lines at the start of a file that the content check reads.
const SNIFF_LINES: usize = 100;

/// The result of the read of a text with public keys.
#[derive(Debug, Default)]
pub struct SshScan {
    /// The keys.
    pub found: Vec<FoundKey>,
    /// The number of lines that are not valid keys. Comment lines and blank lines do not count.
    pub bad: usize,
    /// The number of lines that are keys or are not valid keys.
    pub total: usize,
    /// The number of the first bad line.
    pub first_bad_line: Option<u32>,
}

/// A reader of the SSH wire format: 4-byte lengths, big-endian.
struct Wire<'a> {
    data: &'a [u8],
}

impl<'a> Wire<'a> {
    fn u32(&mut self) -> Option<u32> {
        let (bytes, rest) = self.data.split_first_chunk::<4>()?;
        self.data = rest;
        Some(u32::from_be_bytes(*bytes))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let length = usize::try_from(self.u32()?).ok()?;
        let (text, rest) = self.data.split_at_checked(length)?;
        self.data = rest;
        Some(text)
    }
}

/// Return the algorithm of an SSH public key blob.
pub fn blob_algorithm(blob: &[u8]) -> Result<pqaudit_core::Algorithm, KeyProblem> {
    let mut wire = Wire { data: blob };
    let kind = wire.string().ok_or(KeyProblem::Invalid)?;
    let invalid = || KeyProblem::Invalid;
    let (oid, parts) = match kind {
        b"ssh-rsa" => {
            let _exponent = wire.string().ok_or_else(invalid)?;
            let modulus = wire.string().ok_or_else(invalid)?;
            (
                "1.2.840.113549.1.1.1",
                Parts {
                    rsa_modulus: Some(modulus),
                    ..Parts::default()
                },
            )
        }
        b"ssh-dss" => {
            let p = wire.string().ok_or_else(invalid)?;
            (
                "1.2.840.10040.4.1",
                Parts {
                    dsa_number: Some(p),
                    ..Parts::default()
                },
            )
        }
        b"ssh-ed25519" | b"sk-ssh-ed25519@openssh.com" => {
            wire.string().ok_or_else(invalid)?;
            ("1.3.101.112", Parts::default())
        }
        b"ecdsa-sha2-nistp256"
        | b"ecdsa-sha2-nistp384"
        | b"ecdsa-sha2-nistp521"
        | b"sk-ecdsa-sha2-nistp256@openssh.com" => {
            let curve = wire.string().ok_or_else(invalid)?;
            wire.string().ok_or_else(invalid)?;
            let curve_oid = match curve {
                b"nistp256" => "1.2.840.10045.3.1.7",
                b"nistp384" => "1.3.132.0.34",
                b"nistp521" => "1.3.132.0.35",
                _ => return Err(KeyProblem::Unsupported),
            };
            (
                "1.2.840.10045.2.1",
                Parts {
                    curve_oid: Some(curve_oid.to_string()),
                    ..Parts::default()
                },
            )
        }
        _ => return Err(KeyProblem::Unsupported),
    };
    algorithm::from_oid(oid, &parts).map_err(KeyProblem::UnknownAlgorithm)
}

/// Make the key from a blob.
fn key_from_blob(
    blob: &[u8],
    comment: Option<String>,
    evidence: &'static str,
) -> Result<FoundKey, KeyProblem> {
    let algorithm = blob_algorithm(blob)?;
    Ok(FoundKey::public(
        blob,
        KeyKind::OpenSsh,
        algorithm,
        comment,
        evidence,
    ))
}

/// Read the public key of an OpenSSH private key file. The argument is the decoded text.
pub fn from_openssh_private(data: &[u8]) -> Result<FoundKey, KeyProblem> {
    let rest = data
        .strip_prefix(OPENSSH_MAGIC)
        .ok_or(KeyProblem::Invalid)?;
    let mut wire = Wire { data: rest };
    let cipher = wire.string().ok_or(KeyProblem::Invalid)?;
    let _kdf = wire.string().ok_or(KeyProblem::Invalid)?;
    let _kdf_options = wire.string().ok_or(KeyProblem::Invalid)?;
    let count = wire.u32().ok_or(KeyProblem::Invalid)?;
    if count == 0 {
        return Err(KeyProblem::Invalid);
    }
    // The first public key. The code stops here and never reads the private part.
    let blob = wire.string().ok_or(KeyProblem::Invalid)?;
    let evidence = if cipher == b"none" {
        messages::EVIDENCE_OPENSSH_PRIVATE
    } else {
        messages::EVIDENCE_OPENSSH_ENCRYPTED
    };
    key_from_blob(blob, None, evidence)
}

/// Split a line into tokens. A quoted part with spaces is one token.
fn tokens(line: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut start = None;
    let mut quoted = false;
    for (index, byte) in line.iter().enumerate() {
        match byte {
            b'"' => {
                quoted = !quoted;
                start.get_or_insert(index);
            }
            b' ' | b'\t' if !quoted => {
                if let Some(begin) = start.take() {
                    out.push(&line[begin..index]);
                    if out.len() >= MAX_TOKENS {
                        return out;
                    }
                }
            }
            _ => {
                start.get_or_insert(index);
            }
        }
    }
    if let Some(begin) = start {
        out.push(&line[begin..]);
    }
    out
}

/// Read one line. Return `None` if the line is blank or a comment.
fn read_line(line: &[u8]) -> Option<Result<FoundKey, KeyProblem>> {
    let line = line.trim_ascii();
    if line.is_empty() || line[0] == b'#' {
        return None;
    }
    let tokens = tokens(line);
    for (index, token) in tokens.iter().enumerate() {
        let Some(encoded) = tokens.get(index + 1) else {
            break;
        };
        // The blob starts with the key type. A host name that looks like a type does not match.
        let Ok(blob) = STANDARD.decode(encoded) else {
            continue;
        };
        let mut wire = Wire { data: &blob };
        if wire.string() != Some(*token) {
            continue;
        }
        let comment = tokens
            .get(index + 2..)
            .filter(|rest| !rest.is_empty())
            .map(|rest| {
                rest.iter()
                    .map(|token| String::from_utf8_lossy(token))
                    .collect::<Vec<_>>()
                    .join(" ")
            });
        return Some(key_from_blob(&blob, comment, messages::EVIDENCE_SSH_PUBLIC));
    }
    Some(Err(KeyProblem::Invalid))
}

/// Read all public key lines of a text.
pub fn scan_text(data: &[u8]) -> SshScan {
    let mut scan = SshScan::default();
    for (index, line) in data.split(|byte| *byte == b'\n').enumerate() {
        let number = u32::try_from(index + 1).unwrap_or(u32::MAX);
        match read_line(line) {
            None => {}
            Some(Ok(key)) => {
                scan.total += 1;
                scan.found.push(key.at_line(number));
            }
            Some(Err(_)) => {
                scan.total += 1;
                scan.bad += 1;
                scan.first_bad_line.get_or_insert(number);
            }
        }
    }
    scan
}

/// Return true if the start of a file has a valid SSH public key line.
pub fn looks_like_keys(head: &[u8]) -> bool {
    head.split(|byte| *byte == b'\n')
        .take(SNIFF_LINES)
        .any(|line| matches!(read_line(line), Some(Ok(_))))
}
