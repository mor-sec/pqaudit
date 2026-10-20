//! The facts about one key that a key reader finds, and why a key reader fails.
//!
//! No type in this file holds private key bytes.

use pqaudit_core::{Algorithm, KeyInfo, KeyKind};

use crate::cert::sha256_hex;
use crate::messages;

/// The longest comment that the tool keeps, in characters.
const MAX_COMMENT_CHARS: usize = 256;

/// One key from a file.
#[derive(Debug)]
pub struct FoundKey {
    /// The ID of the key. Two copies of the same key have the same ID.
    ///
    /// It is the hash of a public key, or the OpenPGP version 4 fingerprint in lower case hex.
    /// For a private key with no public part, it is a hash of the place of the key in the file.
    pub id: String,
    /// The facts about the key.
    pub info: KeyInfo,
    /// The note for the place where the tool saw the key.
    pub evidence: &'static str,
    /// The line where the key starts. A binary file has no line.
    pub line: Option<u32>,
}

impl FoundKey {
    /// Make a key with a public part. The ID is the SHA-256 hash of the public key bytes.
    pub fn public(
        public_bytes: &[u8],
        kind: KeyKind,
        algorithm: Algorithm,
        comment: Option<String>,
        evidence: &'static str,
    ) -> Self {
        let hash = sha256_hex(public_bytes);
        Self {
            id: hash.clone(),
            info: KeyInfo {
                fingerprint_sha256: hash,
                kind,
                algorithm: Some(algorithm),
                comment: comment.map(limit_comment),
            },
            evidence,
            line: None,
        }
    }

    /// Make a private key that the tool cannot identify by a public part.
    ///
    /// The ID is a hash of the `place`, never of the key bytes.
    pub fn private_without_public(algorithm: Algorithm, place: &str) -> Self {
        let hash = sha256_hex(format!("private-key:{place}").as_bytes());
        Self {
            id: hash.clone(),
            info: KeyInfo {
                fingerprint_sha256: hash,
                kind: KeyKind::Pkcs8Private,
                algorithm: Some(algorithm),
                comment: None,
            },
            evidence: messages::EVIDENCE_PRIVATE_KEY,
            line: None,
        }
    }

    /// Make an encrypted private key. The ID is the hash of the encrypted text.
    pub fn encrypted(encrypted_text: &[u8]) -> Self {
        let hash = sha256_hex(encrypted_text);
        Self {
            id: hash.clone(),
            info: KeyInfo {
                fingerprint_sha256: hash,
                kind: KeyKind::EncryptedPrivate,
                algorithm: None,
                comment: None,
            },
            evidence: messages::ENCRYPTED_KEY_NOT_INSPECTED,
            line: None,
        }
    }

    /// Set the line.
    pub fn at_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }
}

/// Cut a comment that is too long.
pub fn limit_comment(text: String) -> String {
    if text.chars().count() > MAX_COMMENT_CHARS {
        text.chars().take(MAX_COMMENT_CHARS).collect()
    } else {
        text
    }
}

/// Why the tool cannot read a key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyProblem {
    /// The data is not a valid key.
    Invalid,
    /// The algorithm is not known. The value is the OID text.
    UnknownAlgorithm(String),
    /// The key has a type or a version that the tool does not read.
    Unsupported,
}

impl KeyProblem {
    /// The text for the user. It never holds key bytes.
    ///
    /// The OID text holds digits and dots only.
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid => messages::KEY_DATA_INVALID.to_string(),
            Self::UnknownAlgorithm(oid) => messages::KEY_UNKNOWN_ALGORITHM.replace("{oid}", oid),
            Self::Unsupported => messages::KEY_UNSUPPORTED.to_string(),
        }
    }
}
