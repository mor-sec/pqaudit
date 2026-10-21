//! Hybrid signatures, the trust list, and the check of pack archives.
//!
//! A hybrid signature is an Ed25519 signature and an ML-DSA-65 signature on the same bytes.
//! The check passes only when both signatures are correct.

use std::collections::HashSet;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::NaiveDate;
use ed25519_dalek::pkcs8::{DecodePublicKey, EncodePublicKey};
use ml_dsa::MlDsa65;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::archive::{read_archive, ArchiveError, ArchiveFile};
use crate::messages;
use crate::pack::{PackError, RulesPack};

/// The format name in a signature file.
pub const SIG_FORMAT: &str = "pqaudit-hybrid-sig/1";

/// The format name in a key rotation statement.
pub const ROTATION_FORMAT: &str = "pqaudit-key-rotation/1";

/// The largest number of key rotations in one archive.
const MAX_ROTATIONS: usize = 16;

/// An error when the program checks a signature, a key, or an archive.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// The signature file is not valid.
    #[error("{}", messages::SIG_FILE_INVALID.replace("{reason}", .0))]
    SigFile(String),
    /// A key is not valid.
    #[error("{}", messages::KEY_INVALID.replace("{reason}", .0))]
    Key(String),
    /// One of the two signatures is not correct.
    #[error("{}", messages::BAD_SIGNATURE.replace("{algorithm}", .0))]
    BadSignature(&'static str),
    /// The signature file names a different key.
    #[error("{}", messages::KEY_MISMATCH.replace("{key}", .0))]
    KeyMismatch(String),
    /// The key is not in the trust list, and no key rotation leads to it.
    #[error("{}", messages::UNKNOWN_KEY.replace("{key}", .0))]
    UnknownKey(String),
    /// The trust list revokes the key.
    #[error("{}", messages::KEY_REVOKED.replace("{key}", .0))]
    Revoked(String),
    /// The archive is not valid.
    #[error("{}", messages::ARCHIVE_INVALID.replace("{reason}", .0))]
    Archive(String),
    /// A key rotation statement is not valid.
    #[error("{}", messages::ROTATION_INVALID.replace("{reason}", .0))]
    Rotation(String),
    /// The pack in the archive is not valid.
    #[error("{}", messages::PACK_INVALID.replace("{reason}", &.0.to_string()))]
    Pack(#[from] PackError),
}

impl From<ArchiveError> for VerifyError {
    fn from(error: ArchiveError) -> Self {
        VerifyError::Archive(error.to_string())
    }
}

/// The content of a `.sig.json` file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigFile {
    /// The format name. It must be [`SIG_FORMAT`].
    pub format: String,
    /// The key ID: the hex SHA-256 of both SPKI DER encodings.
    pub key_id: String,
    /// The Ed25519 signature in Base64.
    pub ed25519: String,
    /// The ML-DSA-65 signature in Base64.
    pub ml_dsa_65: String,
}

impl SigFile {
    /// Read a signature file from JSON bytes.
    pub fn parse(bytes: &[u8]) -> Result<SigFile, VerifyError> {
        serde_json::from_slice(bytes).map_err(|error| VerifyError::SigFile(error.to_string()))
    }

    /// Write the signature file as JSON text.
    pub fn to_json(&self) -> String {
        let mut text = serde_json::to_string_pretty(self)
            .expect("a struct of plain strings always converts to JSON");
        text.push('\n');
        text
    }
}

/// A public key pair: one Ed25519 key and one ML-DSA-65 key.
#[derive(Debug, Clone, PartialEq)]
pub struct HybridPublicKey {
    /// The Ed25519 key.
    pub ed25519: ed25519_dalek::VerifyingKey,
    /// The ML-DSA-65 key.
    pub ml_dsa_65: ml_dsa::VerifyingKey<MlDsa65>,
}

impl HybridPublicKey {
    /// Read the two keys from SPKI DER bytes.
    pub fn from_spki_der(ed25519: &[u8], ml_dsa_65: &[u8]) -> Result<Self, VerifyError> {
        let key_err = |error: &dyn std::fmt::Display| VerifyError::Key(error.to_string());
        Ok(HybridPublicKey {
            ed25519: ed25519_dalek::VerifyingKey::from_public_key_der(ed25519)
                .map_err(|e| key_err(&e))?,
            ml_dsa_65: ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_der(ml_dsa_65)
                .map_err(|e| key_err(&e))?,
        })
    }

    /// Read the two keys from SPKI PEM text.
    pub fn from_spki_pem(ed25519: &str, ml_dsa_65: &str) -> Result<Self, VerifyError> {
        let key_err = |error: &dyn std::fmt::Display| VerifyError::Key(error.to_string());
        Ok(HybridPublicKey {
            ed25519: ed25519_dalek::VerifyingKey::from_public_key_pem(ed25519)
                .map_err(|e| key_err(&e))?,
            ml_dsa_65: ml_dsa::VerifyingKey::<MlDsa65>::from_public_key_pem(ml_dsa_65)
                .map_err(|e| key_err(&e))?,
        })
    }

    /// Return the SPKI DER bytes of the Ed25519 key.
    pub fn ed25519_spki_der(&self) -> Vec<u8> {
        self.ed25519
            .to_public_key_der()
            .map(|der| der.as_bytes().to_vec())
            .expect("a valid Ed25519 public key always encodes to DER")
    }

    /// Return the SPKI DER bytes of the ML-DSA-65 key.
    pub fn ml_dsa_65_spki_der(&self) -> Vec<u8> {
        self.ml_dsa_65
            .to_public_key_der()
            .map(|der| der.as_bytes().to_vec())
            .expect("a valid ML-DSA-65 public key always encodes to DER")
    }

    /// Return the key ID: the hex SHA-256 of the Ed25519 SPKI DER and the ML-DSA-65 SPKI DER.
    pub fn key_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.ed25519_spki_der());
        hasher.update(self.ml_dsa_65_spki_der());
        hex(&hasher.finalize())
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_key_id(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Check both signatures of `sig` on `data`. Both must be correct.
pub fn verify_hybrid(data: &[u8], sig: &SigFile, key: &HybridPublicKey) -> Result<(), VerifyError> {
    if sig.format != SIG_FORMAT {
        return Err(VerifyError::SigFile(format!(
            "the format must be {SIG_FORMAT}"
        )));
    }
    if sig.key_id != key.key_id() {
        return Err(VerifyError::KeyMismatch(sig.key_id.clone()));
    }
    let decode = |name: &str, text: &str| {
        B64.decode(text.as_bytes())
            .map_err(|_| VerifyError::SigFile(format!("the {name} signature is not Base64")))
    };
    let ed_bytes = decode("Ed25519", &sig.ed25519)?;
    let ml_bytes = decode("ML-DSA-65", &sig.ml_dsa_65)?;

    let ed_ok = ed25519_dalek::Signature::from_slice(&ed_bytes)
        .map(|signature| key.ed25519.verify_strict(data, &signature).is_ok())
        .unwrap_or(false);
    let ml_ok = ml_dsa::Signature::<MlDsa65>::try_from(ml_bytes.as_slice())
        .map(|signature| key.ml_dsa_65.verify_with_context(data, b"", &signature))
        .unwrap_or(false);
    // Check both before the function returns an error.
    match (ed_ok, ml_ok) {
        (true, true) => Ok(()),
        (false, _) => Err(VerifyError::BadSignature("Ed25519")),
        (true, false) => Err(VerifyError::BadSignature("ML-DSA-65")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    #[serde(default)]
    key: Vec<TrustKeyEntry>,
    #[serde(default)]
    revoked: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustKeyEntry {
    id: String,
    ed25519_spki_pem: String,
    ml_dsa_65_spki_pem: String,
}

/// The keys that the program trusts, and the revoked keys.
///
/// The list comes from the program, never from a pack.
#[derive(Debug, Clone)]
pub struct TrustStore {
    keys: Vec<HybridPublicKey>,
    revoked: HashSet<String>,
}

/// The trust list that the build puts inside the program.
const BUILTIN_TRUST: &str = include_str!("../../../rules/trust/keys.toml");

impl TrustStore {
    /// Make a trust list from keys and revoked key IDs.
    pub fn new(keys: Vec<HybridPublicKey>, revoked: Vec<String>) -> Self {
        TrustStore {
            keys,
            revoked: revoked.into_iter().collect(),
        }
    }

    /// Read a trust list from TOML text. Each `id` must match its keys.
    pub fn from_toml(text: &str) -> Result<Self, VerifyError> {
        let file: TrustFile =
            toml::from_str(text).map_err(|error| VerifyError::Key(error.to_string()))?;
        let mut keys = Vec::new();
        for entry in file.key {
            let key =
                HybridPublicKey::from_spki_pem(&entry.ed25519_spki_pem, &entry.ml_dsa_65_spki_pem)?;
            if key.key_id() != entry.id {
                return Err(VerifyError::Key(format!(
                    "the key {} has a wrong ID",
                    entry.id
                )));
            }
            keys.push(key);
        }
        if let Some(bad) = file.revoked.iter().find(|id| !is_key_id(id)) {
            return Err(VerifyError::Key(format!("{bad:?} is not a key ID")));
        }
        Ok(TrustStore::new(keys, file.revoked))
    }

    /// Return the trust list of the program.
    ///
    /// # Panics
    /// Panics if the list in the program is wrong. A test finds this error.
    pub fn builtin() -> Self {
        // Only a debug build with the feature can replace the trust list.
        #[cfg(all(feature = "test-trust", debug_assertions))]
        if let Ok(path) = std::env::var("PQAUDIT_TEST_TRUST_FILE") {
            eprintln!("{}", crate::messages::TEST_TRUST_WARNING);
            let text = std::fs::read_to_string(&path).expect("the test trust file is readable");
            return Self::from_toml(&text).expect("the test trust file is valid");
        }
        Self::from_toml(BUILTIN_TRUST).expect("the built-in trust list is valid")
    }

    /// Return the number of trusted keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }

    /// Return true if the key ID is in the trust list.
    pub fn is_trusted(&self, key_id: &str) -> bool {
        self.find(key_id).is_some()
    }

    /// Return true if the trust list revokes the key ID.
    pub fn is_revoked(&self, key_id: &str) -> bool {
        self.revoked.contains(key_id)
    }

    fn find(&self, key_id: &str) -> Option<&HybridPublicKey> {
        self.keys.iter().find(|key| key.key_id() == key_id)
    }
}

/// A pack with a correct signature.
#[derive(Debug, Clone)]
pub struct VerifiedPack {
    /// The pack.
    pub pack: RulesPack,
    /// The ID of the key that signed the archive.
    pub signed_by: String,
    /// The key IDs from the trusted key to the signing key.
    pub rotation_chain: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RotationStatement {
    format: String,
    old_key_id: String,
    new_ed25519_spki: String,
    new_ml_dsa_65_spki: String,
    // The date must parse. The program does not use it.
    #[allow(dead_code)]
    issued: NaiveDate,
}

/// The rotation files of an archive, in order: (statement bytes, signature bytes).
type RotationFiles = Vec<(Vec<u8>, Vec<u8>)>;

/// Split the archive files into pack files and rotation files.
fn split_files(files: Vec<ArchiveFile>) -> Result<(Vec<ArchiveFile>, RotationFiles), VerifyError> {
    let bad = |text: String| VerifyError::Archive(text);
    let mut pack_files = Vec::new();
    let mut statements: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut signatures: Vec<(u32, Vec<u8>)> = Vec::new();
    for (name, bytes) in files {
        if name.starts_with("trust/") {
            return Err(bad(format!("the file {name} is not allowed in a pack")));
        }
        let Some(rest) = name.strip_prefix("rotations/") else {
            pack_files.push((name, bytes));
            continue;
        };
        let (number, is_sig) = match rest.strip_suffix(".json.sig.json") {
            Some(number) => (number, true),
            None => match rest.strip_suffix(".json") {
                Some(number) => (number, false),
                None => return Err(bad(format!("the file {name} is not a rotation file"))),
            },
        };
        if number.len() != 3 || !number.bytes().all(|b| b.is_ascii_digit()) {
            return Err(bad(format!("the file {name} has a wrong number")));
        }
        let number: u32 = number.parse().unwrap_or(0);
        if is_sig {
            signatures.push((number, bytes));
        } else {
            statements.push((number, bytes));
        }
    }
    if statements.len() > MAX_ROTATIONS {
        return Err(VerifyError::Rotation("there are too many rotations".into()));
    }
    statements.sort_by_key(|(number, _)| *number);
    signatures.sort_by_key(|(number, _)| *number);
    let numbers = |list: &[(u32, Vec<u8>)]| list.iter().map(|(n, _)| *n).collect::<Vec<_>>();
    let expected: Vec<u32> = (1..=statements.len() as u32).collect();
    if numbers(&statements) != expected || numbers(&signatures) != expected {
        return Err(VerifyError::Rotation(
            "each rotation needs a statement and a signature, numbered from 001 without gaps"
                .into(),
        ));
    }
    let rotations = statements
        .into_iter()
        .zip(signatures)
        .map(|((_, statement), (_, sig))| (statement, sig))
        .collect();
    Ok((pack_files, rotations))
}

/// Follow the rotation statements from a trusted key. Return the key chain.
fn follow_rotations(
    rotations: &RotationFiles,
    first_key_id: &str,
    trust: &TrustStore,
) -> Result<Vec<HybridPublicKey>, VerifyError> {
    let first = trust
        .find(first_key_id)
        .ok_or_else(|| VerifyError::UnknownKey(first_key_id.to_string()))?;
    if trust.is_revoked(first_key_id) {
        return Err(VerifyError::Revoked(first_key_id.to_string()));
    }
    let mut chain = vec![first.clone()];
    for (statement_bytes, sig_bytes) in rotations {
        let current = &chain[chain.len() - 1];
        let current_id = current.key_id();
        let statement: RotationStatement = serde_json::from_slice(statement_bytes)
            .map_err(|error| VerifyError::Rotation(error.to_string()))?;
        if statement.format != ROTATION_FORMAT {
            return Err(VerifyError::Rotation(format!(
                "the format must be {ROTATION_FORMAT}"
            )));
        }
        if statement.old_key_id != current_id {
            return Err(VerifyError::Rotation(
                "a rotation does not start at the key before it".into(),
            ));
        }
        verify_hybrid(statement_bytes, &SigFile::parse(sig_bytes)?, current)
            .map_err(|error| VerifyError::Rotation(error.to_string()))?;
        let decode = |text: &str| {
            B64.decode(text.as_bytes())
                .map_err(|_| VerifyError::Rotation("a new key is not Base64".into()))
        };
        let new_key = HybridPublicKey::from_spki_der(
            &decode(&statement.new_ed25519_spki)?,
            &decode(&statement.new_ml_dsa_65_spki)?,
        )?;
        let new_id = new_key.key_id();
        if trust.is_revoked(&new_id) {
            return Err(VerifyError::Revoked(new_id));
        }
        if chain.iter().any(|key| key.key_id() == new_id) {
            return Err(VerifyError::Rotation("the chain has a loop".into()));
        }
        chain.push(new_key);
    }
    Ok(chain)
}

/// Check the signature of a pack archive and load the pack.
///
/// The signer is a trusted key, or the end of a chain of key rotations that starts at a trusted key.
pub fn verify_pack_archive(
    archive: &[u8],
    sig: &SigFile,
    trust: &TrustStore,
) -> Result<VerifiedPack, VerifyError> {
    let (pack_files, rotations) = split_files(read_archive(archive)?)?;
    let first_key_id = match rotations.first() {
        None => sig.key_id.clone(),
        Some((statement, _)) => {
            #[derive(Deserialize)]
            struct Start {
                old_key_id: String,
            }
            serde_json::from_slice::<Start>(statement)
                .map_err(|error| VerifyError::Rotation(error.to_string()))?
                .old_key_id
        }
    };
    let chain = follow_rotations(&rotations, &first_key_id, trust)?;
    let signer = &chain[chain.len() - 1];
    let signer_id = signer.key_id();
    if sig.key_id != signer_id {
        return Err(if trust.is_revoked(&sig.key_id) {
            VerifyError::Revoked(sig.key_id.clone())
        } else {
            VerifyError::UnknownKey(sig.key_id.clone())
        });
    }
    if trust.is_revoked(&signer_id) {
        return Err(VerifyError::Revoked(signer_id));
    }
    verify_hybrid(archive, sig, signer)?;
    let pack = RulesPack::from_files(pack_files)?;
    Ok(VerifiedPack {
        pack,
        signed_by: signer_id,
        rotation_chain: chain.iter().map(HybridPublicKey::key_id).collect(),
    })
}

/// Load the pack in an archive without a check of its signature.
///
/// Use this function only when the user accepts an unsigned pack.
pub fn load_unverified(archive: &[u8]) -> Result<RulesPack, VerifyError> {
    let (pack_files, _rotations) = split_files(read_archive(archive)?)?;
    Ok(RulesPack::from_files(pack_files)?)
}
