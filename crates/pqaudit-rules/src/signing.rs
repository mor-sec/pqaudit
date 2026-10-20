//! Make keys and signatures. Only the xtask and the tests use this code.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::Signer as _;
use ml_dsa::pkcs8::spki::der::pem::LineEnding;
use ml_dsa::MlDsa65;
use serde::Serialize;

use crate::verify::{HybridPublicKey, SigFile, ROTATION_FORMAT, SIG_FORMAT};

/// An error when the program makes a key or a signature.
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    /// The system has no random bytes.
    #[error("The system cannot give random bytes: {0}")]
    Random(String),
    /// The program cannot read or write a key.
    #[error("A key is not valid: {0}")]
    Key(String),
    /// The date is not valid.
    #[error("The date {0:?} is not valid. Use YYYY-MM-DD.")]
    Date(String),
}

/// The four PEM texts of a key pair.
pub struct KeyPems {
    /// The Ed25519 private key (PKCS#8).
    pub ed25519_private: String,
    /// The Ed25519 public key (SPKI).
    pub ed25519_public: String,
    /// The ML-DSA-65 private key (PKCS#8).
    pub ml_dsa_65_private: String,
    /// The ML-DSA-65 public key (SPKI).
    pub ml_dsa_65_public: String,
}

/// A private key pair: one Ed25519 key and one ML-DSA-65 key.
pub struct HybridSigningKey {
    ed25519: ed25519_dalek::SigningKey,
    ml_dsa_65: ml_dsa::SigningKey<MlDsa65>,
}

impl std::fmt::Debug for HybridSigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never show private key bytes.
        f.write_str("HybridSigningKey(..)")
    }
}

impl HybridSigningKey {
    /// Make a new key pair from system random bytes.
    pub fn generate() -> Result<Self, SigningError> {
        let mut ed_seed = [0u8; 32];
        let mut ml_seed = [0u8; 32];
        getrandom::fill(&mut ed_seed).map_err(|error| SigningError::Random(error.to_string()))?;
        getrandom::fill(&mut ml_seed).map_err(|error| SigningError::Random(error.to_string()))?;
        Ok(HybridSigningKey {
            ed25519: ed25519_dalek::SigningKey::from_bytes(&ed_seed),
            ml_dsa_65: ml_dsa::SigningKey::<MlDsa65>::from_seed(&ml_seed.into()),
        })
    }

    /// Read a key pair from two PKCS#8 PEM texts.
    pub fn from_pems(ed25519_pem: &str, ml_dsa_65_pem: &str) -> Result<Self, SigningError> {
        let key_err = |error: &dyn std::fmt::Display| SigningError::Key(error.to_string());
        Ok(HybridSigningKey {
            ed25519: ed25519_dalek::SigningKey::from_pkcs8_pem(ed25519_pem)
                .map_err(|e| key_err(&e))?,
            ml_dsa_65:
                <ml_dsa::SigningKey<MlDsa65> as ml_dsa::pkcs8::DecodePrivateKey>::from_pkcs8_pem(
                    ml_dsa_65_pem,
                )
                .map_err(|e| key_err(&e))?,
        })
    }

    /// Return the public half.
    pub fn public_key(&self) -> HybridPublicKey {
        HybridPublicKey {
            ed25519: self.ed25519.verifying_key(),
            ml_dsa_65: ml_dsa::signature::Keypair::verifying_key(&self.ml_dsa_65),
        }
    }

    /// Return the two public PEM texts: (Ed25519, ML-DSA-65).
    pub fn public_pems(&self) -> Result<(String, String), SigningError> {
        let public = self.public_key();
        let key_err = |error: &dyn std::fmt::Display| SigningError::Key(error.to_string());
        Ok((
            public
                .ed25519
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| key_err(&e))?,
            public
                .ml_dsa_65
                .to_public_key_pem(LineEnding::LF)
                .map_err(|e| key_err(&e))?,
        ))
    }

    /// Return the four PEM texts of the key pair.
    pub fn to_pems(&self) -> Result<KeyPems, SigningError> {
        let key_err = |error: &dyn std::fmt::Display| SigningError::Key(error.to_string());
        let (ed25519_public, ml_dsa_65_public) = self.public_pems()?;
        Ok(KeyPems {
            ed25519_private: self
                .ed25519
                .to_pkcs8_pem(LineEnding::LF)
                .map_err(|e| key_err(&e))?
                .to_string(),
            ed25519_public,
            ml_dsa_65_private: ml_dsa::pkcs8::EncodePrivateKey::to_pkcs8_pem(
                &self.ml_dsa_65,
                LineEnding::LF,
            )
            .map_err(|e| key_err(&e))?
            .to_string(),
            ml_dsa_65_public,
        })
    }

    /// Sign the bytes with both keys. Return the two raw signatures.
    pub fn sign_raw(&self, data: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let ed = self.ed25519.sign(data).to_bytes().to_vec();
        let ml = self
            .ml_dsa_65
            .expanded_key()
            .sign_deterministic(data, b"")
            .expect("an empty context is never too long")
            .encode()
            .to_vec();
        (ed, ml)
    }

    /// Sign the bytes with both keys. Return the signature file.
    pub fn sign(&self, data: &[u8]) -> SigFile {
        let (ed, ml) = self.sign_raw(data);
        SigFile {
            format: SIG_FORMAT.to_string(),
            key_id: self.public_key().key_id(),
            ed25519: B64.encode(ed),
            ml_dsa_65: B64.encode(ml),
        }
    }
}

#[derive(Serialize)]
struct RotationOut<'a> {
    format: &'a str,
    old_key_id: String,
    new_ed25519_spki: String,
    new_ml_dsa_65_spki: String,
    issued: &'a str,
}

/// Make a key rotation statement and its signature. The old key signs the statement.
pub fn make_rotation(
    old: &HybridSigningKey,
    new: &HybridPublicKey,
    issued: &str,
) -> Result<(Vec<u8>, SigFile), SigningError> {
    if issued.parse::<chrono::NaiveDate>().is_err() {
        return Err(SigningError::Date(issued.to_string()));
    }
    let statement = RotationOut {
        format: ROTATION_FORMAT,
        old_key_id: old.public_key().key_id(),
        new_ed25519_spki: B64.encode(new.ed25519_spki_der()),
        new_ml_dsa_65_spki: B64.encode(new.ml_dsa_65_spki_der()),
        issued,
    };
    let mut bytes = serde_json::to_vec_pretty(&statement)
        .map_err(|error| SigningError::Key(error.to_string()))?;
    bytes.push(b'\n');
    let sig = old.sign(&bytes);
    Ok((bytes, sig))
}
