//! Stable IDs for certificates, keys, and endpoints.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt::Write;

/// A stable ID of a subject. The format is `<kind>:<32 hex digits>`.
#[derive(
    Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
#[serde(transparent)]
pub struct Fingerprint(pub String);

impl Fingerprint {
    /// Make the fingerprint of a certificate from its SHA-256 hash in hex.
    pub fn cert(sha256_hex: &str) -> Self {
        Self::build("cert", &[sha256_hex])
    }

    /// Make the fingerprint of a key from the SHA-256 hash of its SPKI or blob in hex.
    pub fn key(spki_or_blob_sha256_hex: &str) -> Self {
        Self::build("key", &[spki_or_blob_sha256_hex])
    }

    /// Make the fingerprint of an endpoint. The host is in lower case.
    pub fn endpoint(host: &str, port: u16, rule_family: &str) -> Self {
        Self::build(
            "endpoint",
            &[&host.to_lowercase(), &port.to_string(), rule_family],
        )
    }

    fn build(kind: &str, fields: &[&str]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(kind.as_bytes());
        for field in fields {
            hasher.update([0u8]);
            hasher.update(field.as_bytes());
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(32);
        for byte in &digest[..16] {
            write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        }
        Self(format!("{kind}:{hex}"))
    }
}
