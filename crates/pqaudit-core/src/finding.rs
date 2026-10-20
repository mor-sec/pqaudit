//! The finding model and the inventory model.

use crate::fingerprint::Fingerprint;
use chrono::{DateTime, Utc};
use pqaudit_rules::pack::ThreatType;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// The kind of scan that found a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// The file scanner.
    File,
    /// The network scanner.
    Net,
}

/// What a cryptographic item does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Key exchange.
    KeyExchange,
    /// Encryption.
    Encryption,
    /// Signature.
    Signature,
    /// Hash.
    Hash,
    /// The purpose is not known.
    Unknown,
}

/// How easily the item can change to another algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Agility {
    /// The code names the algorithm.
    HardCoded,
    /// A setting selects the algorithm.
    Config,
    /// The library selects the algorithm.
    LibraryDefault,
    /// The tool cannot tell.
    Unknown,
}

/// Who can fix the finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FixOwner {
    /// The user's own team.
    InHouse,
    /// An open-source project.
    OpenSource,
    /// A vendor.
    Vendor,
    /// The tool cannot tell.
    Unknown,
}

/// A network protocol that the tool probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TLS.
    Tls,
    /// SSH.
    Ssh,
}

/// A cryptographic algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Algorithm {
    /// The name of the algorithm.
    pub name: String,
    /// The key size in bits.
    pub key_bits: Option<u32>,
    /// The name of the elliptic curve.
    pub curve: Option<String>,
}

/// Where the tool saw an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Location {
    /// A place in a file.
    File {
        /// The path of the file.
        path: String,
        /// The line number.
        line: Option<u32>,
    },
    /// A network endpoint.
    Endpoint {
        /// The host name.
        host: String,
        /// The IP address.
        ip: IpAddr,
        /// The port.
        port: u16,
        /// The protocol.
        protocol: Protocol,
    },
}

/// One place where the tool saw an item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Occurrence {
    /// The place.
    pub location: Location,
    /// The text that shows the item.
    pub evidence: String,
    /// The run that saw the item.
    pub run_id: Uuid,
}

/// Facts about a certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CertInfo {
    /// The SHA-256 hash of the certificate in hex.
    pub sha256: String,
    /// The subject name.
    pub subject: String,
    /// The issuer name.
    pub issuer: String,
    /// The start of the validity.
    pub not_before: DateTime<Utc>,
    /// The end of the validity.
    pub not_after: DateTime<Utc>,
    /// True if the certificate is a CA.
    pub is_ca: bool,
    /// The key usage values.
    pub key_usage: Vec<String>,
    /// The extended key usage values.
    pub ext_key_usage: Vec<String>,
    /// The public key.
    pub public_key: Algorithm,
    /// The signature algorithm.
    pub signature_algorithm: String,
    /// The position in the chain. The leaf is 0.
    pub chain_position: Option<u8>,
}

/// The kind of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum KeyKind {
    /// An X.509 SubjectPublicKeyInfo public key.
    X509Spki,
    /// An OpenSSH public key.
    OpenSsh,
    /// A PGP key.
    Pgp,
    /// An unencrypted PKCS#8 private key. The results never hold its bytes.
    Pkcs8Private,
    /// An encrypted private key. The results never hold its bytes.
    EncryptedPrivate,
}

/// Facts about a key. This never holds private key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct KeyInfo {
    /// The SHA-256 fingerprint in hex.
    pub fingerprint_sha256: String,
    /// The kind of key.
    pub kind: KeyKind,
    /// The algorithm.
    pub algorithm: Option<Algorithm>,
    /// The comment of the key.
    pub comment: Option<String>,
}

/// What the tool saw in a TLS handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TlsObservation {
    /// True if the server supports a post-quantum hybrid group.
    pub pq_hybrid_supported: Option<bool>,
    /// The negotiated TLS version.
    pub negotiated_version: Option<String>,
    /// The negotiated key exchange group.
    pub negotiated_group: Option<String>,
    /// The negotiated cipher suite.
    pub cipher_suite: Option<String>,
    /// The old protocol versions that the server accepts.
    pub legacy_versions: Option<Vec<String>>,
    /// The errors during the probe.
    pub errors: Vec<String>,
}

/// What the tool saw in an SSH exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SshObservation {
    /// The banner line of the server.
    pub banner: String,
    /// The key exchange algorithms.
    pub kex: Vec<String>,
    /// The host key algorithms.
    pub host_key_algorithms: Vec<String>,
    /// The ciphers.
    pub ciphers: Vec<String>,
    /// The MAC algorithms.
    pub macs: Vec<String>,
}

/// Facts about a network endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct EndpointInfo {
    /// The protocol.
    pub protocol: Protocol,
    /// The TLS facts.
    pub tls: Option<TlsObservation>,
    /// The SSH facts.
    pub ssh: Option<SshObservation>,
}

/// A weak cryptographic item that the tool found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    /// The ID of the finding in this file.
    pub id: String,
    /// The stable ID of the subject.
    pub fingerprint: Fingerprint,
    /// The rule that matched.
    pub rule_id: String,
    /// The kind of scan.
    pub source: Source,
    /// The algorithm.
    pub algorithm: Option<Algorithm>,
    /// What the item does.
    pub purpose: Purpose,
    /// The kind of threat.
    pub threat_type: ThreatType,
    /// How easily the item can change.
    pub agility: Agility,
    /// Who can fix the finding.
    pub fix_owner: FixOwner,
    /// The IDs of other rules that matched the same subject.
    pub also: Vec<String>,
    /// The places where the tool saw the subject.
    pub occurrences: Vec<Occurrence>,
    /// The certificate facts.
    pub cert: Option<CertInfo>,
    /// The key facts.
    pub key: Option<KeyInfo>,
    /// The endpoint facts.
    pub endpoint: Option<EndpointInfo>,
}

/// The kind of an inventory item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InventoryKind {
    /// A certificate.
    Certificate,
    /// A key.
    Key,
    /// An endpoint.
    Endpoint,
}

/// A cryptographic item that the scan found. It can be a finding or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InventoryItem {
    /// The kind of item.
    pub kind: InventoryKind,
    /// The stable ID of the item.
    pub fingerprint: Fingerprint,
    /// True if the item is ready for post-quantum use.
    pub pq_ready: bool,
    /// The algorithm.
    pub algorithm: Option<Algorithm>,
    /// The certificate facts.
    pub cert: Option<CertInfo>,
    /// The key facts.
    pub key: Option<KeyInfo>,
    /// The endpoint facts.
    pub endpoint: Option<EndpointInfo>,
    /// The places where the tool saw the item.
    pub occurrences: Vec<Occurrence>,
}

/// An error during a scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanError {
    /// The file path or the endpoint.
    pub location: String,
    /// Why the scan failed.
    pub reason: String,
}
