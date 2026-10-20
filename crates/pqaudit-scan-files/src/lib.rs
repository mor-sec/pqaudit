//! The offline file scanner of pqaudit.
//!
//! This crate reads files only. It must not open sockets or use network crates.

pub mod cert;
pub mod jks;
pub mod messages;
pub mod pkcs12;
pub mod walk;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::Utc;
use pqaudit_core::classify::classify_cert;
use pqaudit_core::{
    Agility, CertInfo, Finding, Fingerprint, FixOwner, InventoryItem, InventoryKind, KeyInfo,
    KeyKind, Location, Occurrence, Purpose, ScanError, Source,
};
use pqaudit_rules::pack::RulesPack;
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The number of bytes at the start of a file that the tool searches for a certificate.
const SNIFF_BYTES: u64 = 64 * 1024;

/// The settings of a file scan.
pub struct ScanOptions {
    /// The tool skips a file that is larger than this number of bytes.
    pub max_file_size: u64,
    /// If true, the tool follows symbolic links.
    pub follow_symlinks: bool,
    /// Passwords for PKCS#12 key stores. The tool tries each one, then the empty password.
    /// The tool never logs them.
    pub passwords: Vec<Zeroizing<String>>,
}

impl std::fmt::Debug for ScanOptions {
    /// Show the number of passwords. Never show a password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanOptions")
            .field("max_file_size", &self.max_file_size)
            .field("follow_symlinks", &self.follow_symlinks)
            .field(
                "passwords",
                &format_args!("{} hidden", self.passwords.len()),
            )
            .finish()
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: 10_485_760,
            follow_symlinks: false,
            passwords: Vec::new(),
        }
    }
}

/// The result of a file scan.
#[derive(Debug, Default, Serialize)]
pub struct ScanOutput {
    /// The weak items.
    pub findings: Vec<Finding>,
    /// The items that are not findings, for example post-quantum certificates.
    pub inventory: Vec<InventoryItem>,
    /// The paths and files that the tool could not scan.
    pub errors: Vec<ScanError>,
    /// The number of files that the tool read.
    pub files_read: u64,
    /// The number of files with no readable certificate, for example key files
    /// and key stores that no password opens. The tool does not count them in `files_read`.
    pub files_not_read: u64,
    /// The number of symbolic links that the tool skipped.
    pub skipped_symlinks: u64,
}

/// The kind of key store file.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StoreKind {
    /// A PKCS#12 file.
    Pkcs12,
    /// A JKS or JCEKS file.
    Java,
}

/// Find the kind of key store from the first bytes of the file. Return `None` for other files.
fn store_kind_by_content(head: &[u8]) -> Option<StoreKind> {
    if jks::has_jks_magic(head) {
        Some(StoreKind::Java)
    } else if pkcs12::looks_like_p12(head) {
        Some(StoreKind::Pkcs12)
    } else {
        None
    }
}

/// Find the kind of key store from the file extension. Return `None` for other files.
fn store_kind_by_extension(extension: &str) -> Option<StoreKind> {
    match extension {
        "p12" | "pfx" => Some(StoreKind::Pkcs12),
        "jks" | "jceks" | "keystore" => Some(StoreKind::Java),
        _ => None,
    }
}

/// What happened to one file.
enum Outcome {
    /// The tool read the file.
    Read,
    /// The file has no certificate that the tool can read, for example a key file.
    NotRead,
    /// The tool could not read the file. An error explains why.
    Failed,
}

/// A certificate and the places where the tool saw it.
struct Seen {
    cert: CertInfo,
    occurrences: Vec<Occurrence>,
}

/// Scan the paths for X.509 certificates. The scan never stops at a bad file.
pub fn scan(paths: &[PathBuf], opts: &ScanOptions, pack: &RulesPack, run_id: Uuid) -> ScanOutput {
    let mut seen: BTreeMap<String, Seen> = BTreeMap::new();
    let mut output = ScanOutput::default();
    let mut errors = Vec::new();
    let mut files_read = 0u64;

    let mut files_not_read = 0u64;
    let mut locked = Vec::new();

    let skipped_symlinks =
        walk::walk(
            paths,
            opts.follow_symlinks,
            &mut errors,
            |path, errors| match scan_file(path, opts, run_id, &mut seen, &mut locked, errors) {
                Outcome::Read => files_read += 1,
                Outcome::NotRead => files_not_read += 1,
                Outcome::Failed => {}
            },
        );
    if skipped_symlinks > 0 {
        errors.push(ScanError {
            location: String::from("symbolic links"),
            reason: messages::SYMLINKS_SKIPPED.replace("{count}", &skipped_symlinks.to_string()),
        });
    }

    output.inventory.extend(locked);
    let today = Utc::now().date_naive();
    for (index, (_, item)) in seen.into_iter().enumerate() {
        let fingerprint = Fingerprint::cert(&item.cert.sha256);
        match classify_cert(&item.cert, pack, today) {
            Some((rule_id, threat_type, also)) => output.findings.push(Finding {
                id: format!("file-{}", index + 1),
                fingerprint,
                rule_id,
                source: Source::File,
                algorithm: Some(item.cert.public_key.clone()),
                purpose: Purpose::Signature,
                threat_type,
                agility: Agility::Unknown,
                fix_owner: FixOwner::Unknown,
                also,
                occurrences: item.occurrences,
                cert: Some(item.cert),
                key: None,
                endpoint: None,
            }),
            None => {
                let pq_ready = pack
                    .algorithm(&item.cert.public_key.name)
                    .is_some_and(|fact| !fact.quantum_vulnerable);
                output.inventory.push(InventoryItem {
                    kind: InventoryKind::Certificate,
                    fingerprint,
                    pq_ready,
                    algorithm: Some(item.cert.public_key.clone()),
                    cert: Some(item.cert),
                    key: None,
                    endpoint: None,
                    occurrences: item.occurrences,
                });
            }
        }
    }
    output.errors = errors;
    output.files_read = files_read;
    output.files_not_read = files_not_read;
    output.skipped_symlinks = skipped_symlinks;
    output
}

/// Wrap certificates from a key store. A key store has no line numbers.
fn into_found(certs: Vec<CertInfo>) -> Vec<cert::Found> {
    certs
        .into_iter()
        .map(|info| cert::Found { info, line: None })
        .collect()
}

/// Collect the certificates of all Java key store entries.
fn jks_certs(entries: Vec<jks::JksEntry>) -> Vec<cert::Found> {
    let mut certs = Vec::new();
    for entry in entries {
        match entry {
            jks::JksEntry::TrustedCert(info) => certs.push(info),
            jks::JksEntry::PrivateKeyChain(chain) => certs.extend(chain),
        }
    }
    into_found(certs)
}

/// Make the inventory item for a key store that no password opens.
///
/// The fingerprint is the hash of the whole file. The item has no key facts.
fn locked_item(data: &[u8], location: &str, run_id: Uuid) -> InventoryItem {
    InventoryItem {
        kind: InventoryKind::Key,
        fingerprint: Fingerprint::key(&cert::sha256_hex(data)),
        pq_ready: false,
        algorithm: None,
        cert: None,
        key: Some(KeyInfo {
            fingerprint_sha256: cert::sha256_hex(data),
            kind: KeyKind::EncryptedPrivate,
            algorithm: None,
            comment: None,
        }),
        endpoint: None,
        occurrences: vec![Occurrence {
            location: Location::File {
                path: location.to_string(),
                line: None,
            },
            evidence: messages::ENCRYPTED_NOT_INSPECTED.to_string(),
            run_id,
        }],
    }
}

fn is_certificate_extension(extension: &str) -> bool {
    matches!(extension, "pem" | "crt" | "cer" | "der")
}

fn too_large(location: &str, limit: u64) -> ScanError {
    ScanError {
        location: location.to_string(),
        reason: messages::TOO_LARGE.replace("{limit}", &limit.to_string()),
    }
}

/// Read `limit` bytes at most from the reader into the buffer.
fn read_up_to(reader: impl Read, limit: u64, buffer: &mut Vec<u8>) -> std::io::Result<()> {
    reader.take(limit).read_to_end(buffer).map(|_| ())
}

/// Scan one file.
fn scan_file(
    path: &Path,
    opts: &ScanOptions,
    run_id: Uuid,
    seen: &mut BTreeMap<String, Seen>,
    locked: &mut Vec<InventoryItem>,
    errors: &mut Vec<ScanError>,
) -> Outcome {
    let location = path.to_string_lossy().into_owned();
    if path.to_str().is_none() {
        errors.push(ScanError {
            location: location.clone(),
            reason: messages::NAME_NOT_UTF8.to_string(),
        });
    }
    let cannot_read = |error: std::io::Error| ScanError {
        location: location.clone(),
        reason: messages::CANNOT_READ.replace("{reason}", &error.to_string()),
    };
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    let store_by_extension = store_kind_by_extension(&extension);
    let by_extension = is_certificate_extension(&extension) || store_by_extension.is_some();

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            errors.push(cannot_read(error));
            return Outcome::Failed;
        }
    };
    let length = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            errors.push(cannot_read(error));
            return Outcome::Failed;
        }
    };

    let mut data = Vec::new();
    let head_limit = if by_extension {
        if length > opts.max_file_size {
            errors.push(too_large(&location, opts.max_file_size));
            return Outcome::Failed;
        }
        opts.max_file_size
    } else {
        SNIFF_BYTES.min(opts.max_file_size)
    };
    if let Err(error) = read_up_to(&mut file, head_limit.saturating_add(1), &mut data) {
        errors.push(cannot_read(error));
        return Outcome::Failed;
    }
    if !by_extension {
        if !cert::has_pem_certificate(&data) && store_kind_by_content(&data).is_none() {
            return Outcome::Read;
        }
        if length > opts.max_file_size {
            errors.push(too_large(&location, opts.max_file_size));
            return Outcome::Failed;
        }
        let rest = opts.max_file_size.saturating_add(1) - data.len() as u64;
        if let Err(error) = read_up_to(&mut file, rest, &mut data) {
            errors.push(cannot_read(error));
            return Outcome::Failed;
        }
    }
    // The file can grow after the size check.
    if data.len() as u64 > opts.max_file_size {
        errors.push(too_large(&location, opts.max_file_size));
        return Outcome::Failed;
    }

    let store_kind = store_kind_by_content(&data).or(store_by_extension);
    let mut found = Vec::new();
    if let Some(kind) = store_kind {
        let result = match kind {
            StoreKind::Pkcs12 => pkcs12::scan_p12(&data, &opts.passwords).map(into_found),
            StoreKind::Java => jks::scan_jks(&data).map(jks_certs),
        };
        match result {
            Ok(certs) => found = certs,
            Err(pkcs12::StoreError::Encrypted) => {
                errors.push(ScanError {
                    location: location.clone(),
                    reason: messages::ENCRYPTED_NOT_INSPECTED.to_string(),
                });
                locked.push(locked_item(&data, &location, run_id));
                return Outcome::NotRead;
            }
            Err(error) => {
                errors.push(ScanError {
                    location: location.clone(),
                    reason: error.reason(),
                });
                return Outcome::Failed;
            }
        }
    } else if cert::has_any_pem(&data) {
        let result = cert::parse_pem(&data);
        if result.certs.is_empty() && result.bad == 0 {
            // Only blocks of other types, for example keys.
            return Outcome::NotRead;
        }
        if result.bad > 0 {
            let total = result.bad + result.certs.len();
            errors.push(ScanError {
                location: location.clone(),
                reason: messages::PEM_BLOCKS_INVALID
                    .replace("{bad}", &result.bad.to_string())
                    .replace("{total}", &total.to_string())
                    .replace("{reason}", &result.first_problem.unwrap_or_default()),
            });
        }
        found = result.certs;
    } else if by_extension {
        if extension == "pem" {
            errors.push(ScanError {
                location: location.clone(),
                reason: messages::NO_CERTIFICATE.to_string(),
            });
        } else {
            match cert::parse_der(&data) {
                Ok(info) => found.push(cert::Found { info, line: None }),
                Err(reason) => errors.push(ScanError {
                    location: location.clone(),
                    reason,
                }),
            }
        }
    }

    for item in found {
        let evidence = messages::EVIDENCE
            .replace("{subject}", &item.info.subject)
            .replace(
                "{position}",
                &item.info.chain_position.unwrap_or(0).to_string(),
            );
        let occurrence = Occurrence {
            location: Location::File {
                path: location.clone(),
                line: item.line,
            },
            evidence,
            run_id,
        };
        seen.entry(item.info.sha256.clone())
            .or_insert_with(|| Seen {
                cert: item.info,
                occurrences: Vec::new(),
            })
            .occurrences
            .push(occurrence);
    }
    Outcome::Read
}
