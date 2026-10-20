//! The offline file scanner of pqaudit.
//!
//! This crate reads files only. It must not open sockets or use network crates.

mod algorithm;
pub mod cert;
mod der;
mod derive;
mod file;
pub mod gpg;
pub mod jks;
pub mod keys;
pub mod messages;
pub mod pem;
pub mod pkcs12;
pub mod privkey;
mod sniff;
pub mod ssh;
pub mod walk;

use std::path::PathBuf;

use chrono::Utc;
use pqaudit_core::classify::{classify_cert, classify_key};
use pqaudit_core::{
    Agility, Finding, Fingerprint, FixOwner, InventoryItem, InventoryKind, Purpose, ScanError,
    Source,
};
use pqaudit_rules::pack::{Primitive, RulesPack};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::file::{scan_file, Collector, Outcome};

/// The settings of a file scan.
pub struct ScanOptions {
    /// The tool skips a file that is larger than this number of bytes.
    pub max_file_size: u64,
    /// If true, the tool follows symbolic links.
    pub follow_symlinks: bool,
    /// Passwords for PKCS#12 key stores. The tool tries each one, then the empty password.
    /// The tool never logs them.
    pub passwords: Vec<Zeroizing<String>>,
    /// The name of the host that the tool scans. It goes into the fingerprint of a private key
    /// that has no public part, so two hosts do not merge their keys.
    pub host: String,
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
            .field("host", &self.host)
            .finish()
    }
}

/// Find the name of this computer. Return "unknown" if the tool cannot find it.
pub fn local_host_name() -> String {
    for variable in ["HOSTNAME", "COMPUTERNAME"] {
        if let Ok(name) = std::env::var(variable) {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
    }
    for path in ["/proc/sys/kernel/hostname", "/etc/hostname"] {
        if let Ok(name) = std::fs::read_to_string(path) {
            if !name.trim().is_empty() {
                return name.trim().to_string();
            }
        }
    }
    String::from("unknown")
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_file_size: 10_485_760,
            follow_symlinks: false,
            passwords: Vec::new(),
            host: local_host_name(),
        }
    }
}

/// The result of a file scan.
#[derive(Debug, Default, Serialize)]
pub struct ScanOutput {
    /// The weak items.
    pub findings: Vec<Finding>,
    /// The items that are not findings, for example post-quantum certificates and encrypted keys.
    pub inventory: Vec<InventoryItem>,
    /// The paths and files that the tool could not scan.
    pub errors: Vec<ScanError>,
    /// The number of files that the tool read.
    pub files_read: u64,
    /// The number of files with nothing that the tool can read, for example PEM files with
    /// other blocks and key stores that no password opens. The tool does not count them in `files_read`.
    pub files_not_read: u64,
    /// The number of symbolic links that the tool skipped.
    pub skipped_symlinks: u64,
}

/// Scan the paths for certificates and keys. The scan never stops at a bad file.
///
/// The scan reads X.509 certificates, key stores, SSH keys, PEM keys, and OpenPGP keys.
/// It never puts private key bytes in the output.
pub fn scan(paths: &[PathBuf], opts: &ScanOptions, pack: &RulesPack, run_id: Uuid) -> ScanOutput {
    let mut collector = Collector::default();
    let mut output = ScanOutput::default();
    let mut errors = Vec::new();
    let mut files_read = 0u64;
    let mut files_not_read = 0u64;

    let skipped_symlinks =
        walk::walk(
            paths,
            opts.follow_symlinks,
            &mut errors,
            |path, errors| match scan_file(path, opts, run_id, &mut collector, errors) {
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

    let Collector {
        certs,
        keys,
        locked,
    } = collector;
    output.inventory.extend(locked);
    let today = Utc::now().date_naive();
    let mut count = 0;
    let mut next_id = || {
        count += 1;
        format!("file-{count}")
    };
    for (_, item) in certs {
        let fingerprint = Fingerprint::cert(&item.cert.sha256);
        match classify_cert(&item.cert, pack, today) {
            Some((rule_id, threat_type, also)) => output.findings.push(Finding {
                id: next_id(),
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
                let pq_ready = is_pq_ready(pack, &item.cert.public_key.name);
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
    for (_, item) in keys {
        let fingerprint = if item.key.place_based {
            Fingerprint::place(&opts.host, &item.key.id)
        } else {
            Fingerprint::key(&item.key.id)
        };
        let algorithm = item.key.info.algorithm.clone();
        let verdict = algorithm
            .as_ref()
            .and_then(|algorithm| classify_key(algorithm, pack));
        match verdict {
            Some((rule_id, threat_type)) => output.findings.push(Finding {
                id: next_id(),
                fingerprint,
                rule_id,
                source: Source::File,
                purpose: key_purpose(pack, algorithm.as_ref()),
                algorithm,
                threat_type,
                agility: Agility::Unknown,
                fix_owner: FixOwner::Unknown,
                also: Vec::new(),
                occurrences: item.occurrences,
                cert: None,
                key: Some(item.key.info),
                endpoint: None,
            }),
            None => {
                let pq_ready = algorithm
                    .as_ref()
                    .is_some_and(|algorithm| is_pq_ready(pack, &algorithm.name));
                output.inventory.push(InventoryItem {
                    kind: InventoryKind::Key,
                    fingerprint,
                    pq_ready,
                    algorithm,
                    cert: None,
                    key: Some(item.key.info),
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

/// Return true if the pack knows the algorithm and a quantum computer cannot break it.
fn is_pq_ready(pack: &RulesPack, name: &str) -> bool {
    pack.algorithm(name)
        .is_some_and(|fact| !fact.quantum_vulnerable)
}

/// Find the purpose of a key from the primitive of its algorithm.
fn key_purpose(pack: &RulesPack, algorithm: Option<&pqaudit_core::Algorithm>) -> Purpose {
    let primitive = algorithm
        .and_then(|algorithm| pack.algorithm(&algorithm.name))
        .map(|fact| fact.primitive);
    match primitive {
        Some(Primitive::Signature) => Purpose::Signature,
        Some(Primitive::KeyAgree | Primitive::Kem) => Purpose::KeyExchange,
        Some(Primitive::Pke) => Purpose::Encryption,
        _ => Purpose::Unknown,
    }
}
