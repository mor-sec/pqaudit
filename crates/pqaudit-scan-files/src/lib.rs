//! The offline file scanner of pqaudit.
//!
//! This crate reads files only. It must not open sockets or use network crates.

pub mod cert;
pub mod messages;
pub mod walk;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use chrono::Utc;
use pqaudit_core::classify::classify_cert;
use pqaudit_core::{
    Agility, CertInfo, Finding, Fingerprint, FixOwner, InventoryItem, InventoryKind, Location,
    Occurrence, Purpose, ScanError, Source,
};
use pqaudit_rules::pack::RulesPack;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The number of bytes at the start of a file that the tool searches for a certificate.
const SNIFF_BYTES: u64 = 64 * 1024;

/// The settings of a file scan.
#[derive(Debug)]
pub struct ScanOptions {
    /// The tool skips a file that is larger than this number of bytes.
    pub max_file_size: u64,
    /// If true, the tool follows symbolic links.
    pub follow_symlinks: bool,
    /// Passwords for key stores. A later scanner step uses them. The tool never logs them.
    pub passwords: Vec<Zeroizing<String>>,
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
#[derive(Debug, Default)]
pub struct ScanOutput {
    /// The weak items.
    pub findings: Vec<Finding>,
    /// The items that are not findings, for example post-quantum certificates.
    pub inventory: Vec<InventoryItem>,
    /// The paths and files that the tool could not scan.
    pub errors: Vec<ScanError>,
    /// The number of files that the tool read.
    pub files_read: u64,
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

    walk::walk(paths, opts.follow_symlinks, &mut errors, |path, errors| {
        if scan_file(path, opts, run_id, &mut seen, errors) {
            files_read += 1;
        }
    });

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
    output
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

/// Scan one file. Return true if the tool could read the file.
fn scan_file(
    path: &Path,
    opts: &ScanOptions,
    run_id: Uuid,
    seen: &mut BTreeMap<String, Seen>,
    errors: &mut Vec<ScanError>,
) -> bool {
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
    let by_extension = is_certificate_extension(&extension);

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) => {
            errors.push(cannot_read(error));
            return false;
        }
    };
    let length = match file.metadata() {
        Ok(metadata) => metadata.len(),
        Err(error) => {
            errors.push(cannot_read(error));
            return false;
        }
    };

    let mut data = Vec::new();
    let head_limit = if by_extension {
        if length > opts.max_file_size {
            errors.push(too_large(&location, opts.max_file_size));
            return false;
        }
        opts.max_file_size
    } else {
        SNIFF_BYTES.min(opts.max_file_size)
    };
    if let Err(error) = read_up_to(&mut file, head_limit.saturating_add(1), &mut data) {
        errors.push(cannot_read(error));
        return false;
    }
    if !by_extension {
        if !cert::has_pem_certificate(&data) {
            return true;
        }
        if length > opts.max_file_size {
            errors.push(too_large(&location, opts.max_file_size));
            return false;
        }
        let rest = opts.max_file_size.saturating_add(1) - data.len() as u64;
        if let Err(error) = read_up_to(&mut file, rest, &mut data) {
            errors.push(cannot_read(error));
            return false;
        }
    }
    // The file can grow after the size check.
    if data.len() as u64 > opts.max_file_size {
        errors.push(too_large(&location, opts.max_file_size));
        return false;
    }

    let mut found = Vec::new();
    if cert::has_pem_certificate(&data) {
        let result = cert::parse_pem(&data);
        if result.bad > 0 {
            let total = result.bad + result.certs.len();
            errors.push(ScanError {
                location: location.clone(),
                reason: messages::PEM_BLOCKS_INVALID
                    .replace("{bad}", &result.bad.to_string())
                    .replace("{total}", &total.to_string())
                    .replace("{reason}", result.first_problem.unwrap_or_default()),
            });
        }
        found = result.certs;
    } else if by_extension && !cert::has_any_pem(&data) {
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
                    reason: reason.to_string(),
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
    true
}
