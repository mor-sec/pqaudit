//! Scan one file: find its format, read it, and collect what it holds.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use pqaudit_core::{
    CertInfo, Fingerprint, InventoryItem, InventoryKind, KeyInfo, KeyKind, Location, Occurrence,
    ScanError,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cert::CertError;
use crate::keys::{FoundKey, KeyProblem};
use crate::pem::{self, BlockKind};
use crate::sniff::{self, Format, StoreKind};
use crate::{cert, gpg, jks, messages, pkcs12, privkey, ssh, ScanOptions};

/// The number of bytes at the start of a file that the tool searches for a known format.
const SNIFF_BYTES: u64 = 64 * 1024;

/// What happened to one file.
pub(crate) enum Outcome {
    /// The tool read the file.
    Read,
    /// The file has nothing that the tool can read, for example a key store that no password opens.
    NotRead,
    /// The tool could not read the file. An error explains why.
    Failed,
}

/// A certificate and the places where the tool saw it.
pub(crate) struct Seen {
    pub cert: CertInfo,
    pub occurrences: Vec<Occurrence>,
}

/// A key and the places where the tool saw it.
pub(crate) struct SeenKey {
    pub key: FoundKey,
    pub occurrences: Vec<Occurrence>,
}

/// What the scan of all files found.
#[derive(Default)]
pub(crate) struct Collector {
    /// The certificates, by hash.
    pub certs: BTreeMap<String, Seen>,
    /// The keys, by ID.
    pub keys: BTreeMap<String, SeenKey>,
    /// The key stores that no password opens.
    pub locked: Vec<InventoryItem>,
}

/// The facts about the file that the scan reads.
struct FileContext<'a> {
    location: &'a str,
    extension: &'a str,
    run_id: Uuid,
}

impl FileContext<'_> {
    fn occurrence(&self, line: Option<u32>, evidence: String) -> Occurrence {
        Occurrence {
            location: Location::File {
                path: self.location.to_string(),
                line,
            },
            evidence,
            run_id: self.run_id,
        }
    }

    fn error(&self, reason: String) -> ScanError {
        ScanError {
            location: self.location.to_string(),
            reason,
        }
    }
}

impl Collector {
    fn add_certs(&mut self, found: Vec<cert::Found>, ctx: &FileContext<'_>) {
        for item in found {
            let evidence = messages::EVIDENCE
                .replace("{subject}", &item.info.subject)
                .replace(
                    "{position}",
                    &item.info.chain_position.unwrap_or(0).to_string(),
                );
            let occurrence = ctx.occurrence(item.line, evidence);
            self.certs
                .entry(item.info.sha256.clone())
                .or_insert_with(|| Seen {
                    cert: item.info,
                    occurrences: Vec::new(),
                })
                .occurrences
                .push(occurrence);
        }
    }

    fn add_keys(&mut self, found: Vec<FoundKey>, ctx: &FileContext<'_>) {
        for key in found {
            let occurrence = ctx.occurrence(key.line, key.evidence.to_string());
            self.keys
                .entry(key.id.clone())
                .or_insert_with(|| SeenKey {
                    key,
                    occurrences: Vec::new(),
                })
                .occurrences
                .push(occurrence);
        }
    }
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
fn locked_item(data: &[u8], ctx: &FileContext<'_>) -> InventoryItem {
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
        occurrences: vec![ctx.occurrence(None, messages::ENCRYPTED_NOT_INSPECTED.to_string())],
    }
}

fn too_large(location: &str, limit: u64) -> ScanError {
    ScanError {
        location: location.to_string(),
        reason: messages::TOO_LARGE.replace("{limit}", &limit.to_string()),
    }
}

/// Fill the buffer from the reader. Return the number of bytes read.
///
/// The code never grows the buffer. A buffer that grows can leave a copy that nothing wipes.
fn fill(mut reader: impl Read, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match reader.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(count) => filled += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

/// Make a buffer of zeros that wipes itself on drop. The file can hold private keys.
fn wiped_buffer(size: u64) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![0u8; usize::try_from(size).unwrap_or(0)])
}

/// Scan one file.
pub(crate) fn scan_file(
    path: &Path,
    opts: &ScanOptions,
    run_id: Uuid,
    collector: &mut Collector,
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
    let named = sniff::by_name(path);
    // The tool reads a file with a known name in full. It reads the start of other files first.
    let read_all = named.is_some_and(|format| format != Format::Kbx);

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

    let changed = || ScanError {
        location: location.clone(),
        reason: messages::FILE_CHANGED.to_string(),
    };
    // A file with a known name needs the whole file. The tool reads the start of other files
    // into a small buffer first, and reads the rest only if the start shows a known format.
    let head_size = if read_all {
        if length > opts.max_file_size {
            errors.push(too_large(&location, opts.max_file_size));
            return Outcome::Failed;
        }
        length
    } else {
        length.min(SNIFF_BYTES.min(opts.max_file_size))
    };
    // One byte more than expected shows that the file grew after the size check.
    let mut data = wiped_buffer(head_size + 1);
    let head_length = match fill(&mut file, &mut data) {
        Ok(count) => count,
        Err(error) => {
            errors.push(cannot_read(error));
            return Outcome::Failed;
        }
    };
    data.truncate(head_length);
    if read_all && head_length as u64 > length {
        errors.push(changed());
        return Outcome::Failed;
    }
    let Some(format) = sniff::resolve(named, &data, sniff::has_key_extension(path)) else {
        // A file with a key-like name and other content has no keys.
        return if sniff::has_key_extension(path) {
            Outcome::NotRead
        } else {
            Outcome::Read
        };
    };
    let ctx = FileContext {
        location: &location,
        extension: &extension,
        run_id,
    };
    if format == Format::Kbx {
        errors.push(ctx.error(messages::KBX_UNSUPPORTED.to_string()));
        return Outcome::Failed;
    }
    if !read_all {
        if length > opts.max_file_size {
            errors.push(too_large(&location, opts.max_file_size));
            return Outcome::Failed;
        }
        // The full buffer has room for the whole file and one byte more. It never grows.
        let mut full = wiped_buffer(length + 1);
        full[..head_length].copy_from_slice(&data);
        let more = match fill(&mut file, &mut full[head_length..]) {
            Ok(count) => count,
            Err(error) => {
                errors.push(cannot_read(error));
                return Outcome::Failed;
            }
        };
        let total = head_length + more;
        if total as u64 > length {
            errors.push(changed());
            return Outcome::Failed;
        }
        full.truncate(total);
        // The small buffer wipes itself here.
        data = full;
    }

    match format {
        Format::Store(kind) => scan_store(kind, &data, opts, &ctx, collector, errors),
        Format::CertFile | Format::Pem => scan_pem(&data, &ctx, collector, errors),
        Format::DerKey => scan_der_key(&data, &ctx, collector, errors),
        Format::SshKeys => scan_ssh(&data, &ctx, collector, errors),
        Format::Pgp => scan_pgp(&data, &ctx, collector, errors),
        Format::Kbx => Outcome::Failed,
    }
}

/// Scan a PKCS#12 or Java key store.
fn scan_store(
    kind: StoreKind,
    data: &[u8],
    opts: &ScanOptions,
    ctx: &FileContext<'_>,
    collector: &mut Collector,
    errors: &mut Vec<ScanError>,
) -> Outcome {
    let result = match kind {
        StoreKind::Pkcs12 => pkcs12::scan_p12(data, &opts.passwords)
            .map(|scan| (into_found(scan.found), scan.errors)),
        StoreKind::Java => jks::scan_jks(data).map(|scan| (jks_certs(scan.found), scan.errors)),
    };
    match result {
        Ok((certs, reasons)) => {
            errors.extend(reasons.into_iter().map(|reason| ctx.error(reason)));
            collector.add_certs(certs, ctx);
            Outcome::Read
        }
        Err(pkcs12::StoreError::Encrypted) => {
            errors.push(ctx.error(messages::ENCRYPTED_NOT_INSPECTED.to_string()));
            collector.locked.push(locked_item(data, ctx));
            Outcome::NotRead
        }
        Err(error) => {
            errors.push(ctx.error(error.reason()));
            Outcome::Failed
        }
    }
}

/// The key blocks of a PEM file.
#[derive(Default)]
struct KeyBlocks {
    found: Vec<FoundKey>,
    bad: usize,
    total: usize,
    first_problem: Option<KeyProblem>,
}

/// Read the key blocks of a PEM text.
fn read_key_blocks(data: &[u8], ctx: &FileContext<'_>) -> KeyBlocks {
    let mut result = KeyBlocks::default();
    let blocks = pem::blocks(data);
    for (index, block) in blocks
        .blocks
        .iter()
        .filter(|block| block.kind == BlockKind::Key)
        .enumerate()
    {
        result.total += 1;
        let place = format!("{}#{index}", ctx.location);
        match privkey::parse_block(block, &place) {
            Ok(key) => result.found.push(key),
            Err(problem) => {
                result.bad += 1;
                result.first_problem.get_or_insert(problem);
            }
        }
    }
    if blocks.unclosed == Some(BlockKind::Key) {
        result.total += 1;
        result.bad += 1;
        result.first_problem.get_or_insert(KeyProblem::Invalid);
    }
    result
}

/// Make the error for key entries that are not valid.
fn invalid_entries(bad: usize, total: usize, problem: Option<KeyProblem>) -> String {
    messages::KEY_ENTRIES_INVALID
        .replace("{bad}", &bad.to_string())
        .replace("{total}", &total.to_string())
        .replace("{reason}", &problem.unwrap_or(KeyProblem::Invalid).reason())
}

/// Scan a file with PEM blocks: certificates, keys, or both.
fn scan_pem(
    data: &[u8],
    ctx: &FileContext<'_>,
    collector: &mut Collector,
    errors: &mut Vec<ScanError>,
) -> Outcome {
    if !cert::has_any_pem(data) {
        // The file has a certificate name but no PEM text.
        if ctx.extension == "pem" {
            errors.push(ctx.error(messages::NO_CERTIFICATE.to_string()));
        } else {
            return match cert::parse_der(data) {
                Ok(info) => {
                    collector.add_certs(vec![cert::Found { info, line: None }], ctx);
                    Outcome::Read
                }
                // Only a file that is not a certificate can be a key.
                Err(CertError::Invalid) => scan_der_key(data, ctx, collector, errors),
                Err(other) => {
                    errors.push(ctx.error(other.reason()));
                    Outcome::Read
                }
            };
        }
        return Outcome::Read;
    }
    let certs = cert::parse_pem(data);
    let keys = read_key_blocks(data, ctx);
    if certs.certs.is_empty() && certs.bad == 0 && keys.total == 0 {
        // Only blocks of other types.
        return Outcome::NotRead;
    }
    if certs.bad > 0 {
        let total = certs.bad + certs.certs.len();
        errors.push(
            ctx.error(
                messages::PEM_BLOCKS_INVALID
                    .replace("{bad}", &certs.bad.to_string())
                    .replace("{total}", &total.to_string())
                    .replace("{reason}", &certs.first_problem.unwrap_or_default()),
            ),
        );
    }
    if keys.bad > 0 {
        errors.push(ctx.error(invalid_entries(keys.bad, keys.total, keys.first_problem)));
    }
    collector.add_certs(certs.certs, ctx);
    collector.add_keys(keys.found, ctx);
    Outcome::Read
}

/// Scan a file with one key in DER form.
///
/// The error never holds bytes of the file.
fn scan_der_key(
    data: &[u8],
    ctx: &FileContext<'_>,
    collector: &mut Collector,
    errors: &mut Vec<ScanError>,
) -> Outcome {
    let place = format!("{}#0", ctx.location);
    match privkey::parse_der(data, &place) {
        Ok(key) => {
            collector.add_keys(vec![key], ctx);
            Outcome::Read
        }
        Err(KeyProblem::Invalid) => {
            errors.push(ctx.error(messages::DER_INVALID.to_string()));
            Outcome::Read
        }
        Err(problem) => {
            errors.push(ctx.error(problem.reason()));
            Outcome::Read
        }
    }
}

/// Scan a file with SSH public keys.
fn scan_ssh(
    data: &[u8],
    ctx: &FileContext<'_>,
    collector: &mut Collector,
    errors: &mut Vec<ScanError>,
) -> Outcome {
    let scan = ssh::scan_text(data);
    if scan.bad > 0 {
        errors.push(
            ctx.error(
                messages::KEY_LINES_INVALID
                    .replace("{bad}", &scan.bad.to_string())
                    .replace("{total}", &scan.total.to_string())
                    .replace("{line}", &scan.first_bad_line.unwrap_or(0).to_string()),
            ),
        );
    }
    collector.add_keys(scan.found, ctx);
    Outcome::Read
}

/// Scan a file with OpenPGP keys.
fn scan_pgp(
    data: &[u8],
    ctx: &FileContext<'_>,
    collector: &mut Collector,
    errors: &mut Vec<ScanError>,
) -> Outcome {
    let scan = if gpg::is_armored(data) {
        gpg::scan_armored(data)
    } else {
        gpg::scan_binary(data)
    };
    if scan.found.is_empty() && scan.bad == 0 {
        // No key packets, for example a signature or an encrypted message.
        return Outcome::NotRead;
    }
    if scan.bad > 0 {
        errors.push(ctx.error(invalid_entries(scan.bad, scan.total, scan.first_problem)));
    }
    collector.add_keys(scan.found, ctx);
    Outcome::Read
}
