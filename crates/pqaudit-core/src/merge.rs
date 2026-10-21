//! Merge results files and remove sensitive text from them.

use crate::finding::{
    CertInfo, EndpointInfo, Finding, InventoryItem, KeyInfo, Location, Occurrence, ScanError,
    SshObservation, TlsObservation,
};
use crate::fingerprint::{finding_id, Fingerprint};
use crate::messages;
use crate::results::{PackOriginRef, PackRef, ResultsFile, ResultsHeader, RunInfo, ScannerKind};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Write;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use uuid::Uuid;

/// The location of the warning that a merge adds to the error list.
pub const MERGE_WARNING_LOCATION: &str = "merge";

/// The start of each redacted value.
const REDACTED_PREFIX: &str = "redacted:";

/// The number of hex digits after the prefix of a redacted value.
const REDACTED_DIGITS: usize = 12;

/// The most bytes that the tool reads from a key file.
const KEY_FILE_READ_LIMIT: u64 = 256;

/// An error when the tool merges results files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeError {
    /// The call has no input files.
    NoInputs,
    /// Two files belong to different engagements.
    EngagementMismatch {
        /// The engagement of the first file.
        first: String,
        /// The other engagement.
        other: String,
    },
    /// The inputs are a mix of redacted files and plain files.
    MixedRedaction,
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NoInputs => messages::MERGE_NO_INPUTS.to_string(),
            Self::MixedRedaction => messages::MERGE_MIXED_REDACTION.to_string(),
            Self::EngagementMismatch { first, other } => messages::MERGE_ENGAGEMENT_MISMATCH
                .replace("{first}", first)
                .replace("{other}", other),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for MergeError {}

/// An error when the tool reads or makes a redaction key.
#[derive(Debug)]
pub enum RedactKeyError {
    /// The tool cannot read or write the key file.
    Io {
        /// The path of the key file.
        path: String,
        /// The reason.
        reason: String,
    },
    /// The key file does not hold 64 hex digits.
    Invalid {
        /// The path of the key file.
        path: String,
    },
    /// The system cannot give random bytes.
    Random(String),
}

impl std::fmt::Display for RedactKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Io { path, reason } => messages::REDACT_KEY_IO
                .replace("{path}", path)
                .replace("{reason}", reason),
            Self::Invalid { path } => messages::REDACT_KEY_INVALID.replace("{path}", path),
            Self::Random(reason) => messages::REDACT_KEY_RANDOM.replace("{reason}", reason),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for RedactKeyError {}

/// The secret key of a redaction. The same key gives the same redacted values.
#[derive(Clone, PartialEq, Eq)]
pub struct RedactKey([u8; 32]);

impl std::fmt::Debug for RedactKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactKey(..)")
    }
}

impl RedactKey {
    /// Make a key from 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Read a key file. The file holds 64 hex digits.
    pub fn load(path: &Path) -> Result<Self, RedactKeyError> {
        let shown = path.display().to_string();
        let io = |e: std::io::Error| RedactKeyError::Io {
            path: shown.clone(),
            reason: e.to_string(),
        };
        // Check the type before the open call. The open call of a FIFO can wait for ever.
        if !std::fs::metadata(path).map_err(io)?.is_file() {
            return Err(RedactKeyError::Invalid { path: shown });
        }
        let file = std::fs::File::open(path).map_err(io)?;
        if !file.metadata().map_err(io)?.is_file() {
            return Err(RedactKeyError::Invalid { path: shown });
        }
        let mut raw = Vec::new();
        file.take(KEY_FILE_READ_LIMIT)
            .read_to_end(&mut raw)
            .map_err(io)?;
        let digits = match raw.as_slice() {
            [digits @ .., b'\n'] if digits.len() == 64 => digits,
            digits if digits.len() == 64 => digits,
            _ => return Err(RedactKeyError::Invalid { path: shown }),
        };
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(RedactKeyError::Invalid { path: shown });
        }
        let text = std::str::from_utf8(digits).expect("hex digits are ASCII");
        let mut bytes = [0u8; 32];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| {
                RedactKeyError::Invalid {
                    path: shown.clone(),
                }
            })?;
        }
        Ok(Self(bytes))
    }

    /// Read the key file. If the file does not exist, make a new random key and write it.
    ///
    /// On Unix the new file has the mode 0600.
    pub fn load_or_create(path: &Path) -> Result<Self, RedactKeyError> {
        match std::fs::symlink_metadata(path) {
            Ok(_) => return Self::load(path),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(RedactKeyError::Io {
                    path: path.display().to_string(),
                    reason: e.to_string(),
                })
            }
        }
        let io = |e: std::io::Error| RedactKeyError::Io {
            path: path.display().to_string(),
            reason: e.to_string(),
        };
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes).map_err(|e| RedactKeyError::Random(e.to_string()))?;
        let mut text = String::with_capacity(65);
        for byte in bytes {
            write!(text, "{byte:02x}").expect("writing to a String cannot fail");
        }
        text.push('\n');
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).map_err(io)?;
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let mut file = options.open(path).map_err(io)?;
        std::io::Write::write_all(&mut file, text.as_bytes()).map_err(io)?;
        Ok(Self(bytes))
    }

    /// The keyed hash (HMAC-SHA256) of a value in one domain.
    fn mac(&self, domain: &str, value: &str) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.0).expect("HMAC takes any key size");
        mac.update(domain.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

/// Merge results files into one file.
///
/// Findings and inventory items with the same fingerprint become one item.
/// The output does not depend on the order of the inputs.
/// The inputs must be of one kind: all redacted, or all plain.
pub fn merge(mut inputs: Vec<ResultsFile>) -> Result<ResultsFile, MergeError> {
    if inputs.is_empty() {
        return Err(MergeError::NoInputs);
    }
    inputs.sort_by_key(|f| {
        (
            f.header.started,
            f.header.runs.first().map_or(Uuid::nil(), |r| r.run_id),
        )
    });
    check_engagement(&inputs)?;

    let mut header = inputs[0].header.clone();
    header.runs = Vec::new();
    header.redacted = inputs.iter().all(|f| f.header.redacted);
    header.started = inputs
        .iter()
        .map(|f| f.header.started)
        .min()
        .unwrap_or(header.started);
    header.finished = inputs
        .iter()
        .map(|f| f.header.finished)
        .max()
        .unwrap_or(header.finished);
    if inputs.iter().any(|f| f.header.host != header.host) {
        header.host = messages::MERGED_VALUE.into();
    }
    if inputs.iter().any(|f| f.header.operator != header.operator) {
        header.operator = messages::MERGED_VALUE.into();
    }
    let packs: Vec<PackRef> = inputs.iter().map(|f| f.header.rules_pack.clone()).collect();

    let mut findings: Vec<Finding> = Vec::new();
    let mut finding_index: HashMap<Fingerprint, usize> = HashMap::new();
    let mut items: Vec<InventoryItem> = Vec::new();
    let mut item_index: HashMap<Fingerprint, usize> = HashMap::new();
    let mut errors: Vec<ScanError> = Vec::new();
    let mut seen_errors: HashSet<(String, String)> = HashSet::new();
    let mut seen_runs: HashSet<Uuid> = HashSet::new();
    let mut scope_hashes: BTreeSet<String> = BTreeSet::new();
    let mut audit_hashes: BTreeSet<String> = BTreeSet::new();
    for file in inputs {
        // A file with no hash in its runs gives the hash of its header.
        let run_scope = file.header.runs.iter().filter_map(|r| r.scope_hash.clone());
        scope_hashes.extend(run_scope);
        if file.header.runs.iter().all(|r| r.scope_hash.is_none()) {
            scope_hashes.extend(file.header.scope_hash.clone());
        }
        let run_audit = file
            .header
            .runs
            .iter()
            .filter_map(|r| r.audit_log_hash.clone());
        audit_hashes.extend(run_audit);
        if file.header.runs.iter().all(|r| r.audit_log_hash.is_none()) {
            audit_hashes.extend(file.header.audit_log_hash.clone());
        }
        for run in file.header.runs {
            if seen_runs.insert(run.run_id) {
                header.runs.push(run);
            }
        }
        for finding in file.findings {
            add_finding(&mut findings, &mut finding_index, finding);
        }
        for item in file.inventory {
            add_item(&mut items, &mut item_index, item);
        }
        for error in file.errors {
            add_error(&mut errors, &mut seen_errors, error);
        }
    }

    for finding in &mut findings {
        normalize_occurrences(&mut finding.occurrences);
        finding.also.sort();
        finding.also.dedup();
    }
    for item in &mut items {
        normalize_occurrences(&mut item.occurrences);
    }
    findings.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    items.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    for finding in &mut findings {
        finding.id = finding_id(&finding.fingerprint);
    }

    let (best, warnings) = choose_pack(&packs);
    header.rules_pack = best;
    for reason in warnings {
        add_error(
            &mut errors,
            &mut seen_errors,
            ScanError {
                location: MERGE_WARNING_LOCATION.into(),
                reason,
            },
        );
    }
    header.scanner = ScannerKind::Merged;
    header.scope_hash = single(scope_hashes);
    header.audit_log_hash = single(audit_hashes);
    Ok(ResultsFile {
        header,
        findings,
        inventory: items,
        errors,
    })
}

/// Check that the files have one engagement and one kind: all redacted, or all plain.
fn check_engagement(inputs: &[ResultsFile]) -> Result<(), MergeError> {
    let first = &inputs[0].header;
    if inputs.iter().any(|f| f.header.redacted != first.redacted) {
        return Err(MergeError::MixedRedaction);
    }
    match inputs[1..]
        .iter()
        .find(|f| f.header.engagement != first.engagement)
    {
        Some(file) => Err(MergeError::EngagementMismatch {
            first: first.engagement.clone(),
            other: file.header.engagement.clone(),
        }),
        None => Ok(()),
    }
}

/// The one value in a set. If the set has two values or none, return `None`.
fn single(values: BTreeSet<String>) -> Option<String> {
    if values.len() == 1 {
        values.into_iter().next()
    } else {
        None
    }
}

/// Sort the occurrences and remove the duplicates by (run, location).
fn normalize_occurrences(occurrences: &mut Vec<Occurrence>) {
    let mut keyed: Vec<(String, Occurrence)> = occurrences
        .drain(..)
        .map(|o| {
            let location = serde_json::to_string(&o.location).unwrap_or_default();
            (format!("{}|{location}", o.run_id), o)
        })
        .collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    keyed.dedup_by(|a, b| a.0 == b.0);
    occurrences.extend(keyed.into_iter().map(|(_, o)| o));
}

fn add_error(errors: &mut Vec<ScanError>, seen: &mut HashSet<(String, String)>, error: ScanError) {
    if seen.insert((error.location.clone(), error.reason.clone())) {
        errors.push(error);
    }
}

fn add_finding(findings: &mut Vec<Finding>, index: &mut HashMap<Fingerprint, usize>, new: Finding) {
    let Some(&at) = index.get(&new.fingerprint) else {
        index.insert(new.fingerprint.clone(), findings.len());
        findings.push(new);
        return;
    };
    let old = &mut findings[at];
    let mut also = new.also;
    if new.rule_id != old.rule_id {
        also.push(new.rule_id);
    }
    for rule in also {
        if rule != old.rule_id && !old.also.contains(&rule) {
            old.also.push(rule);
        }
    }
    old.occurrences.extend(new.occurrences);
    old.algorithm = old.algorithm.take().or(new.algorithm);
    old.cert = old.cert.take().or(new.cert);
    old.key = old.key.take().or(new.key);
    old.endpoint = old.endpoint.take().or(new.endpoint);
}

fn add_item(
    items: &mut Vec<InventoryItem>,
    index: &mut HashMap<Fingerprint, usize>,
    new: InventoryItem,
) {
    let Some(&at) = index.get(&new.fingerprint) else {
        index.insert(new.fingerprint.clone(), items.len());
        items.push(new);
        return;
    };
    let old = &mut items[at];
    old.pq_ready &= new.pq_ready;
    old.occurrences.extend(new.occurrences);
    old.algorithm = old.algorithm.take().or(new.algorithm);
    old.cert = old.cert.take().or(new.cert);
    old.key = old.key.take().or(new.key);
    old.endpoint = old.endpoint.take().or(new.endpoint);
}

/// Choose the pack with the highest version. Return a warning text for each problem.
///
/// The packs can differ. Or an input can use the chosen pack without a valid signature.
/// In that case the merged file records the pack as unsigned.
fn choose_pack(packs: &[PackRef]) -> (PackRef, Vec<String>) {
    let rank = |p: &PackRef| {
        (
            semver::Version::parse(&p.version).ok(),
            p.content_hash.clone(),
            p.id.clone(),
        )
    };
    let mut best = packs
        .iter()
        .max_by_key(|p| rank(p))
        .expect("a merge has at least one pack")
        .clone();
    let same_pack = |p: &PackRef| {
        p.id == best.id && p.version == best.version && p.content_hash == best.content_hash
    };
    let mut warnings = Vec::new();
    let mut names: Vec<String> = packs
        .iter()
        .map(|p| format!("{} {}", p.id, p.version))
        .collect();
    names.sort();
    names.dedup();
    if packs.iter().any(|p| !same_pack(p)) {
        warnings.push(messages::MERGE_PACK_MISMATCH.replace("{versions}", &names.join(", ")));
    }
    let unsigned = packs
        .iter()
        .filter(|p| same_pack(p))
        .find(|p| matches!(p.origin, PackOriginRef::Unsigned { .. }));
    if let Some(unsigned) = unsigned {
        warnings.push(
            messages::MERGE_UNSIGNED_PACK
                .replace("{pack}", &format!("{} {}", best.id, best.version)),
        );
        best.origin = unsigned.origin.clone();
    }
    (best, warnings)
}

/// True if the text is `redacted:` and 12 lowercase hex digits.
fn is_redacted_shape(value: &str) -> bool {
    value.strip_prefix(REDACTED_PREFIX).is_some_and(|digits| {
        digits.len() == REDACTED_DIGITS
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// Make the redacted form of a value: `redacted:` and 12 hex digits of its keyed hash.
///
/// A value that already has this exact form stays as it is.
/// The engagement name in a redacted header has this form.
pub fn redacted(value: &str, key: &RedactKey) -> String {
    if is_redacted_shape(value) {
        return value.to_string();
    }
    let mac = key.mac("text", value);
    let mut text = String::from(REDACTED_PREFIX);
    for byte in &mac[..REDACTED_DIGITS / 2] {
        write!(text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

/// Make the keyed form of a fingerprint. The kind prefix stays.
///
/// The hex part becomes 32 hex digits of the keyed hash of the full fingerprint.
/// The same key gives the same value, so merge can join redacted files.
pub fn keyed_fingerprint(fingerprint: &Fingerprint, key: &RedactKey) -> Fingerprint {
    let mac = key.mac("fingerprint", &fingerprint.0);
    let mut hex = String::with_capacity(32);
    for byte in &mac[..16] {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    match fingerprint.0.split_once(':') {
        Some((kind, _)) => Fingerprint(format!("{kind}:{hex}")),
        None => Fingerprint(hex),
    }
}

/// Replace a hash of public material with 64 hex digits of its keyed hash.
///
/// A person can compare a plain hash with a known certificate or key. An empty value stays empty.
fn hide_hash(value: &mut String, key: &RedactKey) {
    if value.is_empty() {
        return;
    }
    let mac = key.mac("fingerprint", value);
    let mut hex = String::with_capacity(64);
    for byte in mac {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    *value = hex;
}

/// Replace a fingerprint with its keyed form. Then make the finding ID again from it.
fn hide_fingerprint(fingerprint: &mut Fingerprint, key: &RedactKey) {
    *fingerprint = keyed_fingerprint(fingerprint, key);
}

fn hide(value: &mut String, key: &RedactKey) {
    *value = redacted(value, key);
}

/// Redact a host name. Host names are not case sensitive, so the hash uses lower case.
fn hide_host(value: &mut String, key: &RedactKey) {
    *value = redacted(&value.to_lowercase(), key);
}

fn hide_opt(value: &mut Option<String>, key: &RedactKey) {
    if let Some(v) = value {
        hide(v, key);
    }
}

/// Map an address to a stable address in a range for documents and tests.
///
/// IPv4 goes to 198.18.0.0/15. IPv6 goes to 2001:db8::/32.
fn map_ip(ip: IpAddr, key: &RedactKey) -> IpAddr {
    let mac = key.mac("ip", &ip.to_string());
    match ip {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::new(198, 18 | (mac[0] & 1), mac[1], mac[2])),
        IpAddr::V6(_) => {
            let mut octets = [0u8; 16];
            octets[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            octets[4..].copy_from_slice(&mac[..12]);
            IpAddr::V6(Ipv6Addr::from(octets))
        }
    }
}

/// Replace each host name, address, path, subject, issuer, banner, and key comment.
///
/// The functions below name every field of every type. A new field makes the build fail
/// until the author decides if it is sensitive.
///
/// Each fingerprint, certificate hash, and key hash becomes a keyed hash.
/// Each finding ID comes again from the keyed fingerprint.
/// An IP address cannot hold text. It becomes a keyed address in a reserved range.
/// If the file is already redacted, this function does nothing.
pub fn redact(file: &mut ResultsFile, key: &RedactKey) {
    if file.header.redacted {
        return;
    }
    let ResultsFile {
        header,
        findings,
        inventory,
        errors,
    } = file;
    let ResultsHeader {
        schema_version: _,
        engagement,
        tool_version: _,
        rules_pack,
        scanner: _,
        host,
        operator,
        started: _,
        finished: _,
        scope_hash: _,
        audit_log_hash: _,
        runs,
        redacted: is_redacted,
    } = header;
    let PackRef {
        id: _,
        version: _,
        content_hash: _,
        origin,
    } = rules_pack;
    match origin {
        PackOriginRef::Embedded => {}
        PackOriginRef::Installed {
            path,
            signed_by: _,
            rotation_chain: _,
        }
        | PackOriginRef::Unsigned { path } => hide(path, key),
    }
    hide(engagement, key);
    hide_host(host, key);
    hide(operator, key);
    for run in runs {
        let RunInfo {
            run_id: _,
            scanner: _,
            host,
            started: _,
            scope_hash: _,
            audit_log_hash: _,
        } = run;
        hide_host(host, key);
    }
    *is_redacted = true;

    for finding in findings {
        let Finding {
            id,
            fingerprint,
            rule_id: _,
            source: _,
            algorithm: _,
            purpose: _,
            threat_type: _,
            agility: _,
            fix_owner: _,
            also: _,
            occurrences,
            cert,
            key: key_info,
            endpoint,
        } = finding;
        hide_fingerprint(fingerprint, key);
        *id = finding_id(fingerprint);
        redact_occurrences(occurrences, key);
        redact_facts(cert, key_info, endpoint, key);
    }
    for item in inventory {
        let InventoryItem {
            kind: _,
            fingerprint,
            pq_ready: _,
            algorithm: _,
            cert,
            key: key_info,
            endpoint,
            occurrences,
        } = item;
        hide_fingerprint(fingerprint, key);
        redact_occurrences(occurrences, key);
        redact_facts(cert, key_info, endpoint, key);
    }
    for error in errors {
        let ScanError { location, reason } = error;
        hide(location, key);
        hide(reason, key);
    }
}

fn redact_occurrences(occurrences: &mut [Occurrence], key: &RedactKey) {
    for occurrence in occurrences {
        let Occurrence {
            location,
            evidence,
            run_id: _,
        } = occurrence;
        hide(evidence, key);
        match location {
            Location::File { path, line: _ } => hide(path, key),
            Location::Endpoint {
                host,
                ip,
                port: _,
                protocol: _,
            } => {
                hide_host(host, key);
                *ip = map_ip(*ip, key);
            }
        }
    }
}

fn redact_facts(
    cert: &mut Option<CertInfo>,
    key_info: &mut Option<KeyInfo>,
    endpoint: &mut Option<EndpointInfo>,
    key: &RedactKey,
) {
    if let Some(CertInfo {
        sha256,
        subject,
        issuer,
        not_before: _,
        not_after: _,
        is_ca: _,
        key_usage: _,
        ext_key_usage: _,
        public_key: _,
        signature_algorithm: _,
        chain_position: _,
    }) = cert
    {
        hide_hash(sha256, key);
        hide(subject, key);
        hide(issuer, key);
    }
    if let Some(KeyInfo {
        fingerprint_sha256,
        kind: _,
        algorithm: _,
        comment,
    }) = key_info
    {
        hide_hash(fingerprint_sha256, key);
        hide_opt(comment, key);
    }
    if let Some(EndpointInfo {
        protocol: _,
        tls,
        ssh,
    }) = endpoint
    {
        if let Some(TlsObservation {
            pq_hybrid_supported: _,
            negotiated_version: _,
            negotiated_group: _,
            cipher_suite: _,
            legacy_versions: _,
            errors,
        }) = tls
        {
            errors.iter_mut().for_each(|e| hide(e, key));
        }
        if let Some(SshObservation {
            banner,
            kex: _,
            host_key_algorithms: _,
            ciphers: _,
            macs: _,
        }) = ssh
        {
            hide(banner, key);
        }
    }
}
