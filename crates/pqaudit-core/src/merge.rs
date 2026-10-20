//! Merge results files and remove sensitive text from them.

use crate::finding::{
    CertInfo, EndpointInfo, Finding, InventoryItem, KeyInfo, Location, Occurrence, ScanError,
    SshObservation, TlsObservation,
};
use crate::messages;
use crate::results::{PackOriginRef, PackRef, ResultsFile, RunInfo, ScannerKind};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt::Write;
use std::net::IpAddr;

/// The location of the warning that a merge adds to the error list.
pub const MERGE_WARNING_LOCATION: &str = "merge";

/// The start of each redacted value.
const REDACTED_PREFIX: &str = "redacted:";

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
}

impl std::fmt::Display for MergeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NoInputs => messages::MERGE_NO_INPUTS.to_string(),
            Self::EngagementMismatch { first, other } => messages::MERGE_ENGAGEMENT_MISMATCH
                .replace("{first}", first)
                .replace("{other}", other),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for MergeError {}

/// Merge results files into one file.
///
/// Findings and inventory items with the same fingerprint become one item.
/// The output keeps the order of first appearance.
pub fn merge(inputs: Vec<ResultsFile>) -> Result<ResultsFile, MergeError> {
    let mut iter = inputs.into_iter();
    let mut out = iter.next().ok_or(MergeError::NoInputs)?;
    let rest: Vec<ResultsFile> = iter.collect();
    for file in &rest {
        if file.header.engagement != out.header.engagement {
            return Err(MergeError::EngagementMismatch {
                first: out.header.engagement.clone(),
                other: file.header.engagement.clone(),
            });
        }
    }

    let mut packs = vec![out.header.rules_pack.clone()];
    let mut all_redacted = out.header.redacted;
    for file in rest {
        let h = file.header;
        packs.push(h.rules_pack);
        all_redacted &= h.redacted;
        out.header.started = out.header.started.min(h.started);
        out.header.finished = out.header.finished.max(h.finished);
        if out.header.host != h.host {
            out.header.host = "merged".into();
        }
        if out.header.operator != h.operator {
            out.header.operator = "merged".into();
        }
        if out.header.scope_hash != h.scope_hash {
            out.header.scope_hash = None;
        }
        if out.header.audit_log_hash != h.audit_log_hash {
            out.header.audit_log_hash = None;
        }
        for run in h.runs {
            out.header.runs.push(run);
        }
        for finding in file.findings {
            add_finding(&mut out.findings, finding);
        }
        for item in file.inventory {
            add_item(&mut out.inventory, item);
        }
        for error in file.errors {
            add_error(&mut out.errors, error);
        }
    }
    dedupe_runs(&mut out.header.runs);
    for finding in &mut out.findings {
        dedupe_occurrences(&mut finding.occurrences);
    }
    for item in &mut out.inventory {
        dedupe_occurrences(&mut item.occurrences);
    }

    let (best, warning) = choose_pack(&packs);
    out.header.rules_pack = best;
    if let Some(reason) = warning {
        add_error(
            &mut out.errors,
            ScanError {
                location: MERGE_WARNING_LOCATION.into(),
                reason,
            },
        );
    }
    out.header.scanner = ScannerKind::Merged;
    out.header.redacted = all_redacted;
    for (index, finding) in out.findings.iter_mut().enumerate() {
        finding.id = format!("F-{:04}", index + 1);
    }
    Ok(out)
}

fn dedupe_runs(runs: &mut Vec<RunInfo>) {
    let mut seen = HashSet::new();
    runs.retain(|run| seen.insert(run.run_id));
}

fn dedupe_occurrences(occurrences: &mut Vec<Occurrence>) {
    let mut seen: Vec<(Location, uuid::Uuid)> = Vec::new();
    occurrences.retain(|o| {
        let key = (o.location.clone(), o.run_id);
        if seen.contains(&key) {
            false
        } else {
            seen.push(key);
            true
        }
    });
}

fn add_error(errors: &mut Vec<ScanError>, error: ScanError) {
    if !errors.contains(&error) {
        errors.push(error);
    }
}

fn add_finding(findings: &mut Vec<Finding>, new: Finding) {
    let Some(old) = findings
        .iter_mut()
        .find(|f| f.fingerprint == new.fingerprint)
    else {
        findings.push(new);
        return;
    };
    let mut also = new.also;
    if new.rule_id != old.rule_id {
        also.insert(0, new.rule_id);
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

fn add_item(items: &mut Vec<InventoryItem>, new: InventoryItem) {
    let Some(old) = items.iter_mut().find(|i| i.fingerprint == new.fingerprint) else {
        items.push(new);
        return;
    };
    old.pq_ready &= new.pq_ready;
    old.occurrences.extend(new.occurrences);
    old.algorithm = old.algorithm.take().or(new.algorithm);
    old.cert = old.cert.take().or(new.cert);
    old.key = old.key.take().or(new.key);
    old.endpoint = old.endpoint.take().or(new.endpoint);
}

/// Choose the pack with the highest version. Return a warning text if the packs differ.
fn choose_pack(packs: &[PackRef]) -> (PackRef, Option<String>) {
    let version = |p: &PackRef| semver::Version::parse(&p.version).ok();
    let mut best = &packs[0];
    for pack in &packs[1..] {
        if version(pack) > version(best) {
            best = pack;
        }
    }
    let mut names: Vec<String> = packs
        .iter()
        .map(|p| format!("{} {}", p.id, p.version))
        .collect();
    names.sort();
    names.dedup();
    let differs = packs.iter().any(|p| {
        p.id != best.id || p.version != best.version || p.content_hash != best.content_hash
    });
    let warning =
        differs.then(|| messages::MERGE_PACK_MISMATCH.replace("{versions}", &names.join(", ")));
    (best.clone(), warning)
}

/// Make the redacted form of a value: `redacted:` and 12 hex digits of its SHA-256 hash.
fn redacted(value: &str) -> String {
    if value.starts_with(REDACTED_PREFIX) {
        return value.to_string();
    }
    let digest = Sha256::digest(value.as_bytes());
    let mut text = String::from(REDACTED_PREFIX);
    for byte in &digest[..6] {
        write!(text, "{byte:02x}").expect("writing to a String cannot fail");
    }
    text
}

fn hide(value: &mut String) {
    *value = redacted(value);
}

fn hide_opt(value: &mut Option<String>) {
    if let Some(v) = value {
        hide(v);
    }
}

/// Replace each host name, address, path, subject, issuer, banner, and key comment.
///
/// The functions below name every field of every type. A new field makes the build fail
/// until the author decides if it is sensitive. The fingerprints and hashes stay.
/// An IP address cannot hold text. It becomes the unspecified address of its family.
pub fn redact(file: &mut ResultsFile) {
    let ResultsFile {
        header,
        findings,
        inventory,
        errors,
    } = file;
    let crate::results::ResultsHeader {
        schema_version: _,
        engagement: _,
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
        | PackOriginRef::Unsigned { path } => hide(path),
    }
    hide(host);
    hide(operator);
    for run in runs {
        let RunInfo {
            run_id: _,
            scanner: _,
            host,
            started: _,
        } = run;
        hide(host);
    }
    *is_redacted = true;

    for finding in findings {
        let Finding {
            id: _,
            fingerprint: _,
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
            key,
            endpoint,
        } = finding;
        redact_occurrences(occurrences);
        redact_facts(cert, key, endpoint);
    }
    for item in inventory {
        let InventoryItem {
            kind: _,
            fingerprint: _,
            pq_ready: _,
            algorithm: _,
            cert,
            key,
            endpoint,
            occurrences,
        } = item;
        redact_occurrences(occurrences);
        redact_facts(cert, key, endpoint);
    }
    for error in errors {
        let ScanError { location, reason } = error;
        hide(location);
        hide(reason);
    }
}

fn redact_occurrences(occurrences: &mut [Occurrence]) {
    for occurrence in occurrences {
        let Occurrence {
            location,
            evidence,
            run_id: _,
        } = occurrence;
        hide(evidence);
        match location {
            Location::File { path, line: _ } => hide(path),
            Location::Endpoint {
                host,
                ip,
                port: _,
                protocol: _,
            } => {
                hide(host);
                *ip = match ip {
                    IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                };
            }
        }
    }
}

fn redact_facts(
    cert: &mut Option<CertInfo>,
    key: &mut Option<KeyInfo>,
    endpoint: &mut Option<EndpointInfo>,
) {
    if let Some(CertInfo {
        sha256: _,
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
        hide(subject);
        hide(issuer);
    }
    if let Some(KeyInfo {
        fingerprint_sha256: _,
        kind: _,
        algorithm: _,
        comment,
    }) = key
    {
        hide_opt(comment);
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
            errors.iter_mut().for_each(hide);
        }
        if let Some(SshObservation {
            banner,
            kex: _,
            host_key_algorithms: _,
            ciphers: _,
            macs: _,
        }) = ssh
        {
            hide(banner);
        }
    }
}
