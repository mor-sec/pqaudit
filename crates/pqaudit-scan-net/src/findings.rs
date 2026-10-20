//! Turn the probe results into findings, inventory items, and scan errors.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use chrono::Utc;
use pqaudit_core::classify::classify_cert;
use pqaudit_core::{
    Agility, Algorithm, CertInfo, EndpointInfo, Finding, Fingerprint, FixOwner, InventoryItem,
    InventoryKind, Location, Occurrence, Protocol, Purpose, ScanError, Source, ThreatType,
    TlsObservation,
};
use pqaudit_rules::pack::RulesPack;
use uuid::Uuid;

use crate::messages;
use crate::runtime::{NetOutput, TargetResult};
use crate::scope::PlannedTarget;

/// The ID of the rule for a server without a post-quantum key exchange.
pub const RULE_NO_PQ_KEX: &str = "tls.no-pq-kex";
/// The ID of the rule for a server that accepts an old protocol version.
pub const RULE_LEGACY_VERSION: &str = "tls.legacy-version";

/// A certificate and the endpoints where the tool saw it.
struct SeenCert {
    cert: CertInfo,
    occurrences: Vec<Occurrence>,
}

/// Collect the output of a scan, in the order of the plan.
struct Builder<'a> {
    pack: &'a RulesPack,
    run_id: Uuid,
    output: NetOutput,
    certs: BTreeMap<String, SeenCert>,
    count: usize,
}

/// Make the output of a scan from the results of the probes.
pub(crate) fn build(
    targets: &[PlannedTarget],
    results: Vec<Option<TargetResult>>,
    run_id: Uuid,
    pack: &RulesPack,
) -> NetOutput {
    let mut builder = Builder {
        pack,
        run_id,
        output: NetOutput::default(),
        certs: BTreeMap::new(),
        count: 0,
    };
    for (target, result) in targets.iter().zip(results) {
        match result {
            None => builder.error(target, messages::TARGET_STOPPED.to_string()),
            Some(TargetResult::Tls(result)) => {
                builder.tls(target, result.obs, result.chain, result.failures);
            }
            // The SSH findings come with the SSH probe.
            Some(TargetResult::Ssh(Ok(_))) => {}
            Some(TargetResult::Ssh(Err(reason))) => builder.error(target, reason),
        }
    }
    builder.finish()
}

/// The name of a target for the user: the host name, or the IP address.
fn display_host(t: &PlannedTarget) -> String {
    t.host.clone().unwrap_or_else(|| t.ip.to_string())
}

/// The place of a target as text, for example `[::1]:443`.
fn address_text(ip: IpAddr, port: u16) -> String {
    SocketAddr::new(ip, port).to_string()
}

fn is_pq_ready(pack: &RulesPack, name: &str) -> bool {
    pack.algorithm(name)
        .is_some_and(|fact| !fact.quantum_vulnerable)
}

impl Builder<'_> {
    fn next_id(&mut self) -> String {
        self.count += 1;
        format!("net-{}", self.count)
    }

    fn error(&mut self, t: &PlannedTarget, reason: String) {
        let location = match &t.host {
            Some(host) => format!("{host} ({})", address_text(t.ip, t.port)),
            None => address_text(t.ip, t.port),
        };
        self.output.errors.push(ScanError { location, reason });
    }

    fn occurrence(&self, t: &PlannedTarget, evidence: String) -> Occurrence {
        Occurrence {
            location: Location::Endpoint {
                host: display_host(t),
                ip: t.ip,
                port: t.port,
                protocol: t.protocol,
            },
            evidence,
            run_id: self.run_id,
        }
    }

    fn threat(&self, rule_id: &str, fallback: ThreatType) -> ThreatType {
        self.pack
            .rule(rule_id)
            .and_then(|rule| rule.threat_type)
            .unwrap_or(fallback)
    }

    fn tls(
        &mut self,
        t: &PlannedTarget,
        obs: TlsObservation,
        chain: Vec<CertInfo>,
        failures: Vec<String>,
    ) {
        let host = display_host(t);
        let endpoint = EndpointInfo {
            protocol: Protocol::Tls,
            tls: Some(obs.clone()),
            ssh: None,
        };
        // A failure that stops part of the probe is an error. The scan then exits with 3.
        if !failures.is_empty() {
            self.error(t, failures.join(" "));
        } else if obs.negotiated_version.is_none() && chain.is_empty() {
            let reason = if obs.errors.is_empty() {
                messages::NO_HANDSHAKE.to_string()
            } else {
                obs.errors.join(" ")
            };
            self.error(t, reason);
        }
        if obs.pq_hybrid_supported == Some(false) {
            let group = obs
                .negotiated_group
                .clone()
                .unwrap_or_else(|| messages::UNKNOWN_VALUE.to_string());
            let evidence = messages::EVIDENCE_NO_PQ.replace("{group}", &group);
            let finding = Finding {
                id: self.next_id(),
                fingerprint: Fingerprint::endpoint(&host, t.port, RULE_NO_PQ_KEX),
                rule_id: RULE_NO_PQ_KEX.to_string(),
                source: Source::Net,
                algorithm: obs.negotiated_group.as_ref().map(|name| Algorithm {
                    name: name.clone(),
                    key_bits: None,
                    curve: None,
                }),
                purpose: Purpose::KeyExchange,
                threat_type: self.threat(RULE_NO_PQ_KEX, ThreatType::Hndl),
                agility: Agility::Unknown,
                fix_owner: FixOwner::Unknown,
                also: Vec::new(),
                occurrences: vec![self.occurrence(t, evidence)],
                cert: None,
                key: None,
                endpoint: Some(endpoint.clone()),
            };
            self.output.findings.push(finding);
        }
        if let Some(versions) = obs.legacy_versions.as_ref().filter(|v| !v.is_empty()) {
            let evidence = messages::EVIDENCE_LEGACY.replace("{versions}", &versions.join(", "));
            let finding = Finding {
                id: self.next_id(),
                fingerprint: Fingerprint::endpoint(&host, t.port, RULE_LEGACY_VERSION),
                rule_id: RULE_LEGACY_VERSION.to_string(),
                source: Source::Net,
                algorithm: None,
                purpose: Purpose::Unknown,
                threat_type: self.threat(RULE_LEGACY_VERSION, ThreatType::ClassicalWeakNow),
                agility: Agility::Unknown,
                fix_owner: FixOwner::Unknown,
                also: Vec::new(),
                occurrences: vec![self.occurrence(t, evidence)],
                cert: None,
                key: None,
                endpoint: Some(endpoint.clone()),
            };
            self.output.findings.push(finding);
        }
        if obs.pq_hybrid_supported == Some(true) {
            let occurrence = self.occurrence(t, messages::EVIDENCE_PQ_READY.to_string());
            self.output.inventory.push(InventoryItem {
                kind: InventoryKind::Endpoint,
                fingerprint: Fingerprint::endpoint(&host, t.port, "tls"),
                pq_ready: true,
                algorithm: obs.negotiated_group.as_ref().map(|name| Algorithm {
                    name: name.clone(),
                    key_bits: None,
                    curve: None,
                }),
                cert: None,
                key: None,
                endpoint: Some(endpoint),
                occurrences: vec![occurrence],
            });
        }
        for cert in chain {
            let evidence = messages::EVIDENCE_CHAIN_CERT
                .replace("{position}", &cert.chain_position.unwrap_or(0).to_string())
                .replace("{subject}", &cert.subject);
            let occurrence = self.occurrence(t, evidence);
            self.certs
                .entry(cert.sha256.clone())
                .or_insert_with(|| SeenCert {
                    cert,
                    occurrences: Vec::new(),
                })
                .occurrences
                .push(occurrence);
        }
    }

    /// Classify the certificates. A certificate that many endpoints share is one item.
    fn finish(mut self) -> NetOutput {
        let today = Utc::now().date_naive();
        for (_, seen) in std::mem::take(&mut self.certs) {
            let fingerprint = Fingerprint::cert(&seen.cert.sha256);
            match classify_cert(&seen.cert, self.pack, today) {
                Some((rule_id, threat_type, also)) => {
                    let id = self.next_id();
                    self.output.findings.push(Finding {
                        id,
                        fingerprint,
                        rule_id,
                        source: Source::Net,
                        algorithm: Some(seen.cert.public_key.clone()),
                        purpose: Purpose::Signature,
                        threat_type,
                        agility: Agility::Unknown,
                        fix_owner: FixOwner::Unknown,
                        also,
                        occurrences: seen.occurrences,
                        cert: Some(seen.cert),
                        key: None,
                        endpoint: None,
                    });
                }
                None => {
                    let pq_ready = is_pq_ready(self.pack, &seen.cert.public_key.name);
                    self.output.inventory.push(InventoryItem {
                        kind: InventoryKind::Certificate,
                        fingerprint,
                        pq_ready,
                        algorithm: Some(seen.cert.public_key.clone()),
                        cert: Some(seen.cert),
                        key: None,
                        endpoint: None,
                        occurrences: seen.occurrences,
                    });
                }
            }
        }
        self.output
    }
}
