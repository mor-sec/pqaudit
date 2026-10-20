//! The network runtime: the limits, the audited connect helper, and the scan loop.
//!
//! Every socket in the tool comes from `ProbeCtx::connect`. This helper applies the limits
//! for each IP address and writes one audit line for each connection attempt.
//! The runtime connects only to `PlannedTarget::ip`. It never resolves a name.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{NaiveTime, Timelike, Utc};
use futures_util::future::join_all;
use pqaudit_core::{
    CertInfo, Finding, InventoryItem, Protocol, ScanError, SshObservation, TlsObservation,
};
use pqaudit_rules::pack::RulesPack;
use tokio::net::TcpStream;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Instant};
use uuid::Uuid;

use crate::audit::{AuditEntry, AuditLog, ByteCounts, CountingStream};
use crate::findings;
use crate::messages;
use crate::scope::{HoursWindow, Limits, PlannedTarget, ScopeError, TargetPlan};

/// The file name that the hours check shows in a parse error.
const SCOPE_FILE_NAME: &str = "scope.toml";

/// The result of a TLS probe: what the tool saw and the certificate chain of the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsObservationWithCerts {
    /// What the tool saw in the handshakes.
    pub obs: TlsObservation,
    /// The certificates of the server. The leaf is first.
    pub chain: Vec<CertInfo>,
}

/// The result of an SSH probe. The error is a text for the user.
pub type SshObservationResult = Result<SshObservation, String>;

/// The probes of a scan. A test can replace them.
#[async_trait]
pub trait Probes: Send + Sync {
    /// Probe a TLS target.
    async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts;
    /// Probe an SSH target.
    async fn ssh(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> SshObservationResult;
}

/// The result of a scan.
#[derive(Debug, Default)]
pub struct NetOutput {
    /// The weak items.
    pub findings: Vec<Finding>,
    /// The items that are not findings, for example endpoints that are ready.
    pub inventory: Vec<InventoryItem>,
    /// The targets that the tool could not probe.
    pub errors: Vec<ScanError>,
}

/// Why `ProbeCtx::connect` failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectError {
    /// The connect failed. The value is the reason.
    Failed(String),
    /// The connect did not finish in the connect timeout.
    Timeout,
    /// The audit log does not work, so the tool makes no connection.
    AuditBroken,
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed(reason) => {
                f.write_str(&messages::CONNECT_FAILED.replace("{reason}", reason))
            }
            Self::Timeout => f.write_str(messages::CONNECT_TIMEOUT),
            Self::AuditBroken => f.write_str(messages::AUDIT_BROKEN),
        }
    }
}

impl std::error::Error for ConnectError {}

/// The state of the pacing for one IP address.
#[derive(Debug)]
struct IpGate {
    /// One permit for each connection that can run at the same time.
    slots: Arc<Semaphore>,
    /// The earliest start time of the next connection.
    next_allowed: Mutex<Instant>,
}

/// The limits for each IP address. All targets with the same IP address share one gate.
#[derive(Debug)]
struct Pacer {
    per_host: usize,
    min_interval: Duration,
    gates: Mutex<HashMap<IpAddr, Arc<IpGate>>>,
}

impl Pacer {
    fn gate(&self, ip: IpAddr) -> Arc<IpGate> {
        let mut gates = self.gates.lock().unwrap_or_else(PoisonError::into_inner);
        gates
            .entry(ip)
            .or_insert_with(|| {
                Arc::new(IpGate {
                    slots: Arc::new(Semaphore::new(self.per_host.max(1))),
                    next_allowed: Mutex::new(Instant::now()),
                })
            })
            .clone()
    }
}

/// The right to make one connection to an IP address.
///
/// The holder waits for a free slot and for the minimum interval.
/// The tool sets the next start time again when the holder drops the permit.
#[derive(Debug)]
pub struct HostPermit {
    _slot: OwnedSemaphorePermit,
    gate: Arc<IpGate>,
    min_interval: Duration,
}

impl Drop for HostPermit {
    fn drop(&mut self) {
        let earliest = Instant::now() + self.min_interval;
        let mut next = self
            .gate
            .next_allowed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if *next < earliest {
            *next = earliest;
        }
    }
}

/// What a probe needs: the limits, the audit log, and the run ID.
#[derive(Debug)]
pub struct ProbeCtx<'a> {
    /// The limits of the scan.
    pub limits: Limits,
    /// The audit log.
    pub audit: &'a AuditLog,
    /// The ID of the run.
    pub run_id: Uuid,
    pacer: Pacer,
}

impl<'a> ProbeCtx<'a> {
    /// Make the context of a run.
    pub fn new(limits: Limits, audit: &'a AuditLog, run_id: Uuid) -> Self {
        Self {
            limits,
            audit,
            run_id,
            pacer: Pacer {
                per_host: limits.per_host,
                min_interval: limits.min_interval,
                gates: Mutex::new(HashMap::new()),
            },
        }
    }

    /// Wait until the tool can make a connection to the IP address.
    ///
    /// The limits are for the IP address, not for the planned target.
    /// Two targets with the same IP address and different names share one limit.
    pub async fn acquire_host(&self, ip: IpAddr) -> HostPermit {
        let gate = self.pacer.gate(ip);
        let slot = gate
            .slots
            .clone()
            .acquire_owned()
            .await
            .expect("the semaphore is never closed");
        // Reserve the start time first. Then wait. Two waiters get two different times.
        let start = {
            let mut next = gate
                .next_allowed
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let start = (*next).max(Instant::now());
            *next = start + self.pacer.min_interval;
            start
        };
        tokio::time::sleep_until(start).await;
        HostPermit {
            _slot: slot,
            gate,
            min_interval: self.pacer.min_interval,
        }
    }

    /// Open a TCP connection to the planned target. This is the only way to open a socket.
    ///
    /// The tool connects to `t.ip` only. The helper writes one audit line for each call,
    /// also when the connect fails or times out. For a connection that opens, the helper
    /// writes the line when the caller drops the `Connected` value.
    pub async fn connect(
        &self,
        t: &PlannedTarget,
        probe: &str,
    ) -> Result<Connected<'a>, ConnectError> {
        if self.audit.is_broken() {
            return Err(ConnectError::AuditBroken);
        }
        let permit = self.acquire_host(t.ip).await;
        let started = Instant::now();
        let mut entry = AuditEntry {
            ts: Utc::now(),
            run_id: self.run_id,
            src_ip: None,
            dst_host: t.host.clone(),
            dst_ip: t.ip,
            port: t.port,
            protocol: t.protocol,
            probe: probe.to_string(),
            outcome: String::new(),
            bytes_sent: 0,
            bytes_received: 0,
            duration_ms: 0,
        };
        let address = SocketAddr::new(t.ip, t.port);
        let failure = match timeout(self.limits.connect_timeout, TcpStream::connect(address)).await
        {
            Ok(Ok(stream)) => {
                // A failure to set this option has no effect on the safety of the probe.
                let _ = stream.set_nodelay(true);
                entry.src_ip = stream.local_addr().ok().map(|address| address.ip());
                entry.outcome = String::from(OUTCOME_ABORTED);
                let counts = Arc::new(ByteCounts::default());
                return Ok(Connected {
                    stream: CountingStream::new(stream, counts.clone()),
                    audit: ConnAudit {
                        log: self.audit,
                        entry,
                        counts,
                        started,
                        _permit: permit,
                    },
                });
            }
            Ok(Err(error)) => {
                entry.outcome = format!("connect-failed: {error}");
                ConnectError::Failed(error.to_string())
            }
            Err(_) => {
                entry.outcome = String::from("connect-timeout");
                ConnectError::Timeout
            }
        };
        entry.duration_ms = millis(started.elapsed());
        // A failed write marks the log as broken. The caller sees this at the next connect.
        let _ = self.audit.record(&entry);
        Err(failure)
    }
}

/// The outcome of a connection that nobody finished. A dropped probe leaves this text.
const OUTCOME_ABORTED: &str = "aborted";

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// An open connection and its audit guard.
#[derive(Debug)]
pub struct Connected<'a> {
    /// The stream. It counts the bytes.
    pub stream: CountingStream<TcpStream>,
    /// The audit guard. Keep it until the probe ends.
    pub audit: ConnAudit<'a>,
}

/// The audit guard of one connection. It writes the audit line when it drops.
#[derive(Debug)]
pub struct ConnAudit<'a> {
    log: &'a AuditLog,
    entry: AuditEntry,
    counts: Arc<ByteCounts>,
    started: Instant,
    _permit: HostPermit,
}

impl ConnAudit<'_> {
    /// Set the result of the connection. The default is `aborted`.
    pub fn set_outcome(&mut self, outcome: impl Into<String>) {
        self.entry.outcome = outcome.into();
    }
}

impl Drop for ConnAudit<'_> {
    fn drop(&mut self) {
        self.entry.bytes_sent = self.counts.sent();
        self.entry.bytes_received = self.counts.received();
        self.entry.duration_ms = millis(self.started.elapsed());
        // A failed write marks the log as broken. The next connect then fails.
        let _ = self.log.record(&self.entry);
    }
}

/// What one probe returned.
pub(crate) enum TargetResult {
    Tls(TlsObservationWithCerts),
    Ssh(SshObservationResult),
}

/// Probe all targets of the plan and make the findings.
///
/// The scan obeys the limits of the plan. A global limit caps the probes at the same time.
/// `ProbeCtx::connect` applies the limits for each IP address. The tool never runs a failed probe again.
/// The caller must check the plan and the allowed hours before it calls this function.
pub async fn run(
    plan: &TargetPlan,
    probes: &dyn Probes,
    audit: &AuditLog,
    run_id: Uuid,
    pack: &RulesPack,
) -> NetOutput {
    let ctx = ProbeCtx::new(plan.limits, audit, run_id);
    let global = Semaphore::new(plan.limits.concurrency.max(1));
    let jobs = plan.targets.iter().map(|target| {
        let ctx = &ctx;
        let global = &global;
        async move {
            let _slot = global
                .acquire()
                .await
                .expect("the semaphore is never closed");
            match target.protocol {
                Protocol::Tls => TargetResult::Tls(probes.tls(target, ctx).await),
                Protocol::Ssh => TargetResult::Ssh(probes.ssh(target, ctx).await),
            }
        }
    });
    let results = join_all(jobs).await;
    findings::build(&plan.targets, results, run_id, pack)
}

/// Check the window `allowed_hours` as text. `None` means no window.
///
/// Outside the window, the result is a refusal. The tool then makes no connection.
pub fn check_allowed_hours(spec: Option<&str>, now: NaiveTime) -> Result<(), ScopeError> {
    let window = match spec {
        None => None,
        Some(text) => Some(HoursWindow::parse(text).ok_or_else(|| ScopeError::Parse {
            file: SCOPE_FILE_NAME.to_string(),
            line: 1,
            reason: crate::messages::HOURS_INVALID.to_string(),
        })?),
    };
    check_hours(window.as_ref(), now)
}

/// Check a parsed window. `None` means no window.
pub fn check_hours(window: Option<&HoursWindow>, now: NaiveTime) -> Result<(), ScopeError> {
    let Some(window) = window else {
        return Ok(());
    };
    let minute = u16::try_from(now.hour() * 60 + now.minute()).unwrap_or(0);
    if window.contains(minute) {
        Ok(())
    } else {
        Err(ScopeError::OutsideHours)
    }
}
