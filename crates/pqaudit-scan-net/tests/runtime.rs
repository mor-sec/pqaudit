//! Tests of the network runtime: the limits, the audit log, and the hours check.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use chrono::NaiveTime;
use pqaudit_core::{Protocol, TlsObservation};
use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_net::audit::{AuditEntry, AuditLog};
use pqaudit_scan_net::runtime::{
    check_allowed_hours, check_hours, run, run_until, ProbeCtx, Probes, SshObservationResult,
    TlsObservationWithCerts,
};
use pqaudit_scan_net::scope::{HoursWindow, Limits, PlannedTarget, ScopeError, TargetPlan};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::Instant;
use uuid::Uuid;

fn target(ip: IpAddr, port: u16) -> PlannedTarget {
    PlannedTarget {
        host: None,
        ip,
        port,
        protocol: Protocol::Tls,
        connections: 2,
    }
}

fn plan(targets: Vec<PlannedTarget>, limits: Limits) -> TargetPlan {
    TargetPlan {
        targets,
        refused: Vec::new(),
        limits,
    }
}

fn empty_obs(version: bool) -> TlsObservationWithCerts {
    TlsObservationWithCerts {
        obs: TlsObservation {
            pq_hybrid_supported: None,
            negotiated_version: version.then(|| String::from("TLS 1.3")),
            negotiated_group: None,
            cipher_suite: None,
            legacy_versions: None,
            errors: Vec::new(),
        },
        chain: Vec::new(),
        failures: Vec::new(),
    }
}

fn audit_in(dir: &tempfile::TempDir) -> AuditLog {
    AuditLog::open(&dir.path().join("audit.log")).unwrap()
}

/// All lines of the audit log, with the "started" lines.
fn read_all_entries(dir: &tempfile::TempDir) -> Vec<AuditEntry> {
    std::fs::read_to_string(dir.path().join("audit.log"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The final line of each connection attempt.
fn read_entries(dir: &tempfile::TempDir) -> Vec<AuditEntry> {
    read_all_entries(dir)
        .into_iter()
        .filter(|entry| entry.outcome != "started")
        .collect()
}

/// A fake probe set. It records the time of each call and never opens a socket.
#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<(IpAddr, u16, Instant)>>,
    active: AtomicUsize,
    max_active: AtomicUsize,
    use_host_gate: bool,
}

#[async_trait]
impl Probes for Fake {
    async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts {
        let _permit = if self.use_host_gate {
            Some(ctx.acquire_host(t.ip).await)
        } else {
            None
        };
        self.calls
            .lock()
            .unwrap()
            .push((t.ip, t.port, Instant::now()));
        let now = self.active.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_active.fetch_max(now, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.active.fetch_sub(1, Ordering::SeqCst);
        empty_obs(true)
    }

    async fn ssh(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> SshObservationResult {
        Err(String::from("not used"))
    }
}

#[tokio::test(start_paused = true)]
async fn global_concurrency_respected() {
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let targets = (1..=20u8)
        .map(|n| target(IpAddr::V4(Ipv4Addr::new(10, 0, 0, n)), 443))
        .collect();
    let fake = Fake::default();
    let limits = Limits::DEFAULT;
    let out = run(
        &plan(targets, limits),
        &fake,
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert!(out.errors.is_empty(), "errors: {:?}", out.errors);
    assert_eq!(fake.calls.lock().unwrap().len(), 20);
    assert_eq!(fake.max_active.load(Ordering::SeqCst), 4);
}

#[tokio::test(start_paused = true)]
async fn same_host_min_interval_respected() {
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let same = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let other = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let targets = vec![
        target(same, 443),
        target(same, 8443),
        target(same, 9443),
        target(other, 443),
    ];
    let fake = Fake {
        use_host_gate: true,
        ..Fake::default()
    };
    run(
        &plan(targets, Limits::DEFAULT),
        &fake,
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    let calls = fake.calls.lock().unwrap().clone();
    let mut same_times: Vec<Instant> = calls
        .iter()
        .filter(|call| call.0 == same)
        .map(|call| call.2)
        .collect();
    same_times.sort();
    assert_eq!(same_times.len(), 3);
    for pair in same_times.windows(2) {
        assert!(
            pair[1] - pair[0] >= Duration::from_millis(1000),
            "gap too short: {:?}",
            pair[1] - pair[0]
        );
    }
    // A different IP address does not wait for the first one.
    let start = calls.iter().map(|call| call.2).min().unwrap();
    let other_time = calls.iter().find(|call| call.0 == other).unwrap().2;
    assert!(other_time - start < Duration::from_millis(1000));
}

/// A server that sends five bytes, reads three bytes, and closes the connection.
async fn five_byte_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream.write_all(b"hello").await;
                let mut buffer = [0u8; 3];
                let _ = stream.read_exact(&mut buffer).await;
            });
        }
    });
    address
}

/// A probe that opens one connection through the audited helper.
struct Dial;

#[async_trait]
impl Probes for Dial {
    async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts {
        let mut result = empty_obs(false);
        match ctx.connect(t, "tls-hybrid").await {
            Ok(mut connected) => {
                let mut buffer = [0u8; 5];
                connected.stream.read_exact(&mut buffer).await.unwrap();
                connected.stream.write_all(b"abc").await.unwrap();
                connected.audit.set_outcome("ok");
                result.obs.negotiated_version = Some(String::from("TLS 1.3"));
            }
            Err(error) => result.obs.errors.push(error.to_string()),
        }
        result
    }

    async fn ssh(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> SshObservationResult {
        Err(String::from("not used"))
    }
}

#[tokio::test]
async fn every_connection_audited() {
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let good = five_byte_server().await;
    // Find a port that nobody listens on.
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let targets = vec![target(good.ip(), good.port()), target(good.ip(), closed)];
    let mut limits = Limits::DEFAULT;
    limits.min_interval = Duration::from_millis(10);
    let out = run(
        &plan(targets, limits),
        &Dial,
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    // The failed target is an error in the output.
    assert_eq!(out.errors.len(), 1, "errors: {:?}", out.errors);
    // Each attempt has one "started" line and one final line.
    assert_eq!(read_all_entries(&dir).len(), 4);
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 2, "entries: {entries:?}");
    let ok = entries.iter().find(|e| e.port == good.port()).unwrap();
    assert_eq!(ok.outcome, "ok");
    assert_eq!(ok.bytes_received, 5);
    assert_eq!(ok.bytes_sent, 3);
    assert_eq!(ok.dst_ip, good.ip());
    assert_eq!(ok.probe, "tls-hybrid");
    assert_eq!(ok.protocol, Protocol::Tls);
    assert!(ok.src_ip.is_some());
    let failed = entries.iter().find(|e| e.port == closed).unwrap();
    assert!(
        failed.outcome.starts_with("connect-failed"),
        "{}",
        failed.outcome
    );
    assert_eq!(failed.bytes_sent, 0);
    assert_eq!(failed.bytes_received, 0);
}

#[tokio::test]
async fn dropped_connection_is_still_audited() {
    // A probe that drops its connection without a result must still leave an audit line.
    struct Forget;
    #[async_trait]
    impl Probes for Forget {
        async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts {
            let _connected = ctx.connect(t, "tls-classical").await;
            empty_obs(false)
        }
        async fn ssh(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> SshObservationResult {
            Err(String::new())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let good = five_byte_server().await;
    let mut limits = Limits::DEFAULT;
    limits.min_interval = Duration::from_millis(10);
    run(
        &plan(vec![target(good.ip(), good.port())], limits),
        &Forget,
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].outcome, "aborted");
}

#[tokio::test]
async fn connect_timeout_is_audited() {
    // 192.0.2.1 is a documentation address. A connect to it does not finish.
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let mut limits = Limits::DEFAULT;
    limits.connect_timeout = Duration::from_millis(200);
    let ctx = ProbeCtx::new(limits, &audit, Uuid::new_v4());
    let t = target(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
    let started = std::time::Instant::now();
    let result = ctx.connect(&t, "tls-hybrid").await;
    assert!(result.is_err());
    assert!(started.elapsed() < Duration::from_secs(3));
    drop(result);
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    // Some networks refuse at once. A network that drops packets gives a timeout.
    assert!(
        entries[0].outcome == "connect-timeout" || entries[0].outcome.starts_with("connect-failed"),
        "{}",
        entries[0].outcome
    );
}

#[test]
fn outside_allowed_hours_refuses() {
    let time = |h, m| NaiveTime::from_hms_opt(h, m, 0).unwrap();
    // No window: always allowed.
    assert!(check_allowed_hours(None, time(3, 0)).is_ok());
    // A normal window. The end is not in the window.
    assert!(check_allowed_hours(Some("09:00-17:00"), time(9, 0)).is_ok());
    assert!(check_allowed_hours(Some("09:00-17:00"), time(16, 59)).is_ok());
    let error = check_allowed_hours(Some("09:00-17:00"), time(17, 0)).unwrap_err();
    assert!(matches!(error, ScopeError::OutsideHours));
    assert!(error.is_refusal());
    assert!(check_allowed_hours(Some("09:00-17:00"), time(20, 0)).is_err());
    // A window that crosses midnight.
    assert!(check_allowed_hours(Some("22:00-06:00"), time(23, 30)).is_ok());
    assert!(check_allowed_hours(Some("22:00-06:00"), time(5, 59)).is_ok());
    assert!(check_allowed_hours(Some("22:00-06:00"), time(12, 0)).is_err());
    // A text that is not valid is an error, but not a refusal.
    let bad = check_allowed_hours(Some("late"), time(12, 0)).unwrap_err();
    assert!(!bad.is_refusal());
    // The parsed window gives the same answer.
    let window = HoursWindow::parse("09:00-17:00").unwrap();
    assert!(check_hours(Some(&window), time(10, 0)).is_ok());
    assert!(check_hours(Some(&window), time(18, 0)).is_err());
    assert!(check_hours(None, time(18, 0)).is_ok());
}

#[tokio::test]
async fn no_retries_on_failure() {
    // A failed probe runs one time, also when the limits allow retries.
    struct Failing(AtomicUsize);
    #[async_trait]
    impl Probes for Failing {
        async fn tls(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts {
            self.0.fetch_add(1, Ordering::SeqCst);
            let mut result = empty_obs(false);
            result.obs.errors.push(String::from("failed"));
            result
        }
        async fn ssh(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> SshObservationResult {
            self.0.fetch_add(1, Ordering::SeqCst);
            Err(String::from("failed"))
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let probes = Failing(AtomicUsize::new(0));
    let mut limits = Limits::DEFAULT;
    limits.retries = 3;
    let mut ssh = target(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 22);
    ssh.protocol = Protocol::Ssh;
    ssh.connections = 1;
    let targets = vec![target(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 443), ssh];
    let out = run(
        &plan(targets, limits),
        &probes,
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert_eq!(probes.0.load(Ordering::SeqCst), 2);
    assert_eq!(out.errors.len(), 2);
}

#[tokio::test]
async fn broken_audit_log_stops_connections() {
    // If the tool cannot write the audit log, it must make no more connections.
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    audit.mark_broken();
    let ctx = ProbeCtx::new(Limits::DEFAULT, &audit, Uuid::new_v4());
    let good = five_byte_server().await;
    let result = ctx
        .connect(&target(good.ip(), good.port()), "tls-hybrid")
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn cancelled_run_still_audits_open_connections() {
    // A probe that connects and then waits for ever. The caller cancels the run (Ctrl-C).
    struct Block;
    #[async_trait]
    impl Probes for Block {
        async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts {
            let _connected = ctx.connect(t, "tls-hybrid").await;
            std::future::pending::<()>().await;
            empty_obs(false)
        }
        async fn ssh(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> SshObservationResult {
            Err(String::new())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let good = five_byte_server().await;
    let mut limits = Limits::DEFAULT;
    limits.min_interval = Duration::from_millis(10);
    let plan = plan(vec![target(good.ip(), good.port())], limits);
    let cancelled = tokio::time::timeout(
        Duration::from_millis(300),
        run(&plan, &Block, &audit, Uuid::new_v4(), default_pack()),
    )
    .await;
    assert!(cancelled.is_err());
    let all = read_all_entries(&dir);
    let outcomes: Vec<&str> = all.iter().map(|e| e.outcome.as_str()).collect();
    assert_eq!(outcomes, ["started", "aborted"]);
}

#[tokio::test]
async fn started_line_comes_first_for_each_attempt() {
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    };
    let ctx = ProbeCtx::new(Limits::DEFAULT, &audit, Uuid::new_v4());
    let t = target(IpAddr::V4(Ipv4Addr::LOCALHOST), closed);
    assert!(ctx.connect(&t, "tls-hybrid").await.is_err());
    let all = read_all_entries(&dir);
    assert_eq!(all.len(), 2);
    assert_eq!(all[0].outcome, "started");
    assert!(all[1].outcome.starts_with("connect-failed"));
}

#[tokio::test]
async fn handshake_budget_is_per_address_and_port() {
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(Limits::DEFAULT, &audit, Uuid::new_v4());
    let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(ctx.claim_handshakes(ip, 443, 2), 2);
    assert_eq!(ctx.claim_handshakes(ip, 443, 2), 1);
    assert_eq!(ctx.claim_handshakes(ip, 443, 2), 0);
    // Another port and another address have their own budget.
    assert_eq!(ctx.claim_handshakes(ip, 8443, 3), 3);
    assert_eq!(
        ctx.claim_handshakes(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 443, 3),
        3
    );
}

#[tokio::test]
async fn stopped_run_keeps_finished_results_and_reports_the_rest() {
    // The first target finishes at once. The second one connects and then waits for ever.
    struct Mixed;
    #[async_trait]
    impl Probes for Mixed {
        async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx<'_>) -> TlsObservationWithCerts {
            if t.port == 1 {
                let mut done = empty_obs(true);
                done.obs.pq_hybrid_supported = Some(false);
                return done;
            }
            let _connected = ctx.connect(t, "tls-hybrid").await;
            std::future::pending::<()>().await;
            empty_obs(false)
        }
        async fn ssh(&self, _t: &PlannedTarget, _ctx: &ProbeCtx<'_>) -> SshObservationResult {
            Err(String::new())
        }
    }
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let good = five_byte_server().await;
    let mut limits = Limits::DEFAULT;
    limits.min_interval = Duration::from_millis(10);
    let targets = vec![
        target(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), 1),
        target(good.ip(), good.port()),
    ];
    let out = run_until(
        &plan(targets, limits),
        &Mixed,
        &audit,
        Uuid::new_v4(),
        default_pack(),
        tokio::time::sleep(Duration::from_millis(300)),
    )
    .await;
    // The finished target gives its finding.
    assert!(out.findings.iter().any(|f| f.rule_id == "tls.no-pq-kex"));
    // The other target gives one error with its own address.
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.errors[0].location.contains(&good.port().to_string()));
    let outcomes: Vec<String> = read_entries(&dir).into_iter().map(|e| e.outcome).collect();
    assert_eq!(outcomes, ["aborted"]);
}
