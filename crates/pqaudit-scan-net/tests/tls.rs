//! Tests of the TLS probes against servers in the same process.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use pqaudit_core::{Location, Protocol, ThreatType};
use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_net::audit::{AuditEntry, AuditLog};
use pqaudit_scan_net::runtime::{run, ProbeCtx, Probes};
use pqaudit_scan_net::scope::{Limits, PlannedTarget, TargetPlan};
use pqaudit_scan_net::tls::RealProbes;
use pqaudit_scan_net::tls_legacy;
use rcgen::{CertificateParams, KeyPair, RsaKeySize, PKCS_RSA_SHA256};
use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use uuid::Uuid;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// A certificate and its private key in DER form.
struct Identity {
    cert: Vec<u8>,
    key: Vec<u8>,
}

fn ecdsa_identity() -> Identity {
    let key = KeyPair::generate().unwrap();
    let cert = CertificateParams::new(vec![String::from("localhost")])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    Identity {
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

fn rsa2048_identity() -> Identity {
    let key = KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048).unwrap();
    let cert = CertificateParams::new(vec![String::from("localhost")])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    Identity {
        cert: cert.der().to_vec(),
        key: key.serialize_der(),
    }
}

/// Start a TLS server. The groups decide what the server accepts.
/// Return the address and a counter of accepted connections.
async fn tls_server(
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    identity: Identity,
) -> (SocketAddr, Arc<AtomicUsize>) {
    serve(server_config(groups, identity), Mode::Normal).await
}

fn server_config(
    groups: Vec<&'static dyn rustls::crypto::SupportedKxGroup>,
    identity: Identity,
) -> ServerConfig {
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = groups;
    ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(identity.cert)],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key)),
        )
        .unwrap()
}

/// How a test server treats its connections.
#[derive(Clone, Copy)]
enum Mode {
    /// Finish the handshake. Wait for data for 2 seconds.
    Normal,
    /// Serve the first connections. Hold the later ones and never write.
    SilentAfter(usize),
    /// Finish the handshake. Then never read or write again.
    HoldAfterHandshake,
}

async fn serve(config: ServerConfig, mode: Mode) -> (SocketAddr, Arc<AtomicUsize>) {
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let counter = count.clone();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            let number = counter.fetch_add(1, Ordering::SeqCst) + 1;
            if matches!(mode, Mode::SilentAfter(n) if number > n) {
                held.push(stream);
                continue;
            }
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    if matches!(mode, Mode::HoldAfterHandshake) {
                        tokio::time::sleep(Duration::from_secs(30)).await;
                        return;
                    }
                    let mut buffer = [0u8; 16];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(2), tls.read(&mut buffer)).await;
                }
            });
        }
    });
    (address, count)
}

fn hybrid_groups() -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    vec![kx_group::X25519MLKEM768, kx_group::X25519]
}

fn classical_groups() -> Vec<&'static dyn rustls::crypto::SupportedKxGroup> {
    vec![kx_group::X25519, kx_group::SECP256R1]
}

fn target_for(address: SocketAddr, connections: u8) -> PlannedTarget {
    PlannedTarget {
        host: Some(String::from("localhost")),
        ip: address.ip(),
        port: address.port(),
        protocol: Protocol::Tls,
        connections,
    }
}

fn limits() -> Limits {
    let mut limits = Limits::DEFAULT;
    limits.min_interval = Duration::from_millis(10);
    limits
}

fn audit_in(dir: &tempfile::TempDir) -> AuditLog {
    AuditLog::open(&dir.path().join("audit.log")).unwrap()
}

/// The final line of each connection attempt. The "started" lines are not in the list.
fn read_entries(dir: &tempfile::TempDir) -> Vec<AuditEntry> {
    std::fs::read_to_string(dir.path().join("audit.log"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap())
        .filter(|entry| entry.outcome != "started")
        .collect()
}

#[tokio::test]
async fn hybrid_server_detected() {
    let (address, _) = tls_server(hybrid_groups(), ecdsa_identity()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
    let result = RealProbes::new(false)
        .tls(&target_for(address, 2), &ctx)
        .await;
    assert_eq!(
        result.obs.pq_hybrid_supported,
        Some(true),
        "{:?}",
        result.obs
    );
    assert_eq!(result.obs.negotiated_version.as_deref(), Some("TLS 1.3"));
    assert!(result.obs.cipher_suite.is_some());
    assert_eq!(result.chain.len(), 1);
    assert_eq!(result.chain[0].public_key.name, "ECDSA");
    // Hybrid and classical: two connections, two audit lines.
    let entries = read_entries(&dir);
    let probes: Vec<&str> = entries.iter().map(|e| e.probe.as_str()).collect();
    assert_eq!(probes, ["tls-hybrid", "tls-classical"]);
    assert!(entries.iter().all(|e| e.outcome == "ok"));
    assert!(entries
        .iter()
        .all(|e| e.bytes_sent > 0 && e.bytes_received > 0));
    // The inventory marks the endpoint as ready.
    let plan = TargetPlan {
        targets: vec![target_for(address, 2)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(false),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(out.findings.iter().all(|f| f.rule_id != "tls.no-pq-kex"));
    let endpoint = out
        .inventory
        .iter()
        .find(|item| item.kind == pqaudit_core::InventoryKind::Endpoint)
        .expect("an endpoint inventory item");
    assert!(endpoint.pq_ready);
}

#[tokio::test]
async fn classical_only_server_gives_no_pq_finding() {
    let (address, _) = tls_server(classical_groups(), ecdsa_identity()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![target_for(address, 2)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(false),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let finding = out
        .findings
        .iter()
        .find(|f| f.rule_id == "tls.no-pq-kex")
        .expect("a no-pq finding");
    assert_eq!(finding.threat_type, ThreatType::Hndl);
    let tls = finding.endpoint.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(tls.pq_hybrid_supported, Some(false));
    assert_eq!(tls.negotiated_group.as_deref(), Some("X25519"));
    assert_eq!(tls.negotiated_version.as_deref(), Some("TLS 1.3"));
    assert!(!tls.errors.is_empty());
    assert!(out.inventory.iter().all(|item| !item.pq_ready));
}

#[tokio::test]
async fn chain_certs_classified() {
    let (address, _) = tls_server(hybrid_groups(), rsa2048_identity()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![target_for(address, 2)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(false),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    let finding = out
        .findings
        .iter()
        .find(|f| f.rule_id == "cert.classical-key")
        .expect("a classical key finding");
    let algorithm = finding.algorithm.as_ref().unwrap();
    assert_eq!(algorithm.name, "RSA");
    assert_eq!(algorithm.key_bits, Some(2048));
    assert!(finding.cert.is_some());
    assert_eq!(finding.occurrences.len(), 1);
    match &finding.occurrences[0].location {
        Location::Endpoint {
            host,
            ip,
            port,
            protocol,
        } => {
            assert_eq!(host, "localhost");
            assert_eq!(*ip, LOCALHOST);
            assert_eq!(*port, address.port());
            assert_eq!(*protocol, Protocol::Tls);
        }
        other => panic!("wrong location: {other:?}"),
    }
}

/// The bytes of a ServerHello record with the given version. It has no extensions.
fn server_hello(version: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&[7u8; 32]);
    body.push(0); // session ID length
    body.extend_from_slice(&[0x00, 0x2f]); // cipher suite
    body.push(0); // compression
    let mut handshake = vec![2u8];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);
    let mut record = vec![0x16];
    record.extend_from_slice(&version.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    record
}

/// A raw server that reads a ClientHello and answers it. It saves the ClientHello version.
async fn fake_server(reply: Vec<u8>) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen_version = Arc::new(AtomicUsize::new(0));
    let saved = seen_version.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let reply = reply.clone();
            let saved = saved.clone();
            tokio::spawn(async move {
                let mut header = [0u8; 5];
                if stream.read_exact(&mut header).await.is_err() {
                    return;
                }
                let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
                let mut hello = vec![0u8; length];
                if stream.read_exact(&mut hello).await.is_err() {
                    return;
                }
                // Byte 0 is the handshake type. Bytes 1 to 3 are the length.
                // Bytes 4 and 5 are the client version.
                let version = usize::from(u16::from_be_bytes([hello[4], hello[5]]));
                saved.store(version, Ordering::SeqCst);
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (address, seen_version)
}

#[tokio::test]
async fn legacy_probe_detects_tls10() {
    let (address, seen) = fake_server(server_hello(0x0301)).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
    let versions = tls_legacy::probe(&ctx, &target_for(address, 3))
        .await
        .unwrap();
    assert_eq!(versions, ["TLS 1.0"]);
    assert_eq!(seen.load(Ordering::SeqCst), 0x0302);
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].probe, "tls-legacy");
    assert!(entries[0].bytes_sent > 0);
    assert!(entries[0].bytes_received > 0);
}

#[tokio::test]
async fn legacy_probe_end_to_end_gives_finding() {
    // The fake server speaks TLS 1.0 only. The two normal handshakes fail.
    let (address, _) = fake_server(server_hello(0x0301)).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![target_for(address, 3)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(true),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    let finding = out
        .findings
        .iter()
        .find(|f| f.rule_id == "tls.legacy-version")
        .expect("a legacy version finding");
    assert_eq!(finding.threat_type, ThreatType::ClassicalWeakNow);
    let tls = finding.endpoint.as_ref().unwrap().tls.as_ref().unwrap();
    assert_eq!(
        tls.legacy_versions.as_deref(),
        Some(&[String::from("TLS 1.0")][..])
    );
    // The server does not speak TLS 1.2 or 1.3. The tool must not claim "no hybrid".
    assert!(out.findings.iter().all(|f| f.rule_id != "tls.no-pq-kex"));
    assert_eq!(read_entries(&dir).len(), 3);
}

#[tokio::test]
async fn legacy_probe_detects_tls11_and_ssl3() {
    for (wire, name) in [(0x0302, "TLS 1.1"), (0x0300, "SSL 3.0")] {
        let (address, _) = fake_server(server_hello(wire)).await;
        let dir = tempfile::tempdir().unwrap();
        let audit = audit_in(&dir);
        let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
        let versions = tls_legacy::probe(&ctx, &target_for(address, 3))
            .await
            .unwrap();
        assert_eq!(versions, [name]);
    }
}

#[tokio::test]
async fn legacy_probe_alert_means_not_accepted() {
    // A fatal alert protocol_version.
    let alert = vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x46];
    let (address, _) = fake_server(alert).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
    let versions = tls_legacy::probe(&ctx, &target_for(address, 3))
        .await
        .unwrap();
    assert!(versions.is_empty());
}

#[tokio::test]
async fn legacy_probe_reads_only_a_small_reply() {
    // A hostile server sends a record with a huge length and then endless data.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut sink = [0u8; 4096];
                let _ = stream.read(&mut sink).await;
                let mut reply = vec![
                    0x16, 0x03, 0x01, 0xff, 0xff, 0x02, 0xff, 0xff, 0xff, 0x03, 0x01,
                ];
                reply.extend(std::iter::repeat_n(0u8, 1 << 20));
                let _ = stream.write_all(&reply).await;
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
    let versions = tls_legacy::probe(&ctx, &target_for(address, 3))
        .await
        .unwrap();
    assert_eq!(versions, ["TLS 1.0"]);
    let entries = read_entries(&dir);
    assert!(
        entries[0].bytes_received < 64 * 1024,
        "{}",
        entries[0].bytes_received
    );
}

#[tokio::test]
async fn legacy_probe_rejects_garbage() {
    let (address, _) = fake_server(b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
    let result = tls_legacy::probe(&ctx, &target_for(address, 3)).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn legacy_probe_off_by_default_makes_2_connections() {
    let (address, count) = tls_server(hybrid_groups(), ecdsa_identity()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
    // The plan gives 2 connections when the legacy check is off.
    let result = RealProbes::new(false)
        .tls(&target_for(address, 2), &ctx)
        .await;
    assert_eq!(result.obs.legacy_versions, None);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count.load(Ordering::SeqCst), 2);
    // The flag is off, so even a budget of 3 gives 2 connections.
    let (address, count) = tls_server(hybrid_groups(), ecdsa_identity()).await;
    RealProbes::new(false)
        .tls(&target_for(address, 3), &ctx)
        .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn legacy_probe_on_makes_3_connections_and_modern_server_has_none() {
    let (address, count) = tls_server(hybrid_groups(), ecdsa_identity()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let ctx = ProbeCtx::new(limits(), &audit, Uuid::new_v4());
    let result = RealProbes::new(true)
        .tls(&target_for(address, 3), &ctx)
        .await;
    assert_eq!(result.obs.legacy_versions, Some(Vec::new()));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count.load(Ordering::SeqCst), 3);
    // The handshake limit caps the count: a budget of 2 gives no legacy check.
    let (address, count) = tls_server(hybrid_groups(), ecdsa_identity()).await;
    let result = RealProbes::new(true)
        .tls(&target_for(address, 2), &ctx)
        .await;
    assert_eq!(result.obs.legacy_versions, None);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    // Accept the connections and never write.
    let holder = tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let mut limits = limits();
    limits.read_timeout = Duration::from_secs(1);
    let ctx = ProbeCtx::new(limits, &audit, Uuid::new_v4());
    let started = Instant::now();
    let result = RealProbes::new(true)
        .tls(&target_for(address, 3), &ctx)
        .await;
    let elapsed = started.elapsed();
    assert!(elapsed < Duration::from_secs(2), "took {elapsed:?}");
    assert!(!result.obs.errors.is_empty());
    assert_eq!(result.obs.negotiated_version, None);
    assert_eq!(result.obs.pq_hybrid_supported, None);
    // After the first timeout the tool makes no more connections.
    let entries = read_entries(&dir);
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0].outcome, "timeout");
    holder.abort();
}

#[tokio::test]
async fn closed_port_is_one_audited_error() {
    let closed = {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![target_for(closed, 3)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(true),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert_eq!(out.errors.len(), 1);
    assert!(out.findings.is_empty());
    assert!(out.inventory.is_empty());
    assert_eq!(read_entries(&dir).len(), 1);
}

#[tokio::test]
async fn garbage_server_is_not_a_tls_server() {
    // The server sends endless bytes that are not TLS. The probe must stop and claim nothing.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let chunk = vec![b'A'; 8192];
                for _ in 0..1024 {
                    if stream.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![target_for(address, 2)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(false),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.findings.is_empty());
}

fn sni_target(address: SocketAddr, name: &str, connections: u8) -> PlannedTarget {
    let mut t = target_for(address, connections);
    t.host = Some(name.to_string());
    t
}

#[tokio::test]
async fn two_sni_names_share_the_handshake_budget() {
    let (address, count) = tls_server(hybrid_groups(), ecdsa_identity()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![
            sni_target(address, "a.test", 2),
            sni_target(address, "b.test", 2),
            sni_target(address, "c.test", 2),
        ],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(false),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The default limit is 3 handshakes for each port, over all names.
    assert_eq!(count.load(Ordering::SeqCst), 3);
    assert_eq!(read_entries(&dir).len(), 3);
    // The second name has a budget of 1. The third name has none. Both are errors.
    assert_eq!(out.errors.len(), 2, "{:?}", out.errors);
    assert!(out.errors[0].location.contains("b.test"));
    assert!(out.errors[0].reason.contains("part of the handshake limit"));
    assert!(out.errors[1].location.contains("c.test"));
    assert!(out.errors[1]
        .reason
        .contains("all handshakes for this address"));
    // The second name still gets a verdict: with a budget of 1 the tool runs the hybrid handshake.
    let second = out
        .inventory
        .iter()
        .find(|item| {
            item.kind == pqaudit_core::InventoryKind::Endpoint
                && item.occurrences.iter().any(
                    |o| matches!(&o.location, Location::Endpoint { host, .. } if host == "b.test"),
                )
        })
        .expect("an endpoint item for the second name");
    assert!(second.pq_ready);
}

#[tokio::test]
async fn failed_classical_handshake_after_hybrid_is_an_error() {
    // The server accepts the hybrid group only. The classical handshake fails.
    let (address, _) = tls_server(vec![kx_group::X25519MLKEM768], ecdsa_identity()).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![target_for(address, 2)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(false),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.errors[0].reason.contains("tls-classical"));
}

#[tokio::test]
async fn failed_legacy_check_is_an_error() {
    // The server answers the two normal handshakes. It never answers the third connection.
    let config = server_config(hybrid_groups(), ecdsa_identity());
    let (address, _) = serve(config, Mode::SilentAfter(2)).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let mut limits = limits();
    limits.read_timeout = Duration::from_secs(1);
    let plan = TargetPlan {
        targets: vec![target_for(address, 3)],
        refused: Vec::new(),
        limits,
    };
    let out = run(
        &plan,
        &RealProbes::new(true),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.errors[0].reason.contains("old protocol versions"));
}

#[derive(Debug)]
struct BadChain(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for BadChain {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[tokio::test]
async fn unreadable_chain_certificate_is_an_error() {
    let identity = ecdsa_identity();
    let key = aws_lc_rs::sign::any_supported_type(&PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.key,
    )))
    .unwrap();
    // The certificate is not valid DER.
    let certified = rustls::sign::CertifiedKey::new(
        vec![CertificateDer::from(vec![0x30, 0x03, 0x01, 0x02, 0x03])],
        key,
    );
    let config = ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(BadChain(Arc::new(certified))));
    let (address, _) = serve(config, Mode::Normal).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let plan = TargetPlan {
        targets: vec![target_for(address, 2)],
        refused: Vec::new(),
        limits: limits(),
    };
    let out = run(
        &plan,
        &RealProbes::new(false),
        &audit,
        Uuid::new_v4(),
        default_pack(),
    )
    .await;
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    assert!(out.errors[0].reason.contains("not readable"));
}

#[tokio::test]
async fn slow_close_does_not_lose_the_result() {
    // The server finishes the handshake and then never reads or writes.
    let config = server_config(hybrid_groups(), ecdsa_identity());
    let (address, _) = serve(config, Mode::HoldAfterHandshake).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = audit_in(&dir);
    let mut limits = limits();
    limits.read_timeout = Duration::from_secs(1);
    let ctx = ProbeCtx::new(limits, &audit, Uuid::new_v4());
    let started = Instant::now();
    let result = RealProbes::new(false)
        .tls(&target_for(address, 2), &ctx)
        .await;
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(result.obs.pq_hybrid_supported, Some(true));
    assert!(result.failures.is_empty(), "{:?}", result.failures);
    assert!(read_entries(&dir).iter().all(|e| e.outcome == "ok"));
}
