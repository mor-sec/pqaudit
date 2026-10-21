//! Tests of the SSH probe against fake servers in the same process.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use pqaudit_core::{InventoryKind, Location, Protocol, ThreatType};
use pqaudit_rules::embedded::default_pack;
use pqaudit_scan_net::audit::{AuditEntry, AuditLog};
use pqaudit_scan_net::runtime::{run, NetOutput};
use pqaudit_scan_net::scope::{Limits, PlannedTarget, TargetPlan};
use pqaudit_scan_net::ssh::{self, SshProbeError};
use pqaudit_scan_net::tls::RealProbes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use uuid::Uuid;

const OPENSSH_BANNER: &str = "SSH-2.0-OpenSSH_9.9\r\n";
const OPENSSH_KEX: &str = "mlkem768x25519-sha256,sntrup761x25519-sha512,\
sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org,\
ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,\
diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group14-sha256,\
ext-info-s,kex-strict-s-v00@openssh.com";
const OPENSSH_HOST_KEYS: &str = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519";
const OPENSSH_CIPHERS: &str = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,\
aes128-gcm@openssh.com,aes256-gcm@openssh.com";
const OPENSSH_MACS: &str = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,\
umac-64@openssh.com,umac-128@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1";

fn name_list(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u32).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}

/// A KEXINIT binary packet without encryption.
fn kexinit(kex: &str, host_keys: &str, ciphers: &str, macs: &str) -> Vec<u8> {
    let mut payload = vec![20u8];
    payload.extend_from_slice(&[0xab; 16]);
    name_list(&mut payload, kex);
    name_list(&mut payload, host_keys);
    name_list(&mut payload, ciphers); // encryption client to server
    name_list(&mut payload, ciphers); // encryption server to client
    name_list(&mut payload, macs); // mac client to server
    name_list(&mut payload, macs); // mac server to client
    for _ in 0..4 {
        name_list(&mut payload, "none"); // compression and languages
    }
    payload.push(0); // first_kex_packet_follows
    payload.extend_from_slice(&[0; 4]);
    packet(&payload)
}

/// Wrap a payload in a binary packet with padding.
fn packet(payload: &[u8]) -> Vec<u8> {
    let mut padding = 8 - (5 + payload.len()) % 8;
    if padding < 4 {
        padding += 8;
    }
    let length = 1 + payload.len() + padding;
    let mut out = Vec::new();
    out.extend_from_slice(&(length as u32).to_be_bytes());
    out.push(padding as u8);
    out.extend_from_slice(payload);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

fn openssh_script(kex: &str, host_keys: &str) -> Vec<u8> {
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    script.extend(kexinit(kex, host_keys, OPENSSH_CIPHERS, OPENSSH_MACS));
    script
}

/// Start a server. It sends the script, then reads until the client closes.
/// The task result is every byte that the client sent.
async fn fake_server(script: Vec<u8>) -> (SocketAddr, JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // The client can close early. A failed write is not an error here.
        let _ = stream.write_all(&script).await;
        let mut received = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut received)).await;
        received
    });
    (address, task)
}

fn limits() -> Limits {
    let mut limits = Limits::DEFAULT;
    limits.min_interval = Duration::from_millis(10);
    limits
}

async fn probe_script(script: Vec<u8>) -> Result<pqaudit_core::SshObservation, SshProbeError> {
    let (address, _) = fake_server(script).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    ssh::probe(&mut stream, &limits()).await
}

fn target_for(address: SocketAddr) -> PlannedTarget {
    PlannedTarget {
        host: Some(String::from("localhost")),
        ip: address.ip(),
        port: address.port(),
        protocol: Protocol::Ssh,
        connections: 1,
    }
}

async fn scan(script: Vec<u8>) -> (NetOutput, Vec<AuditEntry>) {
    let (address, _) = fake_server(script).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(&dir.path().join("audit.log")).unwrap();
    let plan = TargetPlan {
        targets: vec![target_for(address)],
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
    let entries = std::fs::read_to_string(dir.path().join("audit.log"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<AuditEntry>(line).unwrap())
        .filter(|entry| entry.outcome != "started")
        .collect();
    (out, entries)
}

#[tokio::test]
async fn parses_openssh_kexinit() {
    let obs = probe_script(openssh_script(OPENSSH_KEX, OPENSSH_HOST_KEYS))
        .await
        .unwrap();
    assert_eq!(obs.banner, "SSH-2.0-OpenSSH_9.9");
    assert_eq!(obs.kex.len(), 14);
    assert_eq!(obs.kex[0], "mlkem768x25519-sha256");
    assert_eq!(obs.kex[13], "kex-strict-s-v00@openssh.com");
    assert_eq!(
        obs.host_key_algorithms,
        [
            "rsa-sha2-512",
            "rsa-sha2-256",
            "ecdsa-sha2-nistp256",
            "ssh-ed25519"
        ]
    );
    assert_eq!(obs.ciphers.len(), 6);
    assert_eq!(obs.ciphers[0], "chacha20-poly1305@openssh.com");
    assert_eq!(obs.macs.len(), 10);
    assert_eq!(obs.macs[9], "hmac-sha1");
}

#[tokio::test]
async fn pq_kex_gives_inventory_and_no_finding() {
    let (out, entries) = scan(openssh_script(OPENSSH_KEX, OPENSSH_HOST_KEYS)).await;
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    assert!(out.findings.iter().all(|f| f.rule_id != "ssh.no-pq-kex"));
    let item = out
        .inventory
        .iter()
        .find(|item| item.kind == InventoryKind::Endpoint)
        .expect("an endpoint inventory item");
    assert!(item.pq_ready);
    assert_eq!(item.endpoint.as_ref().unwrap().protocol, Protocol::Ssh);
    // The host keys are classical, so there is one finding for them.
    assert!(out
        .findings
        .iter()
        .any(|f| f.rule_id == "ssh.classical-hostkey"));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].probe, "ssh-kexinit");
    assert_eq!(entries[0].outcome, "ok");
    assert!(entries[0].bytes_sent > 0 && entries[0].bytes_received > 0);
}

#[tokio::test]
async fn no_pq_kex_finding() {
    let kex = "curve25519-sha256,ecdh-sha2-nistp256,ext-info-s";
    let (out, _) = scan(openssh_script(kex, OPENSSH_HOST_KEYS)).await;
    assert!(out.errors.is_empty(), "{:?}", out.errors);
    let finding = out
        .findings
        .iter()
        .find(|f| f.rule_id == "ssh.no-pq-kex")
        .expect("a no-pq finding");
    assert_eq!(finding.threat_type, ThreatType::Hndl);
    let ssh = finding.endpoint.as_ref().unwrap().ssh.as_ref().unwrap();
    assert_eq!(ssh.kex.len(), 3);
    match &finding.occurrences[0].location {
        Location::Endpoint { port, protocol, .. } => {
            assert_eq!(*protocol, Protocol::Ssh);
            assert_ne!(*port, 0);
        }
        other => panic!("wrong location: {other:?}"),
    }
    assert!(out.inventory.iter().all(|item| !item.pq_ready));
}

#[tokio::test]
async fn weak_kex_finding() {
    let kex = "mlkem768x25519-sha256,diffie-hellman-group14-sha1,curve25519-sha256";
    let (out, _) = scan(openssh_script(kex, OPENSSH_HOST_KEYS)).await;
    let finding = out
        .findings
        .iter()
        .find(|f| f.rule_id == "ssh.weak-kex")
        .expect("a weak-kex finding");
    assert_eq!(finding.threat_type, ThreatType::ClassicalWeakNow);
    assert_eq!(
        finding.algorithm.as_ref().unwrap().name,
        "diffie-hellman-group14-sha1"
    );
    // A post-quantum name is also in the list, so there is no no-pq finding.
    assert!(out.findings.iter().all(|f| f.rule_id != "ssh.no-pq-kex"));
}

#[tokio::test]
async fn classical_hostkey_finding_needs_only_classical_names() {
    let (out, _) = scan(openssh_script(OPENSSH_KEX, "ssh-ed25519,ssh-rsa")).await;
    let finding = out
        .findings
        .iter()
        .find(|f| f.rule_id == "ssh.classical-hostkey")
        .expect("a host key finding");
    assert_eq!(finding.threat_type, ThreatType::ForgeryShortLived);
    // One unknown name stops the finding.
    let (out, _) = scan(openssh_script(OPENSSH_KEX, "ssh-ed25519,ssh-mldsa65")).await;
    assert!(out
        .findings
        .iter()
        .all(|f| f.rule_id != "ssh.classical-hostkey"));
}

#[tokio::test]
async fn pre_banner_lines_skipped() {
    let mut script = b"Welcome to the test host.\r\nThis line is not a banner.\n".to_vec();
    script.extend(openssh_script(OPENSSH_KEX, OPENSSH_HOST_KEYS));
    let obs = probe_script(script).await.unwrap();
    assert_eq!(obs.banner, "SSH-2.0-OpenSSH_9.9");
    assert_eq!(obs.kex[0], "mlkem768x25519-sha256");
}

#[tokio::test]
async fn endless_banner_is_capped() {
    // 1000 lines and no banner. The server stops when the client closes.
    let script: Vec<u8> = (0..1000).flat_map(|_| b"hello\r\n".to_vec()).collect();
    let (address, _) = fake_server(script).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    let error = ssh::probe(&mut stream, &limits()).await.unwrap_err();
    assert!(matches!(error, SshProbeError::BannerTooLong), "{error:?}");
    assert!(error.to_string().contains("too long"));
}

#[tokio::test]
async fn sixty_four_lines_then_banner_is_accepted() {
    let mut script: Vec<u8> = (0..63).flat_map(|_| b"hello\r\n".to_vec()).collect();
    script.extend(openssh_script(OPENSSH_KEX, OPENSSH_HOST_KEYS));
    assert!(probe_script(script).await.is_ok());
    let mut script: Vec<u8> = (0..64).flat_map(|_| b"hello\r\n".to_vec()).collect();
    script.extend(openssh_script(OPENSSH_KEX, OPENSSH_HOST_KEYS));
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::BannerTooLong)
    ));
}

#[tokio::test]
async fn endless_line_is_capped() {
    // A line with no end. The server writes until the client closes.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let chunk = [b'a'; 1024];
        while stream.write_all(&chunk).await.is_ok() {}
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    let error = ssh::probe(&mut stream, &limits()).await.unwrap_err();
    assert!(matches!(error, SshProbeError::BannerTooLong), "{error:?}");
}

#[tokio::test]
async fn banner_line_of_256_bytes_is_too_long() {
    let mut line = b"SSH-2.0-".to_vec();
    line.extend(std::iter::repeat_n(b'x', 256 - 8 - 2));
    line.extend_from_slice(b"\r\n");
    assert_eq!(line.len(), 256);
    assert!(matches!(
        probe_script(line).await,
        Err(SshProbeError::BannerTooLong)
    ));
}

#[tokio::test]
async fn banner_text_is_cleaned() {
    let mut script = b"SSH-2.0-evil\x1b[31m\x07\xff\r\n".to_vec();
    script.extend(kexinit(
        OPENSSH_KEX,
        OPENSSH_HOST_KEYS,
        OPENSSH_CIPHERS,
        OPENSSH_MACS,
    ));
    let obs = probe_script(script).await.unwrap();
    assert!(obs.banner.starts_with("SSH-2.0-evil"));
    assert!(
        obs.banner.chars().all(|c| !c.is_control()),
        "{:?}",
        obs.banner
    );
}

#[tokio::test]
async fn oversized_packet_is_rejected() {
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    script.extend_from_slice(&0x7fff_ffffu32.to_be_bytes());
    script.extend_from_slice(&[0u8; 64]);
    let error = probe_script(script).await.unwrap_err();
    assert!(matches!(error, SshProbeError::PacketTooLarge), "{error:?}");
}

#[tokio::test]
async fn packet_one_byte_above_the_limit_is_rejected() {
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    script.extend_from_slice(&35_001u32.to_be_bytes());
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::PacketTooLarge)
    ));
}

#[tokio::test]
async fn bad_packets_are_errors() {
    // Not a KEXINIT message.
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    script.extend(packet(&[21, 0, 0, 0]));
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::NotKexInit)
    ));
    // A name list that is longer than the packet.
    let mut payload = vec![20u8];
    payload.extend_from_slice(&[0; 16]);
    payload.extend_from_slice(&1000u32.to_be_bytes());
    payload.extend_from_slice(b"abc");
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    script.extend(packet(&payload));
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::PacketInvalid)
    ));
    // A packet length of zero.
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    script.extend_from_slice(&0u32.to_be_bytes());
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::PacketInvalid)
    ));
    // Padding that is longer than the packet.
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    script.extend_from_slice(&[0, 0, 0, 6, 200, 20, 0, 0, 0, 0]);
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::PacketInvalid)
    ));
    // A name with a control character.
    let script = openssh_script("curve25519-sha256,\x1b[2J", OPENSSH_HOST_KEYS);
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::PacketInvalid)
    ));
    // Too many names.
    let many = vec!["a"; 300].join(",");
    let script = openssh_script(&many, OPENSSH_HOST_KEYS);
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::PacketInvalid)
    ));
}

#[tokio::test]
async fn closed_connection_is_an_error() {
    let mut script = OPENSSH_BANNER.as_bytes().to_vec();
    let full = kexinit(
        OPENSSH_KEX,
        OPENSSH_HOST_KEYS,
        OPENSSH_CIPHERS,
        OPENSSH_MACS,
    );
    script.extend_from_slice(&full[..full.len() / 2]);
    assert!(matches!(
        probe_script(script).await,
        Err(SshProbeError::Closed)
    ));
    assert!(matches!(
        probe_script(b"SSH-2.0-x".to_vec()).await,
        Err(SshProbeError::Closed)
    ));
}

#[tokio::test]
async fn never_sends_kexinit() {
    let (address, server) = fake_server(openssh_script(OPENSSH_KEX, OPENSSH_HOST_KEYS)).await;
    let mut stream = TcpStream::connect(address).await.unwrap();
    ssh::probe(&mut stream, &limits()).await.unwrap();
    drop(stream);
    let received = server.await.unwrap();
    let expected = format!("SSH-2.0-pqaudit_{}\r\n", env!("CARGO_PKG_VERSION"));
    assert_eq!(String::from_utf8(received).unwrap(), expected);
}

#[tokio::test]
async fn silent_server_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(30)).await;
        drop(stream);
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut limits = limits();
    limits.read_timeout = Duration::from_millis(300);
    let started = Instant::now();
    let error = ssh::probe(&mut stream, &limits).await.unwrap_err();
    assert!(matches!(error, SshProbeError::Timeout), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn slow_trickle_stops_at_the_read_timeout() {
    // One byte each 100 ms. The timeout is for the whole exchange, not for each read.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        for _ in 0..200 {
            if stream.write_all(b"x").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    let mut limits = limits();
    limits.read_timeout = Duration::from_millis(500);
    let started = Instant::now();
    let error = ssh::probe(&mut stream, &limits).await.unwrap_err();
    assert!(matches!(error, SshProbeError::Timeout), "{error:?}");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test]
async fn probe_failure_is_a_scan_error() {
    let (out, entries) = scan(b"hello\r\n".repeat(100)).await;
    assert!(out.findings.is_empty());
    assert_eq!(out.errors.len(), 1);
    assert!(
        out.errors[0].reason.contains("too long"),
        "{:?}",
        out.errors
    );
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].outcome, "ssh-failed");
}

#[tokio::test]
async fn refused_connection_is_a_scan_error() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(&dir.path().join("audit.log")).unwrap();
    let plan = TargetPlan {
        targets: vec![PlannedTarget {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            ..target_for(address)
        }],
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
    assert_eq!(out.errors.len(), 1);
    assert!(out.findings.is_empty());
}

#[tokio::test]
async fn one_ssh_connection_for_each_address_and_port() {
    // Two names for one address and port: localhost and the address itself.
    let (address, _) = fake_server(openssh_script(OPENSSH_KEX, OPENSSH_HOST_KEYS)).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = AuditLog::open(&dir.path().join("audit.log")).unwrap();
    let mut by_address = target_for(address);
    by_address.host = None;
    let plan = TargetPlan {
        targets: vec![target_for(address), by_address],
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
    let limit_errors: Vec<_> = out
        .errors
        .iter()
        .filter(|e| {
            e.reason
                .contains("used the SSH connection for this address and port")
        })
        .collect();
    assert_eq!(limit_errors.len(), 1, "{:?}", out.errors);
    assert_eq!(out.errors.len(), 1, "{:?}", out.errors);
    let connections = std::fs::read_to_string(dir.path().join("audit.log"))
        .unwrap()
        .lines()
        .filter(|line| line.contains("\"started\""))
        .count();
    assert_eq!(connections, 1, "the tool makes one SSH connection");
}
