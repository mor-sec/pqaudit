//! Helpers that several test files share: in-process servers on 127.0.0.1.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection};

/// A TLS server on a thread. It accepts X25519 only, so it is not a post-quantum server.
pub fn classical_tls_server() -> SocketAddr {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec![String::from("localhost")])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let mut provider = aws_lc_rs::default_provider();
    provider.kx_groups = vec![kx_group::X25519];
    let config = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let config = config.clone();
            thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                if let Ok(mut connection) = ServerConnection::new(config) {
                    if connection.complete_io(&mut stream).is_ok() {
                        let mut sink = [0u8; 16];
                        let _ = stream.read(&mut sink);
                    }
                }
            });
        }
    });
    address
}

const BANNER: &str = "SSH-2.0-OpenSSH_9.9\r\n";
const KEX: &str = "curve25519-sha256,ecdh-sha2-nistp256,diffie-hellman-group14-sha256";
const HOST_KEYS: &str = "rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ssh-ed25519";
const CIPHERS: &str = "chacha20-poly1305@openssh.com,aes128-ctr,aes256-gcm@openssh.com";
const MACS: &str = "hmac-sha2-256-etm@openssh.com,hmac-sha2-512";

fn name_list(out: &mut Vec<u8>, text: &str) {
    out.extend_from_slice(&(text.len() as u32).to_be_bytes());
    out.extend_from_slice(text.as_bytes());
}

/// A KEXINIT binary packet without encryption.
fn kexinit() -> Vec<u8> {
    let mut payload = vec![20u8];
    payload.extend_from_slice(&[0xab; 16]);
    name_list(&mut payload, KEX);
    name_list(&mut payload, HOST_KEYS);
    name_list(&mut payload, CIPHERS);
    name_list(&mut payload, CIPHERS);
    name_list(&mut payload, MACS);
    name_list(&mut payload, MACS);
    for _ in 0..4 {
        name_list(&mut payload, "none");
    }
    payload.push(0);
    payload.extend_from_slice(&[0; 4]);
    let mut padding = 8 - (5 + payload.len()) % 8;
    if padding < 4 {
        padding += 8;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&((1 + payload.len() + padding) as u32).to_be_bytes());
    out.push(padding as u8);
    out.extend_from_slice(&payload);
    out.extend(std::iter::repeat_n(0u8, padding));
    out
}

/// A fake SSH server on a thread. It offers classical algorithms only.
/// It sends the banner and the KEXINIT packet, then reads until the client closes.
pub fn classical_ssh_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut script = BANNER.as_bytes().to_vec();
    script.extend(kexinit());
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            let script = script.clone();
            thread::spawn(move || {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let _ = stream.write_all(&script);
                let mut sink = [0u8; 256];
                while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
            });
        }
    });
    address
}

/// Install the repository rules pack as version 99.0.0, without a signature.
///
/// The pack goes into `<data>/rules/99.0.0`, the place that `rules update` uses.
pub fn install_unsigned_pack(data: &std::path::Path) {
    fn collect(dir: &std::path::Path, base: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if path.is_dir() {
                if name != "trust" {
                    collect(&path, base, out);
                }
            } else if name == "pack.toml" {
                out.push((
                    name,
                    b"id = \"pqaudit-default\"\nversion = \"99.0.0\"\n".to_vec(),
                ));
            } else {
                out.push((name, std::fs::read(&path).unwrap()));
            }
        }
    }
    let rules = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
    let mut files = Vec::new();
    collect(&rules, &rules, &mut files);
    let archive = pqaudit_rules::archive::build_archive(files).unwrap();
    let dir = data.join("rules").join("99.0.0");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("rules-99.0.0.tar.zst"), archive).unwrap();
}
