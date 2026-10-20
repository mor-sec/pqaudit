//! Helpers for the key store tests.
//!
//! `keytool` is not available, so this code writes Java key stores.
//!
//! All numbers in the key store are big-endian.
//! The file starts with the magic number: `FE ED FE ED` (JKS) or `CE CE CE CE` (JCEKS).
//! Then come the version (4 bytes, here 2) and the entry count (4 bytes).
//! Then come the entries.
//!
//! A hash of 20 bytes ends the file.
//! Java computes it from the password. The reader ignores it.
//!
//! Each entry has a tag (4 bytes), an alias, a time (8 bytes), and data.
//! An alias is a 2-byte length and text.
//! Tag 2 is a trusted certificate. Its data is one certificate.
//! A certificate is a type text "X.509", a 4-byte length, and DER bytes.
//!
//! Tag 1 is a private key in a JKS file. Its data starts with a 4-byte length and the encrypted key.
//! Then it has a 4-byte certificate count.
//! Then it has each certificate, written as for tag 2.
//!
//! Tag 1 in a JCEKS file is different. Its data is a Java serialized object.
//! The object starts with `AC ED 00 05` and has no length in front of it.
//! The writer puts the "encrypted key" bytes after these 4 bytes.

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;

/// The JKS magic number.
pub const JKS_MAGIC: [u8; 4] = [0xFE, 0xED, 0xFE, 0xED];
/// The JCEKS magic number.
pub const JCEKS_MAGIC: [u8; 4] = [0xCE, 0xCE, 0xCE, 0xCE];

/// One entry to write.
pub enum Entry {
    /// A trusted certificate with DER bytes.
    Trusted { alias: &'static str, cert: Vec<u8> },
    /// A private key entry. The key bytes are "encrypted", so the tests can use any bytes.
    Key {
        alias: &'static str,
        encrypted_key: Vec<u8>,
        chain: Vec<Vec<u8>>,
    },
}

fn put_u16(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u16::try_from(value).unwrap().to_be_bytes());
}

fn put_u32(out: &mut Vec<u8>, value: usize) {
    out.extend_from_slice(&u32::try_from(value).unwrap().to_be_bytes());
}

fn put_text(out: &mut Vec<u8>, text: &str) {
    put_u16(out, text.len());
    out.extend_from_slice(text.as_bytes());
}

fn put_cert(out: &mut Vec<u8>, der: &[u8]) {
    put_text(out, "X.509");
    put_u32(out, der.len());
    out.extend_from_slice(der);
}

/// Write a key store with the given magic number.
pub fn write_store(magic: [u8; 4], entries: &[Entry]) -> Vec<u8> {
    let mut out = magic.to_vec();
    put_u32(&mut out, 2);
    put_u32(&mut out, entries.len());
    for entry in entries {
        match entry {
            Entry::Trusted { alias, cert } => {
                put_u32(&mut out, 2);
                put_text(&mut out, alias);
                out.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
                put_cert(&mut out, cert);
            }
            Entry::Key {
                alias,
                encrypted_key,
                chain,
            } => {
                put_u32(&mut out, 1);
                put_text(&mut out, alias);
                out.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
                if magic == JCEKS_MAGIC {
                    out.extend_from_slice(&[0xAC, 0xED, 0x00, 0x05]);
                    out.extend_from_slice(encrypted_key);
                    continue;
                }
                put_u32(&mut out, encrypted_key.len());
                out.extend_from_slice(encrypted_key);
                put_u32(&mut out, chain.len());
                for cert in chain {
                    put_cert(&mut out, cert);
                }
            }
        }
    }
    // The filler hash. A real store holds a SHA-1 hash here.
    out.extend_from_slice(&[0xA5; 20]);
    out
}

/// Return the path of a fixture file.
pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Read all certificates of a PEM fixture as DER bytes.
pub fn pem_to_der(name: &str) -> Vec<Vec<u8>> {
    let text = std::fs::read_to_string(fixture(name)).unwrap();
    let mut certs = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    for line in text.lines() {
        if line.starts_with("-----BEGIN") {
            inside = true;
            body.clear();
        } else if line.starts_with("-----END") {
            inside = false;
            certs.push(STANDARD.decode(&body).unwrap());
        } else if inside {
            body.push_str(line.trim());
        }
    }
    certs
}

/// Make bytes that look random. The same seed gives the same bytes.
pub fn pseudo_random(seed: u64, length: usize) -> Vec<u8> {
    let mut state = seed;
    (0..length)
        .map(|_| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as u8
        })
        .collect()
}
