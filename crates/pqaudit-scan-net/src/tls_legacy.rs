//! The check for old TLS versions. It uses a ClientHello that the tool makes by hand.
//!
//! The probe offers TLS 1.1 as the highest version and the usual TLS 1.0 and 1.1 cipher suites.
//! It reads the version from the ServerHello and closes the connection.
//! The probe reads 11 bytes of the reply at most. A hostile server cannot make it read more.

use rustls::crypto::aws_lc_rs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

use crate::messages;
use crate::runtime::{Connected, ProbeCtx};
use crate::scope::PlannedTarget;

/// The probe name in the audit log.
pub const PROBE_NAME: &str = "tls-legacy";

/// The version in the ClientHello: TLS 1.1.
const CLIENT_VERSION: u16 = 0x0302;
/// The version in the record layer of the ClientHello: TLS 1.0.
const RECORD_VERSION: u16 = 0x0301;

/// The record type of a handshake message.
const RECORD_HANDSHAKE: u8 = 0x16;
/// The record type of an alert.
const RECORD_ALERT: u8 = 0x15;
/// The handshake type of a ServerHello.
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;

/// The cipher suites of TLS 1.0 and 1.1, and the signal for secure renegotiation.
const CIPHER_SUITES: [u16; 10] = [
    0xC014, // ECDHE-RSA-AES256-SHA
    0xC013, // ECDHE-RSA-AES128-SHA
    0xC00A, // ECDHE-ECDSA-AES256-SHA
    0xC009, // ECDHE-ECDSA-AES128-SHA
    0x0039, // DHE-RSA-AES256-SHA
    0x0033, // DHE-RSA-AES128-SHA
    0x0035, // AES256-SHA
    0x002F, // AES128-SHA
    0x000A, // DES-CBC3-SHA
    0x00FF, // The signal for secure renegotiation
];

/// The elliptic curves in the ClientHello: secp256r1, secp384r1, and secp521r1.
const CURVES: [u16; 3] = [0x0017, 0x0018, 0x0019];

/// Probe a target for old protocol versions with one connection.
///
/// Return the old versions that the server accepts. An empty list means that the server
/// refused TLS 1.0 and 1.1. Return an error text if the server gives no usable answer.
pub async fn probe(ctx: &ProbeCtx<'_>, t: &PlannedTarget) -> Result<Vec<String>, String> {
    let hello = client_hello(t.host.as_deref())?;
    let Connected {
        mut stream,
        mut audit,
    } = ctx
        .connect(t, PROBE_NAME)
        .await
        .map_err(|e| e.to_string())?;
    let attempt = timeout(ctx.limits.read_timeout, async {
        stream.write_all(&hello).await.map_err(|e| e.to_string())?;
        stream.flush().await.map_err(|e| e.to_string())?;
        read_version(&mut stream).await
    })
    .await;
    match attempt {
        Ok(Ok(versions)) => {
            audit.set_outcome("ok");
            Ok(versions)
        }
        Ok(Err(reason)) => {
            audit.set_outcome("legacy-failed");
            Err(reason)
        }
        Err(_) => {
            audit.set_outcome("timeout");
            Err(messages::HANDSHAKE_TIMEOUT.replace("{probe}", PROBE_NAME))
        }
    }
}

/// Read the start of the reply and find the old version, if any.
async fn read_version<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<String>, String> {
    let bad = || messages::LEGACY_BAD_REPLY.to_string();
    let mut header = [0u8; 5];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|e| e.to_string())?;
    if header[1] != 3 {
        return Err(bad());
    }
    match header[0] {
        // A fatal alert, for example protocol_version. The server refuses the old versions.
        RECORD_ALERT => Ok(Vec::new()),
        RECORD_HANDSHAKE => {
            let length = usize::from(u16::from_be_bytes([header[3], header[4]]));
            // The handshake header has 4 bytes. The ServerHello starts with the version.
            if length < 6 {
                return Err(bad());
            }
            let mut start = [0u8; 6];
            stream
                .read_exact(&mut start)
                .await
                .map_err(|e| e.to_string())?;
            if start[0] != HANDSHAKE_SERVER_HELLO {
                return Err(bad());
            }
            match u16::from_be_bytes([start[4], start[5]]) {
                0x0300 => Ok(vec![String::from("SSL 3.0")]),
                0x0301 => Ok(vec![String::from("TLS 1.0")]),
                0x0302 => Ok(vec![String::from("TLS 1.1")]),
                // TLS 1.2 or later in answer to a TLS 1.1 offer is not a legacy version.
                0x0303 | 0x0304 => Ok(Vec::new()),
                _ => Err(bad()),
            }
        }
        _ => Err(bad()),
    }
}

/// Return true if the text is usable as an SNI host name.
fn valid_sni(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && host.parse::<std::net::IpAddr>().is_err()
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
}

/// Make the ClientHello record.
pub fn client_hello(host: Option<&str>) -> Result<Vec<u8>, String> {
    let mut random = [0u8; 32];
    aws_lc_rs::default_provider()
        .secure_random
        .fill(&mut random)
        .map_err(|_| messages::RANDOM_FAILED.to_string())?;

    let mut extensions = Vec::new();
    if let Some(name) = host.filter(|name| valid_sni(name)) {
        let name = name.as_bytes();
        let mut list = vec![0u8]; // The name type: host name.
        list.extend_from_slice(&(name.len() as u16).to_be_bytes());
        list.extend_from_slice(name);
        let mut data = (list.len() as u16).to_be_bytes().to_vec();
        data.extend_from_slice(&list);
        extension(&mut extensions, 0x0000, &data);
    }
    let mut curves = ((CURVES.len() * 2) as u16).to_be_bytes().to_vec();
    for curve in CURVES {
        curves.extend_from_slice(&curve.to_be_bytes());
    }
    extension(&mut extensions, 0x000a, &curves);
    extension(&mut extensions, 0x000b, &[0x01, 0x00]);

    let mut body = Vec::new();
    body.extend_from_slice(&CLIENT_VERSION.to_be_bytes());
    body.extend_from_slice(&random);
    body.push(0); // The session ID is empty.
    body.extend_from_slice(&((CIPHER_SUITES.len() * 2) as u16).to_be_bytes());
    for suite in CIPHER_SUITES {
        body.extend_from_slice(&suite.to_be_bytes());
    }
    body.extend_from_slice(&[1, 0]); // One compression method: null.
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);

    let mut handshake = vec![0x01];
    handshake.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&body);

    let mut record = vec![RECORD_HANDSHAKE];
    record.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}

fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}
