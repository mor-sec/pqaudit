//! The SSH probe. It reads the banner and the KEXINIT message of the server.
//!
//! The tool sends its own banner. It never sends a KEXINIT message, so no key exchange starts.
//! The server is not trusted. Each read has a size limit, and one timeout covers the exchange.

use std::time::Duration;

use pqaudit_core::SshObservation;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

use crate::messages;
use crate::scope::Limits;

/// The probe name in the audit log.
pub const PROBE_NAME: &str = "ssh-kexinit";

/// The most lines that the tool reads before the banner.
const MAX_BANNER_LINES: usize = 64;
/// The longest line, with the end of line. RFC 4253 sets this limit.
const MAX_LINE_BYTES: usize = 255;
/// The largest `packet_length` that the tool accepts.
const MAX_PACKET_BYTES: usize = 35_000;
/// The most names in one name list.
const MAX_NAMES: usize = 256;
/// The longest name, in bytes.
const MAX_NAME_BYTES: usize = 128;
/// The size of one read.
const READ_CHUNK: usize = 4096;
/// The length of the cookie in a KEXINIT message.
const COOKIE_BYTES: usize = 16;
/// The message number of SSH_MSG_KEXINIT.
const MSG_KEXINIT: u8 = 20;
/// The time to wait when the tool closes the stream.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(1);

/// Why an SSH probe failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SshProbeError {
    /// The server sent too many lines, or a line that is too long, before the banner.
    BannerTooLong,
    /// The packet length is above the limit.
    PacketTooLarge,
    /// The packet is not valid.
    PacketInvalid,
    /// The first packet is not a KEXINIT message.
    NotKexInit,
    /// The server closed the connection before the exchange ended.
    Closed,
    /// A read or write failed. The value is the reason.
    Io(String),
    /// The exchange did not finish in the read timeout.
    Timeout,
}

impl std::fmt::Display for SshProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BannerTooLong => f.write_str(messages::SSH_BANNER_TOO_LONG),
            Self::PacketTooLarge => f.write_str(
                &messages::SSH_PACKET_TOO_LARGE.replace("{max}", &MAX_PACKET_BYTES.to_string()),
            ),
            Self::PacketInvalid => f.write_str(messages::SSH_PACKET_INVALID),
            Self::NotKexInit => f.write_str(messages::SSH_NOT_KEXINIT),
            Self::Closed => f.write_str(messages::SSH_CLOSED),
            Self::Io(reason) => f.write_str(&messages::SSH_IO.replace("{reason}", reason)),
            Self::Timeout => f.write_str(messages::SSH_TIMEOUT),
        }
    }
}

impl std::error::Error for SshProbeError {}

fn io_error(error: &std::io::Error) -> SshProbeError {
    if error.kind() == std::io::ErrorKind::UnexpectedEof {
        SshProbeError::Closed
    } else {
        SshProbeError::Io(error.to_string().chars().take(200).collect())
    }
}

/// Read the banner and the KEXINIT message of a server.
///
/// One timeout, `limits.read_timeout`, covers the whole exchange.
/// The function does not close the stream. The caller must drop it.
pub async fn probe<S>(stream: &mut S, limits: &Limits) -> Result<SshObservation, SshProbeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match timeout(limits.read_timeout, exchange(stream)).await {
        Ok(result) => result,
        Err(_) => Err(SshProbeError::Timeout),
    }
}

/// Close the write side of a stream. A slow peer cannot hold the tool.
pub async fn close<S>(stream: &mut S)
where
    S: AsyncWrite + Unpin,
{
    let _ = timeout(CLOSE_TIMEOUT, stream.shutdown()).await;
}

/// A buffer for the bytes that the server sent. It never holds much more than one packet.
struct Input<'a, S> {
    stream: &'a mut S,
    buffer: Vec<u8>,
}

impl<S: AsyncRead + Unpin> Input<'_, S> {
    /// Read more bytes from the stream.
    async fn fill(&mut self) -> Result<(), SshProbeError> {
        let mut chunk = [0u8; READ_CHUNK];
        let count = self
            .stream
            .read(&mut chunk)
            .await
            .map_err(|e| io_error(&e))?;
        if count == 0 {
            return Err(SshProbeError::Closed);
        }
        self.buffer.extend_from_slice(&chunk[..count]);
        Ok(())
    }

    /// Read one line, with its end of line. A line has at most `MAX_LINE_BYTES` bytes.
    async fn line(&mut self) -> Result<Vec<u8>, SshProbeError> {
        loop {
            let window = self.buffer.len().min(MAX_LINE_BYTES);
            if let Some(end) = self.buffer[..window].iter().position(|byte| *byte == b'\n') {
                return Ok(self.buffer.drain(..=end).collect());
            }
            if self.buffer.len() >= MAX_LINE_BYTES {
                return Err(SshProbeError::BannerTooLong);
            }
            self.fill().await?;
        }
    }

    /// Read exactly `count` bytes. The caller checks that `count` is small.
    async fn bytes(&mut self, count: usize) -> Result<Vec<u8>, SshProbeError> {
        while self.buffer.len() < count {
            self.fill().await?;
        }
        Ok(self.buffer.drain(..count).collect())
    }
}

/// Replace the control characters. A banner can go to a terminal.
fn clean(bytes: &[u8]) -> String {
    pqaudit_core::text::clean_bytes(bytes)
}

async fn exchange<S>(stream: &mut S) -> Result<SshObservation, SshProbeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut input = Input {
        stream,
        buffer: Vec::new(),
    };
    let mut banner = None;
    for _ in 0..MAX_BANNER_LINES {
        let line = input.line().await?;
        if line.starts_with(b"SSH-") {
            let text = line.strip_suffix(b"\n").unwrap_or(&line);
            let text = text.strip_suffix(b"\r").unwrap_or(text);
            banner = Some(clean(text));
            break;
        }
    }
    let banner = banner.ok_or(SshProbeError::BannerTooLong)?;

    let ours = format!("SSH-2.0-pqaudit_{}\r\n", env!("CARGO_PKG_VERSION"));
    input
        .stream
        .write_all(ours.as_bytes())
        .await
        .map_err(|e| io_error(&e))?;
    input.stream.flush().await.map_err(|e| io_error(&e))?;

    let header = input.bytes(4).await?;
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if length > MAX_PACKET_BYTES {
        return Err(SshProbeError::PacketTooLarge);
    }
    // The packet holds the padding length, one message byte, and the padding at least.
    if length < 2 {
        return Err(SshProbeError::PacketInvalid);
    }
    let body = input.bytes(length).await?;
    let padding = usize::from(body[0]);
    if padding + 2 > length {
        return Err(SshProbeError::PacketInvalid);
    }
    let payload = &body[1..length - padding];
    if payload[0] != MSG_KEXINIT {
        return Err(SshProbeError::NotKexInit);
    }
    let mut cursor = Cursor {
        rest: &payload[1..],
    };
    cursor.take(COOKIE_BYTES)?;
    // The order is: kex, host key, cipher to server, cipher to client, mac to server, mac to client.
    let kex = cursor.name_list()?;
    let host_key_algorithms = cursor.name_list()?;
    cursor.name_list()?;
    let ciphers = cursor.name_list()?;
    cursor.name_list()?;
    let macs = cursor.name_list()?;
    Ok(SshObservation {
        banner,
        kex,
        host_key_algorithms,
        ciphers,
        macs,
    })
}

/// A reader for the bytes of a packet payload.
struct Cursor<'a> {
    rest: &'a [u8],
}

impl<'a> Cursor<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], SshProbeError> {
        if self.rest.len() < count {
            return Err(SshProbeError::PacketInvalid);
        }
        let (head, tail) = self.rest.split_at(count);
        self.rest = tail;
        Ok(head)
    }

    /// Read a name list: a length, then names with commas between them.
    fn name_list(&mut self) -> Result<Vec<String>, SshProbeError> {
        let size = self.take(4)?;
        let size = u32::from_be_bytes([size[0], size[1], size[2], size[3]]) as usize;
        let text = self.take(size)?;
        if text.is_empty() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for name in text.split(|byte| *byte == b',') {
            // RFC 4251 allows printable US-ASCII in a name.
            let valid = !name.is_empty()
                && name.len() <= MAX_NAME_BYTES
                && name.iter().all(|byte| (0x21..0x7f).contains(byte));
            if !valid || names.len() >= MAX_NAMES {
                return Err(SshProbeError::PacketInvalid);
            }
            names.push(clean(name));
        }
        Ok(names)
    }
}
