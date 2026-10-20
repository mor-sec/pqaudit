//! The audit log: one JSON line for each connection attempt.
//!
//! A consultant can give the log to the client as proof of each connection.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};

use chrono::{DateTime, Utc};
use pqaudit_core::Protocol;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use uuid::Uuid;

/// One line of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEntry {
    /// The time when the connection attempt started.
    pub ts: DateTime<Utc>,
    /// The ID of the run.
    pub run_id: Uuid,
    /// The local IP address of the connection. It is `None` if the connect failed.
    pub src_ip: Option<IpAddr>,
    /// The host name of the target, if the scope has one.
    pub dst_host: Option<String>,
    /// The IP address that the tool connected to.
    pub dst_ip: IpAddr,
    /// The port.
    pub port: u16,
    /// The protocol.
    pub protocol: Protocol,
    /// The probe: `tls-hybrid`, `tls-classical`, `tls-legacy`, or `ssh-kexinit`.
    pub probe: String,
    /// The result, for example `ok`, `timeout`, or `connect-failed: ...`.
    pub outcome: String,
    /// The number of bytes that the tool sent.
    pub bytes_sent: u64,
    /// The number of bytes that the tool received.
    pub bytes_received: u64,
    /// The time from the start of the attempt to its end, in milliseconds.
    pub duration_ms: u64,
}

/// The audit log file. The tool only adds lines to it.
#[derive(Debug)]
pub struct AuditLog {
    file: Mutex<File>,
    broken: AtomicBool,
}

impl AuditLog {
    /// Open the log. Make the file if it does not exist. Add new lines at the end.
    pub fn open(path: &Path) -> io::Result<AuditLog> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(AuditLog {
            file: Mutex::new(file),
            broken: AtomicBool::new(false),
        })
    }

    /// Add one line to the log.
    ///
    /// If the write fails, the log sets its broken flag. The runtime then makes no more connections.
    pub fn record(&self, entry: &AuditEntry) -> io::Result<()> {
        let result = self.write_line(entry);
        if result.is_err() {
            self.mark_broken();
        }
        result
    }

    fn write_line(&self, entry: &AuditEntry) -> io::Result<()> {
        let mut line = serde_json::to_vec(entry).map_err(io::Error::other)?;
        line.push(b'\n');
        let mut file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        file.write_all(&line)?;
        file.flush()
    }

    /// True if a write failed. A broken log means the tool must not connect.
    pub fn is_broken(&self) -> bool {
        self.broken.load(Ordering::SeqCst)
    }

    /// Set the log to the broken state.
    pub fn mark_broken(&self) {
        self.broken.store(true, Ordering::SeqCst);
    }

    /// Write the data of the log to the disk.
    pub fn sync(&self) -> io::Result<()> {
        let file = self.file.lock().unwrap_or_else(PoisonError::into_inner);
        file.sync_all()
    }
}

/// Return the SHA-256 hash of a file in hex.
pub fn hash_file(path: &Path) -> io::Result<String> {
    use std::fmt::Write as _;
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let mut hex = String::with_capacity(64);
    for byte in hasher.finalize() {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(hex)
}

/// Counts of the bytes of one connection. The stream and the audit guard share them.
#[derive(Debug, Default)]
pub struct ByteCounts {
    sent: AtomicU64,
    received: AtomicU64,
}

impl ByteCounts {
    /// The number of bytes sent.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::Relaxed)
    }

    /// The number of bytes received.
    pub fn received(&self) -> u64 {
        self.received.load(Ordering::Relaxed)
    }
}

/// A stream that counts the bytes that pass through it.
#[derive(Debug)]
pub struct CountingStream<S> {
    inner: S,
    counts: Arc<ByteCounts>,
}

impl<S> CountingStream<S> {
    /// Wrap a stream. Read the counts from the shared `ByteCounts`.
    pub fn new(inner: S, counts: Arc<ByteCounts>) -> Self {
        Self { inner, counts }
    }

    /// The shared counts.
    pub fn counts(&self) -> &Arc<ByteCounts> {
        &self.counts
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let added = buf.filled().len().saturating_sub(before);
            self.counts
                .received
                .fetch_add(added as u64, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(count)) = &poll {
            self.counts.sent.fetch_add(*count as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        if let Poll::Ready(Ok(count)) = &poll {
            self.counts.sent.fetch_add(*count as u64, Ordering::Relaxed);
        }
        poll
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
