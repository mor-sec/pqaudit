//! Find the blocks of PEM text and tell what kind each block is.
//!
//! This code does not decode a block. The reader of each kind of block does that.
//! The decode function puts the bytes in a buffer that wipes itself on drop.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use zeroize::Zeroizing;

use crate::privkey;

/// The start of every PEM block.
pub(crate) const BEGIN: &[u8] = b"-----BEGIN ";
/// The end of a PEM label.
pub(crate) const DASHES: &[u8] = b"-----";
/// The PEM labels that hold an X.509 certificate.
pub(crate) const CERT_LABELS: [&[u8]; 3] =
    [b"CERTIFICATE", b"TRUSTED CERTIFICATE", b"X509 CERTIFICATE"];
/// The start of the label of an OpenPGP armor block.
const PGP_PREFIX: &[u8] = b"PGP ";
/// The longest label that the tool accepts, in bytes.
const MAX_LABEL: usize = 64;

/// What a PEM block holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockKind {
    /// An X.509 certificate.
    Certificate,
    /// A public or private key in a format that the tool reads.
    Key,
    /// An OpenPGP armor block.
    Pgp,
    /// Anything else. The tool does not read it.
    Other,
}

impl BlockKind {
    /// Find the kind of a block from its label.
    pub fn of(label: &[u8]) -> Self {
        if CERT_LABELS.contains(&label) {
            Self::Certificate
        } else if privkey::is_key_label(label) {
            Self::Key
        } else if label.starts_with(PGP_PREFIX) {
            Self::Pgp
        } else {
            Self::Other
        }
    }
}

/// One block of PEM text.
#[derive(Debug)]
pub struct Block<'a> {
    /// The label, for example `PRIVATE KEY`.
    pub label: &'a [u8],
    /// The kind of the block.
    pub kind: BlockKind,
    /// The text between the start line and the end line.
    pub body: &'a [u8],
    /// The line number of the start line. The first line is line 1.
    pub line: u32,
}

/// The blocks of a text.
#[derive(Debug, Default)]
pub struct Blocks<'a> {
    /// The blocks with an end line.
    pub blocks: Vec<Block<'a>>,
    /// The kind of a block that has no end line. A block like this ends the search.
    pub unclosed: Option<BlockKind>,
}

/// Find the first place of `needle` at or after `from`.
pub(crate) fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|index| index + from)
}

/// Find all blocks of a text.
pub fn blocks(data: &[u8]) -> Blocks<'_> {
    let mut result = Blocks::default();
    let mut cursor = 0;
    let mut line = 1u32;
    let mut counted = 0;
    while let Some(start) = find(data, BEGIN, cursor) {
        let label_start = start + BEGIN.len();
        let label_end = find(data, DASHES, label_start).filter(|end| {
            end - label_start <= MAX_LABEL && !data[label_start..*end].contains(&b'\n')
        });
        let Some(label_end) = label_end else {
            cursor = label_start;
            continue;
        };
        let label = &data[label_start..label_end];
        let body_start = label_end + DASHES.len();
        line = line.saturating_add(count_lines(&data[counted..start]));
        counted = start;
        let mut end_marker = b"-----END ".to_vec();
        end_marker.extend_from_slice(label);
        end_marker.extend_from_slice(DASHES);
        let Some(end) = find(data, &end_marker, body_start) else {
            result.unclosed = Some(BlockKind::of(label));
            break;
        };
        result.blocks.push(Block {
            label,
            kind: BlockKind::of(label),
            body: &data[body_start..end],
            line,
        });
        cursor = end + end_marker.len();
    }
    result
}

fn count_lines(data: &[u8]) -> u32 {
    u32::try_from(data.iter().filter(|byte| **byte == b'\n').count()).unwrap_or(u32::MAX)
}

/// Return true if the data has the start line of a block of the given kind.
///
/// The block does not need an end line. The data can be the start of a file.
pub fn has_kind(data: &[u8], kind: BlockKind) -> bool {
    let mut cursor = 0;
    while let Some(start) = find(data, BEGIN, cursor) {
        let label_start = start + BEGIN.len();
        cursor = label_start;
        let Some(label_end) = find(data, DASHES, label_start) else {
            return false;
        };
        let label = &data[label_start..label_end];
        if label.len() <= MAX_LABEL && !label.contains(&b'\n') && BlockKind::of(label) == kind {
            return true;
        }
    }
    false
}

/// Split the body into header lines and base64 lines.
///
/// A body can start with header lines, for example `Proc-Type: 4,ENCRYPTED`.
/// A blank line ends them. OpenPGP armor has header lines too.
fn split_headers(body: &[u8]) -> (&[u8], &[u8]) {
    let trimmed = body
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map_or(&body[body.len()..], |start| &body[start..]);
    let first_line_end = trimmed
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(trimmed.len());
    if !trimmed[..first_line_end].contains(&b':') {
        return (&[], trimmed);
    }
    match find(trimmed, b"\n\n", 0).or_else(|| find(trimmed, b"\n\r\n", 0)) {
        Some(end) => (&trimmed[..end], &trimmed[end..]),
        None => (trimmed, &[]),
    }
}

/// Return true if the header lines of the body show an encrypted key.
pub fn has_encryption_header(body: &[u8]) -> bool {
    find(split_headers(body).0, b"ENCRYPTED", 0).is_some()
}

/// Return the base64 text of the body without spaces. The buffer wipes itself on drop.
///
/// If `armor` is true, the code also drops the checksum line of OpenPGP armor.
pub fn base64_text(body: &[u8], armor: bool) -> Zeroizing<Vec<u8>> {
    let (_, text) = split_headers(body);
    let mut out = Zeroizing::new(Vec::with_capacity(text.len()));
    for line in text.split(|byte| *byte == b'\n') {
        let line = line.trim_ascii();
        if armor && line.first() == Some(&b'=') {
            continue;
        }
        out.extend_from_slice(line);
    }
    out
}

/// Decode the body of a block. The buffer wipes itself on drop. Return `None` for bad base64 text.
pub fn decode(body: &[u8], armor: bool) -> Option<Zeroizing<Vec<u8>>> {
    let text = base64_text(body, armor);
    let mut out = Zeroizing::new(vec![0u8; text.len() / 4 * 3 + 3]);
    let length = STANDARD.decode_slice(text.as_slice(), &mut out).ok()?;
    out.truncate(length);
    Some(out)
}
