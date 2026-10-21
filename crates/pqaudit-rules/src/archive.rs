//! The pack archive: a `tar.zst` file with a fixed layout.
//!
//! The builder makes the same bytes each time. The reader treats the archive as untrusted.

use std::collections::HashSet;
use std::io::Read;

use crate::messages;

/// The largest size of the unpacked archive, in bytes.
pub const MAX_UNPACKED_BYTES: u64 = 64 * 1024 * 1024;

/// The largest number of files in an archive.
pub const MAX_ENTRIES: usize = 2048;

/// The longest path of a file in an archive.
const MAX_PATH_BYTES: usize = 200;

/// A file in an archive: a relative path with `/` and the bytes.
pub type ArchiveFile = (String, Vec<u8>);

/// An error when the program builds or reads an archive.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveError {
    /// A path in the archive is not safe.
    #[error("{}", messages::ARCHIVE_BAD_PATH.replace("{path}", &format!("{:?}", .0)))]
    BadPath(String),
    /// Two files have the same path.
    #[error("{}", messages::ARCHIVE_DUPLICATE.replace("{path}", &format!("{:?}", .0)))]
    Duplicate(String),
    /// The archive has too many files, or it is too large.
    #[error("{}", messages::ARCHIVE_TOO_LARGE)]
    TooLarge,
    /// The archive has an entry that is not a normal file.
    #[error("{}", messages::ARCHIVE_NOT_A_FILE.replace("{path}", &format!("{:?}", .0)))]
    NotAFile(String),
    /// The bytes are not a valid `tar.zst` file.
    #[error("{}", messages::ARCHIVE_READ.replace("{reason}", .0))]
    Read(String),
}

/// Return true if the path is a safe relative path.
fn path_is_safe(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PATH_BYTES
        && !path.starts_with('/')
        && !path.contains('\\')
        && !path.chars().any(char::is_control)
        && path
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Build the archive from a list of files. Sort the files by path.
///
/// The result is the same each time: mtime 0, owner 0, mode 0644.
pub fn build_archive(mut files: Vec<ArchiveFile>) -> Result<Vec<u8>, ArchiveError> {
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let mut seen = HashSet::new();
    let mut builder = tar::Builder::new(Vec::new());
    for (path, bytes) in &files {
        if !path_is_safe(path) {
            return Err(ArchiveError::BadPath(path.clone()));
        }
        if !seen.insert(path.clone()) {
            return Err(ArchiveError::Duplicate(path.clone()));
        }
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        builder
            .append_data(&mut header, path, bytes.as_slice())
            .map_err(|error| ArchiveError::Read(error.to_string()))?;
    }
    let tar_bytes = builder
        .into_inner()
        .map_err(|error| ArchiveError::Read(error.to_string()))?;
    zstd::encode_all(tar_bytes.as_slice(), 19)
        .map_err(|error| ArchiveError::Read(error.to_string()))
}

/// Read the files of an archive. Reject unsafe paths, links, and large archives.
pub fn read_archive(bytes: &[u8]) -> Result<Vec<ArchiveFile>, ArchiveError> {
    let read_err = |error: std::io::Error| ArchiveError::Read(error.to_string());
    let decoder = zstd::Decoder::new(bytes).map_err(read_err)?;
    // One byte more than the limit shows that the archive is too large.
    let limited = decoder.take(MAX_UNPACKED_BYTES + 1);
    let mut archive = tar::Archive::new(limited);
    let mut files = Vec::new();
    let mut seen = HashSet::new();
    let mut total: u64 = 0;
    for entry in archive.entries().map_err(read_err)? {
        let mut entry = entry.map_err(read_err)?;
        let path = entry
            .path()
            .map_err(read_err)?
            .to_str()
            .ok_or_else(|| ArchiveError::BadPath(String::from(messages::NOT_UTF8)))?
            .to_string();
        if !path_is_safe(&path) {
            return Err(ArchiveError::BadPath(path));
        }
        if !entry.header().entry_type().is_file() {
            return Err(ArchiveError::NotAFile(path));
        }
        if files.len() >= MAX_ENTRIES {
            return Err(ArchiveError::TooLarge);
        }
        if !seen.insert(path.clone()) {
            return Err(ArchiveError::Duplicate(path));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_UNPACKED_BYTES {
            return Err(ArchiveError::TooLarge);
        }
        let mut data = Vec::new();
        entry.read_to_end(&mut data).map_err(read_err)?;
        files.push((path, data));
    }
    Ok(files)
}
