//! Read the certificates of a PKCS#12 file.
//!
//! The code tries each password that the user gives, then the empty password.
//! It reads the certificate bags and never shows or stores key bytes.
//!
//! The library `p12-keystore` also decrypts the key bags. It keeps the decrypted keys
//! in plain memory, and the code cannot wipe them. The code drops the archive at once
//! after it reads the certificates, so the keys stay in memory for a short time only.

use p12_keystore::error::Error as P12Error;
use p12_keystore::Pkcs12Archive;
use pqaudit_core::CertInfo;
use zeroize::Zeroizing;

use crate::cert::parse_certificate;
use crate::messages;

/// Why the tool cannot read a key store.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The data is not a valid key store.
    Invalid,
    /// The data ends too soon.
    Truncated,
    /// The key store has an entry type that the tool does not read.
    Unsupported,
    /// No password opens the key store.
    Encrypted,
}

/// The result of a key store scan. Bad entries do not stop the scan.
#[derive(Debug)]
pub struct StoreScan<T> {
    /// The entries that the tool could read.
    pub found: T,
    /// The reasons for the entries that the tool could not read.
    pub errors: Vec<String>,
}

impl StoreError {
    /// The text for the user. It never holds key store bytes.
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid => messages::KEYSTORE_INVALID.to_string(),
            Self::Truncated => messages::KEYSTORE_TRUNCATED.to_string(),
            Self::Unsupported => messages::KEYSTORE_UNSUPPORTED.to_string(),
            Self::Encrypted => messages::ENCRYPTED_NOT_INSPECTED.to_string(),
        }
    }
}

/// Return the length of the header and the length of the content of the outer DER sequence.
fn outer_sequence(data: &[u8]) -> Option<(usize, usize)> {
    if *data.first()? != 0x30 {
        return None;
    }
    let first = *data.get(1)?;
    if first < 0x80 {
        return Some((2, usize::from(first)));
    }
    let count = usize::from(first & 0x7f);
    if count == 0 || count > 4 {
        return None;
    }
    let bytes = data.get(2..2 + count)?;
    let length = bytes
        .iter()
        .fold(0usize, |total, byte| (total << 8) | usize::from(*byte));
    Some((2 + count, length))
}

/// Return true if the data starts like a PKCS#12 file: a sequence, then the version 3.
pub fn looks_like_p12(data: &[u8]) -> bool {
    outer_sequence(data).is_some_and(|(header, _)| data.get(header..header + 3) == Some(&[2, 1, 3]))
}

/// Return true if the outer sequence fits in the data.
fn is_complete(data: &[u8]) -> bool {
    outer_sequence(data)
        .and_then(|(header, length)| header.checked_add(length))
        .is_some_and(|total| total <= data.len())
}

/// Return true if the error means that the password is wrong.
fn is_password_error(error: &P12Error) -> bool {
    matches!(
        error,
        P12Error::MacError(_) | P12Error::UnpadError | P12Error::Pkcs5Error(_)
    )
}

/// Read the certificates of a PKCS#12 file.
///
/// The code tries the passwords in order, then the empty password.
/// If no password opens the file, the error is `StoreError::Encrypted`.
/// A certificate that is not valid gives an error text. The other certificates stay.
pub fn scan_p12(
    bytes: &[u8],
    passwords: &[Zeroizing<String>],
) -> Result<StoreScan<Vec<CertInfo>>, StoreError> {
    if !looks_like_p12(bytes) {
        return Err(StoreError::Invalid);
    }
    if !is_complete(bytes) {
        return Err(StoreError::Truncated);
    }
    let candidates = passwords
        .iter()
        .map(|password| password.as_str())
        .chain(std::iter::once(""));
    for password in candidates {
        match Pkcs12Archive::from_pkcs12(bytes, password) {
            Ok(archive) => {
                let mut scan = StoreScan {
                    found: Vec::with_capacity(archive.certs.len()),
                    errors: Vec::new(),
                };
                for (index, bag) in archive.certs.iter().enumerate() {
                    match parse_certificate(bag.cert.as_der(), index) {
                        Ok(info) => scan.found.push(info),
                        Err(error) => scan.errors.push(error.reason()),
                    }
                }
                drop(archive);
                return Ok(scan);
            }
            Err(error) if is_password_error(&error) => {}
            Err(
                P12Error::InvalidVersion
                | P12Error::UnsupportedContentType
                | P12Error::UnsupportedEncryptionScheme
                | P12Error::UnsupportedMacAlgorithm,
            ) => return Err(StoreError::Unsupported),
            Err(_) => return Err(StoreError::Invalid),
        }
    }
    Err(StoreError::Encrypted)
}
