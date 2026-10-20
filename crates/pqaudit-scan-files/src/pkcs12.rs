//! Read the certificates of a PKCS#12 file.
//!
//! The code tries each password that the user gives, then the empty password.
//! It reads certificate bags only. It never keeps or shows key bytes.

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
    /// A certificate in the key store is not valid. The value is the reason.
    Cert(String),
}

impl StoreError {
    /// The text for the user. It never holds key store bytes.
    pub fn reason(&self) -> String {
        match self {
            Self::Invalid => messages::KEYSTORE_INVALID.to_string(),
            Self::Truncated => messages::KEYSTORE_TRUNCATED.to_string(),
            Self::Unsupported => messages::KEYSTORE_UNSUPPORTED.to_string(),
            Self::Encrypted => messages::ENCRYPTED_NOT_INSPECTED.to_string(),
            Self::Cert(reason) => reason.clone(),
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

/// Read the certificates of a PKCS#12 file.
///
/// The code tries the passwords in order, then the empty password.
/// If no password opens the file, the error is `StoreError::Encrypted`.
pub fn scan_p12(
    bytes: &[u8],
    passwords: &[Zeroizing<String>],
) -> Result<Vec<CertInfo>, StoreError> {
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
        if let Ok(archive) = Pkcs12Archive::from_pkcs12(bytes, password) {
            let mut certs = Vec::with_capacity(archive.certs.len());
            for (index, bag) in archive.certs.iter().enumerate() {
                let info = parse_certificate(bag.cert.as_der(), index)
                    .map_err(|error| StoreError::Cert(error.reason()))?;
                certs.push(info);
            }
            return Ok(certs);
        }
    }
    Err(StoreError::Encrypted)
}
