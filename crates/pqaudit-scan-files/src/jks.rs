//! Read the certificates of a Java key store (JKS or JCEKS).
//!
//! All numbers in the file are big-endian.
//! The file starts with the magic number: `FE ED FE ED` for JKS, `CE CE CE CE` for JCEKS.
//! Then come the version (4 bytes, 1 or 2) and the entry count (4 bytes).
//! Then come the entries. A hash of 20 bytes ends the file.
//!
//! Each entry has a tag (4 bytes), an alias, a time stamp (8 bytes), and data.
//! An alias is a 2-byte length and text.
//! Tag 2 is a trusted certificate. Its data is one certificate.
//! A certificate is a type text (version 2 only), a 4-byte length, and DER bytes.
//!
//! Tag 1 is a private key entry in a JKS file.
//! Its data is the encrypted key (a 4-byte length and bytes), a certificate count (4 bytes),
//! and the certificates.
//!
//! A JCEKS file uses another layout for tag 1 and tag 3.
//! Those entries hold a Java serialized object. It starts with the bytes `AC ED 00 05`.
//! It has no length in front of it, so the code cannot skip it.
//! At such an entry the code stops, keeps the entries before it, and reports an error.
//!
//! The code needs no password. It skips the encrypted key bytes and does not copy them.
//! It does not check the hash at the end.

use pqaudit_core::CertInfo;

use crate::cert::parse_certificate;
use crate::messages;
use crate::pkcs12::{StoreError, StoreScan};

/// The magic number of a JKS file.
const JKS_MAGIC: [u8; 4] = [0xFE, 0xED, 0xFE, 0xED];
/// The magic number of a JCEKS file.
const JCEKS_MAGIC: [u8; 4] = [0xCE, 0xCE, 0xCE, 0xCE];
/// The length of the hash at the end of the file.
const HASH_LENGTH: usize = 20;
/// The tag of a private key entry.
const TAG_PRIVATE_KEY: u32 = 1;
/// The tag of a trusted certificate entry.
const TAG_TRUSTED_CERT: u32 = 2;
/// The longest alias that the tool shows in a message, in characters.
const MAX_ALIAS_CHARS: usize = 128;

/// One entry of a Java key store.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum JksEntry {
    /// A trusted certificate.
    TrustedCert(CertInfo),
    /// The certificate chain of a private key. The leaf is first. The key is not read.
    PrivateKeyChain(Vec<CertInfo>),
}

/// Return true if the data starts with the magic number of a JKS or JCEKS file.
pub fn has_jks_magic(data: &[u8]) -> bool {
    data.starts_with(&JKS_MAGIC) || data.starts_with(&JCEKS_MAGIC)
}

/// A reader that checks each length against the data.
struct Reader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], StoreError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(StoreError::Truncated)?;
        let bytes = self
            .data
            .get(self.position..end)
            .ok_or(StoreError::Truncated)?;
        self.position = end;
        Ok(bytes)
    }

    fn u16(&mut self) -> Result<u16, StoreError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn skip_text(&mut self) -> Result<(), StoreError> {
        let length = usize::from(self.u16()?);
        self.take(length).map(|_| ())
    }

    fn block(&mut self) -> Result<&'a [u8], StoreError> {
        let length = usize::try_from(self.u32()?).map_err(|_| StoreError::Truncated)?;
        self.take(length)
    }

    /// Read one certificate. The inner error is for a certificate that is not valid.
    fn certificate(
        &mut self,
        version: u32,
        position: usize,
    ) -> Result<Result<CertInfo, String>, StoreError> {
        if version == 2 {
            self.skip_text()?;
        }
        let der = self.block()?;
        Ok(parse_certificate(der, position).map_err(|error| error.reason()))
    }

    /// Read an alias for a message. Cut a long alias.
    fn alias(&mut self) -> Result<String, StoreError> {
        let length = usize::from(self.u16()?);
        let text = pqaudit_core::text::clean_bytes(self.take(length)?);
        Ok(text.chars().take(MAX_ALIAS_CHARS).collect())
    }
}

/// Read the certificates of a JKS or JCEKS file.
///
/// A certificate that is not valid gives an error text. The other entries stay.
/// In a JCEKS file, the code stops at the first key entry and reports an error.
pub fn scan_jks(bytes: &[u8]) -> Result<StoreScan<Vec<JksEntry>>, StoreError> {
    if !has_jks_magic(bytes) {
        return Err(StoreError::Invalid);
    }
    let is_jceks = bytes.starts_with(&JCEKS_MAGIC);
    let mut reader = Reader {
        data: bytes,
        position: JKS_MAGIC.len(),
    };
    let version = reader.u32()?;
    if version != 1 && version != 2 {
        return Err(StoreError::Invalid);
    }
    let count = reader.u32()?;
    let mut scan = StoreScan {
        found: Vec::new(),
        errors: Vec::new(),
    };
    for _ in 0..count {
        let tag = reader.u32()?;
        let alias = reader.alias()?;
        reader.take(8)?;
        match tag {
            TAG_TRUSTED_CERT => match reader.certificate(version, 0)? {
                Ok(info) => scan.found.push(JksEntry::TrustedCert(info)),
                Err(reason) => scan.errors.push(reason),
            },
            TAG_PRIVATE_KEY if !is_jceks => {
                // Skip the encrypted key. Do not copy it.
                reader.block()?;
                let chain_length = reader.u32()?;
                let mut chain = Vec::new();
                for position in 0..chain_length {
                    let position = usize::try_from(position).unwrap_or(usize::MAX);
                    match reader.certificate(version, position)? {
                        Ok(info) => chain.push(info),
                        Err(reason) => scan.errors.push(reason),
                    }
                }
                scan.found.push(JksEntry::PrivateKeyChain(chain));
            }
            // A JCEKS key entry holds a Java object with no length. The code cannot skip it.
            TAG_PRIVATE_KEY | 3 if is_jceks => {
                scan.errors
                    .push(messages::JCEKS_ENTRY_UNSUPPORTED.replace("{alias}", &alias));
                return Ok(scan);
            }
            _ => return Err(StoreError::Invalid),
        }
    }
    if bytes.len() - reader.position < HASH_LENGTH {
        return Err(StoreError::Truncated);
    }
    Ok(scan)
}
