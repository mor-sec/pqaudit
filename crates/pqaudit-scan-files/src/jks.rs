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
//! Tag 1 is a private key entry.
//!
//! The data of a private key entry has 3 parts.
//! The first part is the encrypted key: a 4-byte length and bytes.
//! The second part is a certificate count (4 bytes). Then come the certificates.
//! A certificate is a type text (version 2 only), a 4-byte length, and DER bytes.
//!
//! The code needs no password. It skips the encrypted key bytes and does not copy them.
//! It does not check the hash at the end.

use pqaudit_core::CertInfo;

use crate::cert::parse_certificate;
use crate::pkcs12::StoreError;

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

    fn certificate(&mut self, version: u32, position: usize) -> Result<CertInfo, StoreError> {
        if version == 2 {
            self.skip_text()?;
        }
        let der = self.block()?;
        parse_certificate(der, position).map_err(|error| StoreError::Cert(error.reason()))
    }
}

/// Read the certificates of a JKS or JCEKS file.
pub fn scan_jks(bytes: &[u8]) -> Result<Vec<JksEntry>, StoreError> {
    if !has_jks_magic(bytes) {
        return Err(StoreError::Invalid);
    }
    let mut reader = Reader {
        data: bytes,
        position: JKS_MAGIC.len(),
    };
    let version = reader.u32()?;
    if version != 1 && version != 2 {
        return Err(StoreError::Invalid);
    }
    let count = reader.u32()?;
    let mut entries = Vec::new();
    for _ in 0..count {
        let tag = reader.u32()?;
        reader.skip_text()?;
        reader.take(8)?;
        match tag {
            TAG_TRUSTED_CERT => {
                entries.push(JksEntry::TrustedCert(reader.certificate(version, 0)?));
            }
            TAG_PRIVATE_KEY => {
                // Skip the encrypted key. Do not copy it.
                reader.block()?;
                let chain_length = reader.u32()?;
                let mut chain = Vec::new();
                for position in 0..chain_length {
                    let position = usize::try_from(position).unwrap_or(usize::MAX);
                    chain.push(reader.certificate(version, position)?);
                }
                entries.push(JksEntry::PrivateKeyChain(chain));
            }
            // A JCEKS secret key entry holds a Java object. The tool does not read it.
            3 => return Err(StoreError::Unsupported),
            _ => return Err(StoreError::Invalid),
        }
    }
    if bytes.len() - reader.position < HASH_LENGTH {
        return Err(StoreError::Truncated);
    }
    Ok(entries)
}
