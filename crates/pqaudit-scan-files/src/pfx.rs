//! A bounded check of the key derivation work in a PKCS#12 file.
//!
//! A PKCS#12 file sets its own key derivation parameters. A hostile file can ask for
//! very many iterations, for scrypt with much memory, or for very many encrypted bags.
//! The library `p12-keystore` does that work without a limit that suits a scanner.
//!
//! This module reads the structure before the library sees the file. It counts the
//! key derivations and their iterations. It rejects scrypt. It decrypts the encrypted
//! safes itself, inside the limits, so that it can also count the bags inside them.

use cbc::cipher::{block_padding::Pkcs7, BlockModeDecrypt, KeyIvInit};
use pkcs12::kdf::{derive_key_utf8, Pkcs12KeyType};
use pkcs5::der::Decode;
use sha1::Sha1;
use zeroize::Zeroizing;

use crate::der::{self, Tlv};
use crate::pkcs12::StoreError;

/// The most iterations that the tool accepts for one key derivation.
pub const MAX_KDF_ITERATIONS: u64 = 100_000;

/// The most key derivations that one file can ask for.
///
/// The MAC, each encrypted safe, and each encrypted bag count as one key derivation.
pub const MAX_KDF_USES: usize = 16;

/// The most iterations for one file, for all passwords together.
pub const MAX_FILE_WORK: u64 = MAX_KDF_USES as u64 * MAX_KDF_ITERATIONS;

/// The most iterations for all key stores of one scan.
pub const MAX_SCAN_WORK: u64 = 5_000_000;

/// The tag of a context-specific constructed element `[0]`.
const CONTEXT_0: u8 = 0xa0;
/// The tag of a context-specific primitive element `[0]`.
const CONTEXT_0_PRIMITIVE: u8 = 0x80;

/// The DER content of the OID 1.2.840.113549.1.7.1 (data).
const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// The DER content of the OID 1.2.840.113549.1.7.6 (encrypted data).
const OID_ENCRYPTED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06];
/// The DER content of the OID 1.2.840.113549.1.12.10.1.2 (shrouded key bag).
const OID_SHROUDED_KEY_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x02,
];
/// The DER content of the OID 1.2.840.113549.1.12.10.1.5 (secret bag).
const OID_SECRET_BAG: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x0a, 0x01, 0x05,
];
/// The DER content of the OID 1.2.840.113549.1.5.13 (PBES2).
const OID_PBES2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d];
/// The DER content of the OID 1.2.840.113549.1.5.12 (PBKDF2).
const OID_PBKDF2: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c];
/// The DER content of the OID 1.3.6.1.4.1.11591.4.11 (scrypt).
const OID_SCRYPT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x04, 0x0b];
/// The DER content of the OID 1.2.840.113549.1.12.1.3 (PBES1 with SHA-1 and 3DES).
const OID_PBE_3DES: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x03];
/// The DER content of the OID 1.2.840.113549.1.12.1.6 (PBES1 with SHA-1 and 40-bit RC2).
const OID_PBE_RC2_40: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x0c, 0x01, 0x06];

/// A limit on the key derivation work of a scan. The unit is one iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfBudget {
    remaining: u64,
}

impl KdfBudget {
    /// Make a budget with this number of iterations.
    pub fn new(iterations: u64) -> Self {
        Self {
            remaining: iterations,
        }
    }

    /// The number of iterations that are not used.
    pub fn remaining(&self) -> u64 {
        self.remaining
    }
}

impl Default for KdfBudget {
    fn default() -> Self {
        Self::new(MAX_SCAN_WORK)
    }
}

/// The work for one file. It takes from the file limit and from the scan budget.
pub(crate) struct FileWork<'a> {
    scan: &'a mut KdfBudget,
    file_left: u64,
}

impl<'a> FileWork<'a> {
    /// Start the count for one file.
    pub(crate) fn new(scan: &'a mut KdfBudget) -> Self {
        Self {
            scan,
            file_left: MAX_FILE_WORK,
        }
    }

    /// Take iterations before the work starts. Refuse if a limit is too low.
    fn take(&mut self, iterations: u64) -> Result<(), StoreError> {
        if iterations > self.file_left || iterations > self.scan.remaining {
            return Err(StoreError::TooMuchWork);
        }
        self.file_left -= iterations;
        self.scan.remaining -= iterations;
        Ok(())
    }
}

/// The PBES1 ciphers that the library supports.
#[derive(Clone, Copy)]
enum Pbes1 {
    TripleDes,
    Rc2Bits40,
}

/// The encryption of a safe or a bag.
enum Cipher<'a> {
    /// PBES2 with PBKDF2. The value is the DER of the parameters.
    Pbes2(&'a [u8]),
    /// PBES1 with the PKCS#12 key derivation.
    Pbes1 {
        kind: Pbes1,
        salt: &'a [u8],
        iterations: u64,
    },
}

/// An encryption and its cost in iterations.
struct Encryption<'a> {
    cipher: Cipher<'a>,
    cost: u64,
}

/// An encrypted safe of the authenticated safe.
struct EncryptedSafe<'a> {
    encryption: Encryption<'a>,
    data: &'a [u8],
}

/// The parts of a PKCS#12 file that cause key derivation work.
pub(crate) struct Layout<'a> {
    /// The number of key derivations outside the encrypted safes.
    uses: usize,
    /// The iterations that the library does outside the encrypted safes.
    cost: u64,
    /// The encrypted safes.
    safes: Vec<EncryptedSafe<'a>>,
}

/// The counts of key derivations in a list of bags.
#[derive(Default)]
struct BagWork {
    uses: usize,
    cost: u64,
}

/// What one password attempt found.
pub(crate) enum Attempt {
    /// The password does not open an encrypted safe.
    WrongPassword,
    /// The work is inside the limits. The library can open the file.
    Ready,
}

/// Read a DER element with the given tag, or say that the file is not valid.
fn expect(data: &[u8], tag: u8) -> Result<(Tlv<'_>, &[u8]), StoreError> {
    der::read_tag(data, tag).ok_or(StoreError::Invalid)
}

/// Read all elements of a SEQUENCE OF.
fn elements(mut data: &[u8]) -> impl Iterator<Item = Result<Tlv<'_>, StoreError>> {
    std::iter::from_fn(move || {
        if data.is_empty() {
            return None;
        }
        match der::read(data) {
            Some((element, rest)) => {
                data = rest;
                Some(Ok(element))
            }
            None => {
                data = &[];
                Some(Err(StoreError::Invalid))
            }
        }
    })
}

/// Read a positive INTEGER as an iteration count. A count above the limit is too much work.
fn iterations(content: &[u8]) -> Result<u64, StoreError> {
    let Some(first) = content.first() else {
        return Err(StoreError::Invalid);
    };
    if first & 0x80 != 0 {
        return Err(StoreError::Invalid);
    }
    let digits: &[u8] = {
        let start = content
            .iter()
            .position(|byte| *byte != 0)
            .unwrap_or(content.len());
        &content[start..]
    };
    if digits.len() > 8 {
        return Err(StoreError::TooMuchWork);
    }
    let value = digits
        .iter()
        .fold(0u64, |total, byte| (total << 8) | u64::from(*byte));
    if value > MAX_KDF_ITERATIONS {
        return Err(StoreError::TooMuchWork);
    }
    Ok(value)
}

/// Read an AlgorithmIdentifier of an encryption. Find its key derivation and its cost.
fn encryption(algorithm: &[u8]) -> Result<Encryption<'_>, StoreError> {
    let (oid, params) = expect(algorithm, der::OID)?;
    if oid.content == OID_PBES2 {
        let (pbes2, _) = expect(params, der::SEQUENCE)?;
        let (kdf, _) = expect(pbes2.content, der::SEQUENCE)?;
        let (kdf_oid, kdf_params) = expect(kdf.content, der::OID)?;
        if kdf_oid.content == OID_SCRYPT {
            // scrypt can ask for gigabytes of memory. The tool never runs it.
            return Err(StoreError::TooMuchWork);
        }
        if kdf_oid.content != OID_PBKDF2 {
            return Err(StoreError::Unsupported);
        }
        let (pbkdf2, _) = expect(kdf_params, der::SEQUENCE)?;
        let (_salt, rest) = expect(pbkdf2.content, der::OCTET_STRING)?;
        let (count, _) = expect(rest, der::INTEGER)?;
        let count = iterations(count.content)?;
        return Ok(Encryption {
            cipher: Cipher::Pbes2(pbes2.whole),
            cost: count,
        });
    }
    let kind = if oid.content == OID_PBE_3DES {
        Pbes1::TripleDes
    } else if oid.content == OID_PBE_RC2_40 {
        Pbes1::Rc2Bits40
    } else {
        return Err(StoreError::Unsupported);
    };
    let (pbe, _) = expect(params, der::SEQUENCE)?;
    let (salt, rest) = expect(pbe.content, der::OCTET_STRING)?;
    let (count, _) = expect(rest, der::INTEGER)?;
    let count = iterations(count.content)?;
    Ok(Encryption {
        cipher: Cipher::Pbes1 {
            kind,
            salt: salt.content,
            iterations: count,
        },
        // PBES1 derives the key and the IV separately.
        cost: count.saturating_mul(2),
    })
}

/// Count the key derivations of the bags in a SafeContents.
fn bag_work(safe_contents: &[u8], before: usize) -> Result<BagWork, StoreError> {
    let (bags, _) = expect(safe_contents, der::SEQUENCE)?;
    let mut work = BagWork::default();
    for bag in elements(bags.content) {
        let bag = bag?;
        if bag.tag != der::SEQUENCE {
            return Err(StoreError::Invalid);
        }
        let (bag_id, rest) = expect(bag.content, der::OID)?;
        // The library reads the value with any tag. Thus this code does the same.
        let (value, _) = der::read(rest).ok_or(StoreError::Invalid)?;
        let cost = if bag_id.content == OID_SHROUDED_KEY_BAG {
            let (info, _) = expect(value.content, der::SEQUENCE)?;
            let (algorithm, _) = expect(info.content, der::SEQUENCE)?;
            Some(encryption(algorithm.content)?.cost)
        } else if bag_id.content == OID_SECRET_BAG {
            secret_bag_cost(value.content)?
        } else {
            None
        };
        if let Some(cost) = cost {
            work.uses += 1;
            work.cost = work.cost.saturating_add(cost);
            if before + work.uses > MAX_KDF_USES {
                return Err(StoreError::TooMuchWork);
            }
        }
    }
    Ok(work)
}

/// Find the cost of a secret bag.
///
/// The library rejects a file with a secret bag that is not valid. It ignores a secret bag
/// with an encryption that it cannot read.
fn secret_bag_cost(value: &[u8]) -> Result<Option<u64>, StoreError> {
    let (bag, _) = expect(value, der::SEQUENCE)?;
    let (_type, rest) = expect(bag.content, der::OID)?;
    let (wrapped, _) = expect(rest, CONTEXT_0)?;
    let (octets, _) = expect(wrapped.content, der::OCTET_STRING)?;
    let inner = der::read_tag(octets.content, der::SEQUENCE)
        .and_then(|(info, _)| der::read_tag(info.content, der::SEQUENCE));
    let Some((algorithm, _)) = inner else {
        return Ok(None);
    };
    match encryption(algorithm.content) {
        Ok(found) => Ok(Some(found.cost)),
        Err(StoreError::TooMuchWork) => Err(StoreError::TooMuchWork),
        Err(_) => Ok(None),
    }
}

/// Read the structure of a PKCS#12 file. Count the key derivations outside the encrypted safes.
///
/// This step does no key derivation. Its work is linear in the size of the file.
pub(crate) fn layout(bytes: &[u8]) -> Result<Layout<'_>, StoreError> {
    let (pfx, _) = expect(bytes, der::SEQUENCE)?;
    let (_version, rest) = expect(pfx.content, der::INTEGER)?;
    let (auth_safe, rest) = expect(rest, der::SEQUENCE)?;
    let mut layout = Layout {
        uses: 0,
        cost: 0,
        safes: Vec::new(),
    };
    if !rest.is_empty() {
        // MacData: the digest, the salt, and the iterations. The default is 1 iteration.
        let (mac, _) = expect(rest, der::SEQUENCE)?;
        let (_digest, rest) = expect(mac.content, der::SEQUENCE)?;
        let (_salt, rest) = expect(rest, der::OCTET_STRING)?;
        let count = match der::read_tag(rest, der::INTEGER) {
            Some((count, _)) => iterations(count.content)?,
            None => 1,
        };
        layout.uses += 1;
        layout.cost = count;
    }
    let (content_type, rest) = expect(auth_safe.content, der::OID)?;
    if content_type.content != OID_DATA {
        return Err(StoreError::Unsupported);
    }
    let (explicit, _) = expect(rest, CONTEXT_0)?;
    let (octets, _) = expect(explicit.content, der::OCTET_STRING)?;
    let (safes, _) = expect(octets.content, der::SEQUENCE)?;
    for safe in elements(safes.content) {
        let safe = safe?;
        if safe.tag != der::SEQUENCE {
            return Err(StoreError::Invalid);
        }
        let (content_type, rest) = expect(safe.content, der::OID)?;
        let (explicit, _) = expect(rest, CONTEXT_0)?;
        if content_type.content == OID_DATA {
            let (octets, _) = expect(explicit.content, der::OCTET_STRING)?;
            let work = bag_work(octets.content, layout.uses)?;
            layout.uses += work.uses;
            layout.cost = layout.cost.saturating_add(work.cost);
        } else if content_type.content == OID_ENCRYPTED_DATA {
            let (encrypted, _) = expect(explicit.content, der::SEQUENCE)?;
            let (_version, rest) = expect(encrypted.content, der::INTEGER)?;
            let (info, _) = expect(rest, der::SEQUENCE)?;
            let (_type, rest) = expect(info.content, der::OID)?;
            let (algorithm, rest) = expect(rest, der::SEQUENCE)?;
            let found = encryption(algorithm.content)?;
            layout.uses += 1;
            if layout.uses > MAX_KDF_USES {
                return Err(StoreError::TooMuchWork);
            }
            layout.cost = layout.cost.saturating_add(found.cost);
            // Without content, the library decrypts nothing.
            if let Some((data, _)) = der::read_tag(rest, CONTEXT_0_PRIMITIVE) {
                layout.safes.push(EncryptedSafe {
                    encryption: found,
                    data: data.content,
                });
            }
        } else {
            return Err(StoreError::Unsupported);
        }
        if layout.uses > MAX_KDF_USES {
            return Err(StoreError::TooMuchWork);
        }
    }
    Ok(layout)
}

/// Decrypt data with a password. Return `None` if the password or the data is wrong.
fn decrypt(cipher: &Cipher<'_>, data: &[u8], password: &str) -> Option<Zeroizing<Vec<u8>>> {
    let plain = match cipher {
        Cipher::Pbes2(params) => pkcs5::pbes2::Parameters::from_der(params)
            .ok()?
            .decrypt(password.as_bytes(), data)
            .ok()?,
        Cipher::Pbes1 {
            kind,
            salt,
            iterations,
        } => {
            let rounds = i32::try_from(*iterations).ok()?;
            let size = match kind {
                Pbes1::TripleDes => 24,
                Pbes1::Rc2Bits40 => 5,
            };
            let key = Zeroizing::new(
                derive_key_utf8::<Sha1>(password, salt, Pkcs12KeyType::EncryptionKey, rounds, size)
                    .ok()?,
            );
            let iv = derive_key_utf8::<Sha1>(password, salt, Pkcs12KeyType::Iv, rounds, 8).ok()?;
            match kind {
                Pbes1::TripleDes => cbc::Decryptor::<des::TdesEde3>::new_from_slices(&key, &iv)
                    .ok()?
                    .decrypt_padded_vec::<Pkcs7>(data)
                    .ok()?,
                Pbes1::Rc2Bits40 => cbc::Decryptor::<rc2::Rc2>::new_from_slices(&key, &iv)
                    .ok()?
                    .decrypt_padded_vec::<Pkcs7>(data)
                    .ok()?,
            }
        }
    };
    Some(Zeroizing::new(plain))
}

/// Check the work of one password attempt. Take the iterations from the budget.
///
/// The code decrypts each encrypted safe and counts the bags inside it.
/// Then it takes the iterations that the library will do with this password.
pub(crate) fn attempt(
    layout: &Layout<'_>,
    password: &str,
    work: &mut FileWork<'_>,
) -> Result<Attempt, StoreError> {
    let mut uses = layout.uses;
    let mut cost = layout.cost;
    for safe in &layout.safes {
        work.take(safe.encryption.cost)?;
        let Some(plain) = decrypt(&safe.encryption.cipher, safe.data, password) else {
            return Ok(Attempt::WrongPassword);
        };
        let inner = match bag_work(&plain, uses) {
            Ok(inner) => inner,
            Err(StoreError::TooMuchWork) => return Err(StoreError::TooMuchWork),
            // Data that is not valid after decryption comes from a wrong password.
            Err(_) => return Ok(Attempt::WrongPassword),
        };
        uses += inner.uses;
        cost = cost.saturating_add(inner.cost);
    }
    work.take(cost)?;
    Ok(Attempt::Ready)
}
