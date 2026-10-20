//! Compute the public key of a private key, in memory.
//!
//! Some private key formats hold only a seed. The code derives the public key from the seed.
//! It needs the public key to make the same fingerprint as the public key file.
//! The code returns public bytes only. It never returns or logs a seed.
//!
//! The seed stays in the buffer of the caller. The code copies it into wiping buffers.
//! The key types of the libraries wipe themselves on drop.
//! One by-value call of a library function can leave a short-lived copy on the stack.

use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::SigningKey;
use ml_dsa::signature::Keypair;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams};
use ml_kem::{DecapsulationKey, KeyExport, MlKem1024, MlKem512, MlKem768};
use zeroize::Zeroizing;

/// Derive an X25519 public key from a 32-byte seed.
pub(crate) fn x25519(seed: &[u8]) -> Option<Vec<u8>> {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed.try_into().ok()?);
    Some(MontgomeryPoint::mul_base_clamped(*seed).to_bytes().to_vec())
}

/// Derive an Ed25519 public key from a 32-byte seed.
pub(crate) fn ed25519(seed: &[u8]) -> Option<Vec<u8>> {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed.try_into().ok()?);
    let key = SigningKey::from_bytes(&seed);
    Some(key.verifying_key().to_bytes().to_vec())
}

fn ml_dsa_for<P: MlDsaParams>(seed: &[u8]) -> Option<Vec<u8>> {
    let seed: Zeroizing<[u8; 32]> = Zeroizing::new(seed.try_into().ok()?);
    let array = Zeroizing::new(ml_dsa::Seed::from(*seed));
    let key = ml_dsa::SigningKey::<P>::from_seed(&array);
    Some(key.verifying_key().encode().to_vec())
}

/// Derive an ML-DSA public key from a 32-byte seed. The `level` is 44, 65, or 87.
pub(crate) fn ml_dsa(level: u8, seed: &[u8]) -> Option<Vec<u8>> {
    match level {
        44 => ml_dsa_for::<MlDsa44>(seed),
        65 => ml_dsa_for::<MlDsa65>(seed),
        87 => ml_dsa_for::<MlDsa87>(seed),
        _ => None,
    }
}

/// Derive an ML-KEM public key from a 64-byte seed. The `level` is 512, 768, or 1024.
pub(crate) fn ml_kem(level: u16, seed: &[u8]) -> Option<Vec<u8>> {
    let seed: Zeroizing<[u8; 64]> = Zeroizing::new(seed.try_into().ok()?);
    let array = Zeroizing::new(ml_kem::Seed::from(*seed));
    match level {
        512 => Some(
            DecapsulationKey::<MlKem512>::from_seed(*array)
                .encapsulation_key()
                .to_bytes()
                .to_vec(),
        ),
        768 => Some(
            DecapsulationKey::<MlKem768>::from_seed(*array)
                .encapsulation_key()
                .to_bytes()
                .to_vec(),
        ),
        1024 => Some(
            DecapsulationKey::<MlKem1024>::from_seed(*array)
                .encapsulation_key()
                .to_bytes()
                .to_vec(),
        ),
        _ => None,
    }
}
