//! The `sign` task: sign a file with a hybrid key pair.

use std::fs;
use std::path::{Path, PathBuf};

use pqaudit_rules::signing::HybridSigningKey;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Return `<file><suffix>`.
fn with_suffix(file: &Path, suffix: &str) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Sign `file` with the keys in `keys`. Write three signature files next to it.
///
/// The files are `<file>.sig.json`, `<file>.ed25519.sig`, and `<file>.mldsa65.sig`.
pub fn run(keys: &Path, file: &Path) -> Result<()> {
    let key = HybridSigningKey::from_pems(
        &fs::read_to_string(keys.join("ed25519.key.pem"))?,
        &fs::read_to_string(keys.join("mldsa65.key.pem"))?,
    )?;
    let data = fs::read(file)?;
    let (ed25519, ml_dsa_65) = key.sign_raw(&data);
    fs::write(with_suffix(file, ".ed25519.sig"), ed25519)?;
    fs::write(with_suffix(file, ".mldsa65.sig"), ml_dsa_65)?;
    fs::write(with_suffix(file, ".sig.json"), key.sign(&data).to_json())?;
    Ok(())
}
