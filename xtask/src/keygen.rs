//! The `keygen` task: make a hybrid key pair.

use std::fs;
use std::path::Path;

use pqaudit_rules::signing::HybridSigningKey;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Write a new key pair to `out`. The task never overwrites a file.
pub fn run(out: &Path) -> Result<()> {
    fs::create_dir_all(out)?;
    let key = HybridSigningKey::generate()?;
    let pems = key.to_pems()?;
    write_new(&out.join("ed25519.key.pem"), &pems.ed25519_private, true)?;
    write_new(&out.join("ed25519.pub.pem"), &pems.ed25519_public, false)?;
    write_new(&out.join("mldsa65.key.pem"), &pems.ml_dsa_65_private, true)?;
    write_new(&out.join("mldsa65.pub.pem"), &pems.ml_dsa_65_public, false)?;
    println!("key_id: {}", key.public_key().key_id());
    Ok(())
}

/// Write a file that must not exist. A private file gets the mode 0600.
fn write_new(path: &Path, text: &str, private: bool) -> Result<()> {
    use std::io::Write as _;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|error| format!("{}: {error}", path.display()))?;
    file.write_all(text.as_bytes())?;
    Ok(())
}
