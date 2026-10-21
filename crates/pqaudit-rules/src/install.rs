//! Install rules packs and choose the active pack.
//!
//! The program keeps each installed pack as the archive and its signature.
//! It checks the signature again each time it loads the pack.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::embedded::default_pack;
use crate::pack::{PackError, RulesPack};
use crate::verify::{
    load_unverified, verify_pack_archive, SigFile, TrustStore, VerifiedPack, VerifyError,
};

/// The name of the environment variable that sets the data directory.
pub const DATA_DIR_VARIABLE: &str = "PQAUDIT_DATA_DIR";

/// The largest size of an archive file, in bytes.
const MAX_ARCHIVE_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// The largest size of a signature file, in bytes.
const MAX_SIG_FILE_BYTES: u64 = 1024 * 1024;

/// An error when the program installs or loads a pack.
#[derive(Debug, thiserror::Error)]
pub enum InstallError {
    /// The program cannot find the data directory of the user.
    #[error("Cannot find the data directory. Set {DATA_DIR_VARIABLE}.")]
    NoDataDir,
    /// The program cannot read or write a file.
    #[error("Cannot use {path}: {message}")]
    Io {
        /// The file.
        path: String,
        /// The reason.
        message: String,
    },
    /// A file is not a normal file, or it is too large.
    #[error("The file {0} is not a normal file, or it is too large.")]
    BadFile(String),
    /// The signature check failed, or the archive is not valid.
    #[error("{0}")]
    Verify(#[from] VerifyError),
    /// The pack is not valid.
    #[error("The pack is not valid: {0}")]
    Pack(#[from] PackError),
}

/// Where a pack comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackOrigin {
    /// The pack is part of the program.
    Embedded,
    /// The user installed the pack. The signature is correct.
    Installed {
        /// The directory of the pack.
        path: PathBuf,
        /// The ID of the key that signed the pack.
        signed_by: String,
        /// The key IDs from the trusted key to the signing key.
        rotation_chain: Vec<String>,
    },
    /// The pack has no valid signature. The user accepted it.
    Unsigned {
        /// The directory of the pack.
        path: PathBuf,
    },
}

/// The pack that the program uses.
#[derive(Debug, Clone)]
pub struct ActivePack {
    /// The pack.
    pub pack: Arc<RulesPack>,
    /// Where the pack comes from.
    pub origin: PackOrigin,
    /// The installed packs that the program did not use because they failed the check.
    pub skipped: Vec<SkippedPack>,
}

/// An installed pack that the program did not use because it failed the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedPack {
    /// The name of the directory. It is the version of the pack.
    pub version: String,
    /// The directory of the pack.
    pub path: PathBuf,
    /// Why the program did not use the pack.
    pub reason: String,
}

/// The state of an installed pack after the check.
#[derive(Debug, Clone)]
pub enum InstalledState {
    /// The signature is correct.
    Verified {
        /// The pack.
        pack: Arc<RulesPack>,
        /// The ID of the key that signed the pack.
        signed_by: String,
        /// The key IDs from the trusted key to the signing key.
        rotation_chain: Vec<String>,
    },
    /// The pack has no signature, or the signature is wrong. The pack itself is valid.
    Unverified {
        /// The pack.
        pack: Arc<RulesPack>,
        /// The reason why the signature check did not pass.
        reason: String,
    },
    /// The program cannot load the pack.
    Invalid {
        /// Why the program cannot load the pack.
        reason: String,
    },
}

/// A pack in the data directory.
#[derive(Debug, Clone)]
pub struct InstalledPack {
    /// The name of the directory. It is the version of the pack.
    pub version: String,
    /// The directory of the pack.
    pub path: PathBuf,
    /// The result of the check.
    pub state: InstalledState,
}

/// Return the data directory of pqaudit.
///
/// The variable `PQAUDIT_DATA_DIR` has priority over the directory of the user.
pub fn data_root() -> Result<PathBuf, InstallError> {
    if let Some(dir) = std::env::var_os(DATA_DIR_VARIABLE).filter(|dir| !dir.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    dirs::data_dir()
        .map(|dir| dir.join("pqaudit"))
        .ok_or(InstallError::NoDataDir)
}

fn io_error(path: &Path, error: impl ToString) -> InstallError {
    InstallError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    }
}

/// Read a normal file. Reject links, other file types, and files above the limit.
fn read_limited(path: &Path, limit: u64) -> Result<Vec<u8>, InstallError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| io_error(path, e))?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(InstallError::BadFile(path.display().to_string()));
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(|e| io_error(path, e))?
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| io_error(path, e))?;
    if bytes.len() as u64 > limit {
        return Err(InstallError::BadFile(path.display().to_string()));
    }
    Ok(bytes)
}

/// Write a file in one step: write a temporary file, then rename it.
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), InstallError> {
    let temp = path.with_extension("tmp");
    fs::write(&temp, bytes).map_err(|e| io_error(&temp, e))?;
    fs::rename(&temp, path).map_err(|e| io_error(path, e))
}

/// The installed packs and the trust list that checks them.
#[derive(Debug, Clone)]
pub struct RulesStore {
    root: PathBuf,
    trust: TrustStore,
}

impl RulesStore {
    /// Make a store for a data directory and a trust list.
    pub fn new(root: PathBuf, trust: TrustStore) -> Self {
        RulesStore { root, trust }
    }

    /// Make the store of the user: the data directory of the user and the trust list of the program.
    pub fn for_user() -> Result<Self, InstallError> {
        Ok(Self::new(data_root()?, TrustStore::builtin()))
    }

    fn rules_dir(&self) -> PathBuf {
        self.root.join("rules")
    }

    fn write_pack(
        &self,
        pack: &RulesPack,
        archive: &[u8],
        sig: Option<&[u8]>,
    ) -> Result<PathBuf, InstallError> {
        // The version contains only letters, digits, and the characters . - +
        let version = pack.version.to_string();
        let dir = self.rules_dir().join(&version);
        fs::create_dir_all(&dir).map_err(|e| io_error(&dir, e))?;
        let archive_path = dir.join(format!("rules-{version}.tar.zst"));
        let sig_path = dir.join(format!("rules-{version}.tar.zst.sig.json"));
        match sig {
            Some(sig) => {
                write_atomic(&archive_path, archive)?;
                write_atomic(&sig_path, sig)?;
            }
            None => {
                // Remove an old signature first. It does not fit the new archive.
                if sig_path.exists() {
                    fs::remove_file(&sig_path).map_err(|e| io_error(&sig_path, e))?;
                }
                write_atomic(&archive_path, archive)?;
            }
        }
        Ok(dir)
    }

    /// Check the signature of an archive file. Return the pack and the signer.
    pub fn verify(
        &self,
        archive_path: &Path,
        sig_path: &Path,
    ) -> Result<VerifiedPack, InstallError> {
        let archive = read_limited(archive_path, MAX_ARCHIVE_FILE_BYTES)?;
        let sig = SigFile::parse(&read_limited(sig_path, MAX_SIG_FILE_BYTES)?)?;
        Ok(verify_pack_archive(&archive, &sig, &self.trust)?)
    }

    /// Read the pack in an archive file without a check of its signature.
    pub fn load_unsigned(&self, archive_path: &Path) -> Result<RulesPack, InstallError> {
        let archive = read_limited(archive_path, MAX_ARCHIVE_FILE_BYTES)?;
        Ok(load_unverified(&archive)?)
    }

    /// Check a signed archive and install it. Return the directory of the pack.
    pub fn install(&self, archive_path: &Path, sig_path: &Path) -> Result<PathBuf, InstallError> {
        let archive = read_limited(archive_path, MAX_ARCHIVE_FILE_BYTES)?;
        let sig_bytes = read_limited(sig_path, MAX_SIG_FILE_BYTES)?;
        let sig = SigFile::parse(&sig_bytes)?;
        let verified = verify_pack_archive(&archive, &sig, &self.trust)?;
        self.write_pack(&verified.pack, &archive, Some(&sig_bytes))
    }

    /// Install an archive without a signature check. Return the directory of the pack.
    ///
    /// The archive must still be a valid pack.
    pub fn install_unsigned(&self, archive_path: &Path) -> Result<PathBuf, InstallError> {
        let archive = read_limited(archive_path, MAX_ARCHIVE_FILE_BYTES)?;
        let pack = load_unverified(&archive)?;
        self.write_pack(&pack, &archive, None)
    }

    /// Check one installed pack.
    fn check_dir(&self, version: String, path: PathBuf) -> InstalledPack {
        let state = match self.load_state(&version, &path) {
            Ok(state) => state,
            Err(error) => InstalledState::Invalid {
                reason: error.to_string(),
            },
        };
        InstalledPack {
            version,
            path,
            state,
        }
    }

    fn load_state(&self, version: &str, dir: &Path) -> Result<InstalledState, InstallError> {
        let archive_path = dir.join(format!("rules-{version}.tar.zst"));
        let sig_path = dir.join(format!("rules-{version}.tar.zst.sig.json"));
        let archive = read_limited(&archive_path, MAX_ARCHIVE_FILE_BYTES)?;
        let wrong_version = |pack: &RulesPack| pack.version.to_string() != version;
        if fs::symlink_metadata(&sig_path).is_ok() {
            let checked = read_limited(&sig_path, MAX_SIG_FILE_BYTES)
                .and_then(|bytes| SigFile::parse(&bytes).map_err(InstallError::from))
                .and_then(|sig| {
                    verify_pack_archive(&archive, &sig, &self.trust).map_err(InstallError::from)
                });
            return match checked {
                Ok(verified) if wrong_version(&verified.pack) => Ok(InstalledState::Invalid {
                    reason: String::from("The directory name is not the version of the pack."),
                }),
                Ok(verified) => Ok(InstalledState::Verified {
                    pack: Arc::new(verified.pack),
                    signed_by: verified.signed_by,
                    rotation_chain: verified.rotation_chain,
                }),
                Err(error) => self.unverified(&archive, version, error.to_string()),
            };
        }
        self.unverified(
            &archive,
            version,
            String::from("The pack has no signature."),
        )
    }

    fn unverified(
        &self,
        archive: &[u8],
        version: &str,
        reason: String,
    ) -> Result<InstalledState, InstallError> {
        let pack = load_unverified(archive)?;
        if pack.version.to_string() != version {
            return Ok(InstalledState::Invalid {
                reason: String::from("The directory name is not the version of the pack."),
            });
        }
        Ok(InstalledState::Unverified {
            pack: Arc::new(pack),
            reason,
        })
    }

    /// Check all installed packs. Sort them by directory name.
    pub fn list_installed(&self) -> Vec<InstalledPack> {
        let Ok(entries) = fs::read_dir(self.rules_dir()) else {
            return Vec::new();
        };
        let mut found: Vec<(String, PathBuf)> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                Some((name, entry.path()))
            })
            .collect();
        found.sort();
        found
            .into_iter()
            .map(|(version, path)| self.check_dir(version, path))
            .collect()
    }

    /// Choose the pack with the highest version.
    ///
    /// The choice is between the default pack and the installed packs that pass the check.
    /// With `allow_unsigned`, a pack without a valid signature can also win.
    /// The result lists each installed pack that the check stopped.
    pub fn active_pack(&self, allow_unsigned: bool) -> Result<ActivePack, InstallError> {
        let mut best = ActivePack {
            pack: Arc::new(default_pack().clone()),
            origin: PackOrigin::Embedded,
            skipped: Vec::new(),
        };
        let mut skipped = Vec::new();
        for installed in self.list_installed() {
            let candidate = match installed.state {
                InstalledState::Verified {
                    pack,
                    signed_by,
                    rotation_chain,
                } => ActivePack {
                    pack,
                    origin: PackOrigin::Installed {
                        path: installed.path,
                        signed_by,
                        rotation_chain,
                    },
                    skipped: Vec::new(),
                },
                InstalledState::Unverified { pack, .. } if allow_unsigned => ActivePack {
                    pack,
                    origin: PackOrigin::Unsigned {
                        path: installed.path,
                    },
                    skipped: Vec::new(),
                },
                InstalledState::Unverified { reason, .. } | InstalledState::Invalid { reason } => {
                    skipped.push(SkippedPack {
                        version: installed.version,
                        path: installed.path,
                        reason,
                    });
                    continue;
                }
            };
            if candidate.pack.version > best.pack.version {
                best = candidate;
            }
        }
        best.skipped = skipped;
        Ok(best)
    }
}

/// Check a signed archive and install it for the user. Return the directory of the pack.
pub fn install_pack(archive_path: &Path, sig_path: &Path) -> Result<PathBuf, InstallError> {
    RulesStore::for_user()?.install(archive_path, sig_path)
}

/// Choose the active pack for the user.
pub fn active_pack(allow_unsigned: bool) -> Result<ActivePack, InstallError> {
    RulesStore::for_user()?.active_pack(allow_unsigned)
}
