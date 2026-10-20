//! The rules pack format. A pack holds rules, algorithm facts, and deadline profiles.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use chrono::NaiveDate;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The kind of threat that a finding shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatType {
    /// An attacker records data now and decrypts it later.
    Hndl,
    /// An attacker forges a signature that stays valid for a long time.
    ForgeryLongLived,
    /// An attacker forges a signature that is valid for a short time.
    ForgeryShortLived,
    /// An attacker can break the algorithm now without a quantum computer.
    ClassicalWeakNow,
}

/// The kind of work that a fix needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeType {
    /// A change to a configuration.
    Config,
    /// An upgrade of a library.
    LibraryUpgrade,
    /// A change to source code.
    CodeChange,
    /// A change that a partner on the protocol must also make.
    ProtocolPartner,
    /// A change to hardware.
    Hardware,
    /// A change that a vendor must make.
    Vendor,
}

/// A part of the system that a larger key or signature affects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SizeImpact {
    /// The certificate chain gets larger.
    CertChain,
    /// Packets can pass the maximum transmission unit.
    Mtu,
    /// A storage field can be too small.
    StorageField,
}

/// A type of test for a fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TestType {
    /// A unit test.
    Unit,
    /// An integration test.
    Integration,
    /// An interoperability test.
    Interop,
    /// A performance test.
    Performance,
    /// A certification test.
    Certification,
}

/// The tier of an asset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// The asset is critical.
    High,
    /// The asset is not critical.
    Standard,
}

/// The assets that a milestone covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TierScope {
    /// Only high-tier assets.
    High,
    /// All assets.
    All,
}

/// The primitive type of an algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Primitive {
    /// Public-key encryption.
    Pke,
    /// Key encapsulation mechanism.
    Kem,
    /// Digital signature.
    Signature,
    /// Key agreement.
    KeyAgree,
    /// Hash function.
    Hash,
    /// Symmetric cipher.
    Cipher,
}

/// The kind of a milestone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MilestoneKind {
    /// A date for planning work.
    Planning,
    /// A date for migration work.
    Migration,
}

/// A rule that the scanners apply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleDef {
    /// The rule ID, for example `tls.no-pq-kex`.
    pub id: String,
    /// The family of the rule, for example `tls`.
    pub family: String,
    /// Old IDs of the rule.
    #[serde(default)]
    pub aliases: Vec<String>,
    /// A short title.
    pub title: String,
    /// What the rule finds.
    pub description: String,
    /// How to fix the finding.
    pub remediation: String,
    /// The threat type. `None` means that the scanner sets it.
    #[serde(default)]
    pub threat_type: Option<ThreatType>,
    /// CWE IDs.
    #[serde(default)]
    pub cwe: Vec<String>,
    /// ATT&CK technique IDs.
    #[serde(default)]
    pub attack: Vec<String>,
    /// The kind of work that the fix needs.
    pub change_type: ChangeType,
    /// The parts that a fix makes larger.
    #[serde(default)]
    pub size_impact: Vec<SizeImpact>,
    /// The tests that a fix needs.
    #[serde(default)]
    pub testing: Vec<TestType>,
}

/// Facts about one algorithm.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmFact {
    /// The algorithm name.
    pub name: String,
    /// The object identifier, if the algorithm has one.
    #[serde(default)]
    pub oid: Option<String>,
    /// The primitive type.
    pub primitive: Primitive,
    /// True when a quantum computer can break the algorithm.
    pub quantum_vulnerable: bool,
    /// The NIST quantum security level. 0 means no level.
    pub nist_quantum_level: u8,
    /// Keys that are smaller than this size are weak.
    #[serde(default)]
    pub weak_below_bits: Option<u32>,
    /// True when the algorithm is always weak.
    #[serde(default)]
    pub weak_always: bool,
}

/// The assets and threats that a milestone covers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliesTo {
    /// The asset tiers. `None` means all tiers.
    #[serde(default)]
    pub tier: Option<TierScope>,
    /// The threat types. An empty list means all threat types.
    #[serde(default)]
    pub threat_types: Vec<ThreatType>,
    /// The sector. `None` means all sectors.
    #[serde(default)]
    pub sector: Option<String>,
}

/// A date in a deadline profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Milestone {
    /// The date of the milestone.
    pub date: NaiveDate,
    /// The kind of the milestone.
    pub kind: MilestoneKind,
    /// The assets that the milestone covers.
    #[serde(default)]
    pub applies_to: AppliesTo,
    /// What the source says.
    pub description: String,
    /// The title of the source.
    pub source_title: String,
    /// The URL of the source.
    pub source_url: String,
    /// The date on which a person checked the source.
    pub as_of: NaiveDate,
}

/// The deadlines of one country or body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadlineProfile {
    /// The profile ID, for example `uk`.
    pub id: String,
    /// The profile name.
    pub name: String,
    /// The dates of the profile.
    pub milestones: Vec<Milestone>,
}

/// A complete rules pack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesPack {
    /// The pack ID.
    pub id: String,
    /// The pack version.
    pub version: semver::Version,
    /// The rules.
    pub rules: Vec<RuleDef>,
    /// The algorithm facts.
    pub algorithms: Vec<AlgorithmFact>,
    /// The deadline profiles.
    pub profiles: Vec<DeadlineProfile>,
    /// The SHA-256 hash (hex) of the sorted file list. Each entry is a path and its bytes.
    pub content_hash: String,
}

/// An error when a pack loads.
#[derive(Debug, thiserror::Error)]
pub enum PackError {
    /// The program cannot open a file.
    #[error("Cannot read {path}: {message}")]
    Io {
        /// The file.
        path: String,
        /// The reason.
        message: String,
    },
    /// A file has wrong content.
    #[error("Cannot parse {path}: {message}")]
    Parse {
        /// The file.
        path: String,
        /// The reason.
        message: String,
    },
    /// The pack has no file that it needs.
    #[error("The pack has no file {path}.")]
    Missing {
        /// The file.
        path: String,
    },
    /// Two rules use the same ID or alias.
    #[error("The ID {id} is in the pack more than one time.")]
    Duplicate {
        /// The ID.
        id: String,
    },
}

#[derive(Deserialize)]
struct PackManifest {
    id: String,
    version: semver::Version,
}

fn parse_err(path: &str, error: impl ToString) -> PackError {
    PackError::Parse {
        path: path.to_string(),
        message: error.to_string(),
    }
}

impl RulesPack {
    /// Load a pack from a directory.
    pub fn load_dir(path: &Path) -> Result<RulesPack, PackError> {
        let mut files = Vec::new();
        collect_dir(path, path, &mut files)?;
        Self::from_files(files)
    }

    /// Build a pack from a list of (relative path, bytes). Paths use `/`.
    pub fn from_files(mut files: Vec<(String, Vec<u8>)>) -> Result<RulesPack, PackError> {
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut hasher = Sha256::new();
        for (name, bytes) in &files {
            hasher.update((name.len() as u64).to_le_bytes());
            hasher.update(name.as_bytes());
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        let content_hash = hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();

        let text_of = |name: &str, bytes: &[u8]| {
            std::str::from_utf8(bytes)
                .map(str::to_string)
                .map_err(|error| parse_err(name, error))
        };
        let manifest_file = files
            .iter()
            .find(|(name, _)| name == "pack.toml")
            .ok_or_else(|| PackError::Missing {
                path: "pack.toml".into(),
            })?;
        let manifest: PackManifest = toml::from_str(&text_of(&manifest_file.0, &manifest_file.1)?)
            .map_err(|error| parse_err("pack.toml", error))?;

        let mut rules: Vec<RuleDef> = Vec::new();
        let mut algorithms = None;
        let mut profiles = Vec::new();
        for (name, bytes) in &files {
            if !name.ends_with(".yaml") {
                continue;
            }
            if name == "algorithms.yaml" {
                algorithms = Some(
                    serde_yaml::from_str(&text_of(name, bytes)?)
                        .map_err(|error| parse_err(name, error))?,
                );
            } else if name.starts_with("rules/") {
                let list: Vec<RuleDef> = serde_yaml::from_str(&text_of(name, bytes)?)
                    .map_err(|error| parse_err(name, error))?;
                rules.extend(list);
            } else if name.starts_with("profiles/") {
                let profile: DeadlineProfile = serde_yaml::from_str(&text_of(name, bytes)?)
                    .map_err(|error| parse_err(name, error))?;
                profiles.push(profile);
            }
        }
        let algorithms = algorithms.ok_or_else(|| PackError::Missing {
            path: "algorithms.yaml".into(),
        })?;

        let mut seen = HashSet::new();
        for rule in &rules {
            for id in std::iter::once(&rule.id).chain(&rule.aliases) {
                if !seen.insert(id.clone()) {
                    return Err(PackError::Duplicate { id: id.clone() });
                }
            }
        }
        Ok(RulesPack {
            id: manifest.id,
            version: manifest.version,
            rules,
            algorithms,
            profiles,
            content_hash,
        })
    }

    /// Find a rule by its ID or by one of its aliases.
    pub fn rule(&self, id_or_alias: &str) -> Option<&RuleDef> {
        self.rules
            .iter()
            .find(|rule| rule.id == id_or_alias || rule.aliases.iter().any(|a| a == id_or_alias))
    }

    /// Find an algorithm by its name.
    pub fn algorithm(&self, name: &str) -> Option<&AlgorithmFact> {
        self.algorithms.iter().find(|fact| fact.name == name)
    }

    /// Find a deadline profile by its ID.
    pub fn profile(&self, id: &str) -> Option<&DeadlineProfile> {
        self.profiles.iter().find(|profile| profile.id == id)
    }
}

fn collect_dir(
    root: &Path,
    dir: &Path,
    files: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), PackError> {
    let io_err = |path: &Path, error: std::io::Error| PackError::Io {
        path: path.display().to_string(),
        message: error.to_string(),
    };
    for entry in fs::read_dir(dir).map_err(|e| io_err(dir, e))? {
        let path = entry.map_err(|e| io_err(dir, e))?.path();
        if path.is_dir() {
            collect_dir(root, &path, files)?;
        } else {
            let relative = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .components()
                .map(|part| part.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            files.push((relative, fs::read(&path).map_err(|e| io_err(&path, e))?));
        }
    }
    Ok(())
}
