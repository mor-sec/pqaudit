//! The engagement files: `engagement.toml`, `assets.toml`, `overrides.toml`, and `scoring.toml`.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use chrono::NaiveDate;
use ipnet::IpNet;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

use crate::messages;
use crate::Tier;

/// The name of the engagement file. This file is necessary.
pub const ENGAGEMENT_FILE: &str = "engagement.toml";
/// The name of the file with the asset context.
pub const ASSETS_FILE: &str = "assets.toml";
/// The name of the file with the customer overrides.
pub const OVERRIDES_FILE: &str = "overrides.toml";
/// The name of the file with the scoring settings.
pub const SCORING_FILE: &str = "scoring.toml";

/// Read a TOML date, for example `2026-10-20`. The `toml` crate gives dates as a special type.
fn date<'de, D: Deserializer<'de>>(deserializer: D) -> Result<NaiveDate, D::Error> {
    let value = toml::value::Datetime::deserialize(deserializer)?;
    value
        .to_string()
        .parse()
        .map_err(|_| serde::de::Error::custom(messages::DATE_EXPECTED))
}

fn optional_date<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<NaiveDate>, D::Error> {
    date(deserializer).map(Some)
}

/// The content of `engagement.toml`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngagementConfig {
    /// The name of the client.
    pub client: String,
    /// The name of the assessor.
    pub assessor: String,
    /// The date of the assessment. If it is not set, the tool uses the local date.
    #[serde(default, deserialize_with = "optional_date")]
    pub assessment_date: Option<NaiveDate>,
    /// The deadline profiles to use.
    #[serde(default)]
    pub deadlines: DeadlineSelection,
    /// The assumptions of the assessment.
    pub assumptions: Assumptions,
    /// Where to read the passwords of key stores.
    #[serde(default)]
    pub passwords: Option<PasswordSource>,
}

/// The deadline profiles that the engagement uses.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeadlineSelection {
    /// The IDs of the profiles. A finding shows the earliest date of all profiles.
    #[serde(default)]
    pub profiles: Vec<String>,
    /// The sector overlay, for example `government`.
    #[serde(default)]
    pub sector: Option<String>,
}

/// The assumptions that each report shows.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assumptions {
    /// The year of the first cryptographically relevant quantum computer (CRQC).
    pub crqc_year: i32,
}

/// The place of the passwords of key stores. The file never holds a password itself.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum PasswordSource {
    /// Read the passwords from this environment variable.
    Env {
        /// The name of the environment variable.
        env: String,
    },
    /// Read the passwords from this file.
    File {
        /// The path of the password file.
        file: PathBuf,
    },
}

/// The content of `assets.toml`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetsFile {
    /// The assets of the customer.
    #[serde(default)]
    pub asset: Vec<Asset>,
}

/// One asset with the context that the tool cannot find itself.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// The name of the asset.
    pub name: String,
    /// The business unit that owns the asset.
    #[serde(default)]
    pub business_unit: Option<String>,
    /// The rules that match findings to this asset. The TOML key is `match`.
    #[serde(default, rename = "match")]
    pub matcher: AssetMatch,
    /// The classification of the data, in the scheme of the customer.
    #[serde(default)]
    pub classification: Option<String>,
    /// The number of years that the data must stay secret.
    #[serde(default)]
    pub data_lifespan_years: Option<u32>,
    /// How far the asset is open to attack.
    #[serde(default)]
    pub exposure: Option<Exposure>,
    /// The team or person that owns the asset.
    #[serde(default)]
    pub owner: Option<String>,
    /// If true, a vendor supplies the asset.
    #[serde(default)]
    pub vendor: Option<bool>,
    /// The tier that selects the deadline milestones.
    #[serde(default)]
    pub priority_tier: Option<Tier>,
    /// If true, the fix needs a hardware change.
    #[serde(default)]
    pub hardware_constrained: Option<bool>,
}

/// The ways to match a finding to an asset.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AssetMatch {
    /// Host names.
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Address ranges.
    #[serde(default)]
    pub cidrs: Vec<IpNet>,
    /// Path globs.
    #[serde(default)]
    pub paths: Vec<String>,
}

/// How far an asset is open to attack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    /// Anyone on the internet can reach the asset.
    Internet,
    /// Partners can reach the asset.
    Partner,
    /// Only the internal network can reach the asset.
    Internal,
    /// The asset has no network connection to other systems.
    Isolated,
}

/// The content of `overrides.toml`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverridesFile {
    /// The overrides of suggested priorities.
    #[serde(default)]
    pub r#override: Vec<Override>,
}

/// One customer override of a suggested priority.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Override {
    /// The stable fingerprint of the finding.
    pub fingerprint: String,
    /// The priority band that replaces the suggested band.
    pub priority: Band,
    /// The reason for the override.
    pub reason: String,
    /// The person who made the override.
    pub by: String,
    /// The date of the override.
    #[serde(deserialize_with = "date")]
    pub date: NaiveDate,
}

/// A priority band.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Band {
    /// The most urgent band.
    Critical,
    /// The second band.
    High,
    /// The third band.
    Medium,
    /// The least urgent band.
    Low,
}

/// The complexity size of a fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
pub enum Size {
    /// Small.
    S,
    /// Medium.
    M,
    /// Large.
    L,
    /// Extra large.
    XL,
}

/// The content of `scoring.toml`. A key that the file does not set keeps its default value.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ScoringConfig {
    /// The weights of the six factors of the priority score.
    pub weights: Weights,
    /// The value (0 to 1) of each data classification. A classification in the file replaces this map.
    pub classification: BTreeMap<String, f64>,
    /// The lowest score of each band.
    pub bands: Bands,
    /// The migration time in years for each size. A size that the file does not set keeps its default.
    #[serde(deserialize_with = "merge_migration_years")]
    pub migration_years: BTreeMap<Size, f64>,
}

/// The weights of the factors of the priority score.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Weights {
    /// The weight of the threat type.
    pub threat: f64,
    /// The weight of the exposure.
    pub exposure: f64,
    /// The weight of the data sensitivity.
    pub sensitivity: f64,
    /// The weight of the Mosca margin.
    pub mosca: f64,
    /// The weight of the deadline proximity.
    pub deadline: f64,
    /// The weight of the scale.
    pub scale: f64,
}

/// The lowest score of each priority band. A score below `medium` is low.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Bands {
    /// The lowest score of the critical band.
    pub critical: f64,
    /// The lowest score of the high band.
    pub high: f64,
    /// The lowest score of the medium band.
    pub medium: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            threat: 0.25,
            exposure: 0.20,
            sensitivity: 0.20,
            mosca: 0.15,
            deadline: 0.10,
            scale: 0.10,
        }
    }
}

impl Default for Bands {
    fn default() -> Self {
        Self {
            critical: 80.0,
            high: 60.0,
            medium: 40.0,
        }
    }
}

fn default_classification() -> BTreeMap<String, f64> {
    [
        ("public", 0.1),
        ("internal", 0.4),
        ("confidential", 0.7),
        ("secret", 1.0),
        ("restricted", 1.0),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_string(), value))
    .collect()
}

fn default_migration_years() -> BTreeMap<Size, f64> {
    BTreeMap::from([
        (Size::S, 0.25),
        (Size::M, 0.5),
        (Size::L, 1.0),
        (Size::XL, 2.0),
    ])
}

fn merge_migration_years<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<Size, f64>, D::Error> {
    let mut years = default_migration_years();
    years.extend(BTreeMap::<Size, f64>::deserialize(deserializer)?);
    Ok(years)
}

impl Default for ScoringConfig {
    fn default() -> Self {
        Self {
            weights: Weights::default(),
            classification: default_classification(),
            bands: Bands::default(),
            migration_years: default_migration_years(),
        }
    }
}

/// An engagement directory with all its files, loaded.
#[derive(Debug, Clone, PartialEq)]
pub struct Engagement {
    /// The engagement directory.
    pub dir: PathBuf,
    /// The content of `engagement.toml`.
    pub config: EngagementConfig,
    /// The content of `assets.toml`, or an empty value.
    pub assets: AssetsFile,
    /// The content of `overrides.toml`, or an empty value.
    pub overrides: OverridesFile,
    /// The content of `scoring.toml`, or the defaults.
    pub scoring: ScoringConfig,
}

/// An error when the tool loads the engagement files.
#[derive(Debug)]
pub enum EngagementError {
    /// A necessary file does not exist.
    Missing {
        /// The name of the file.
        file: String,
        /// The engagement directory.
        dir: PathBuf,
    },
    /// The tool cannot read a file.
    Io {
        /// The name of the file.
        file: String,
        /// The reason.
        reason: String,
    },
    /// A file is not valid TOML, or has a wrong key or value.
    Parse {
        /// The name of the file.
        file: String,
        /// The line number, counted from 1.
        line: usize,
        /// The reason.
        reason: String,
    },
}

impl fmt::Display for EngagementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Missing { file, dir } => messages::ENGAGEMENT_MISSING
                .replace("{file}", file)
                .replace("{dir}", &dir.display().to_string()),
            Self::Io { file, reason } => messages::ENGAGEMENT_IO
                .replace("{file}", file)
                .replace("{reason}", reason),
            Self::Parse { file, line, reason } => messages::ENGAGEMENT_PARSE
                .replace("{file}", file)
                .replace("{line}", &line.to_string())
                .replace("{reason}", reason),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for EngagementError {}

/// Read one file. Return `None` if the file does not exist.
fn read_file<T: DeserializeOwned>(dir: &Path, name: &str) -> Result<Option<T>, EngagementError> {
    let text = match std::fs::read_to_string(dir.join(name)) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(EngagementError::Io {
                file: name.to_string(),
                reason: error.to_string(),
            })
        }
    };
    toml::from_str(&text).map(Some).map_err(|error| {
        let offset = error.span().map_or(0, |span| span.start).min(text.len());
        let line = 1 + text.as_bytes()[..offset]
            .iter()
            .filter(|b| **b == b'\n')
            .count();
        EngagementError::Parse {
            file: name.to_string(),
            line,
            reason: error.message().to_string(),
        }
    })
}

impl Engagement {
    /// Load the engagement files from a directory.
    ///
    /// `engagement.toml` is necessary. If another file does not exist, the tool uses an empty value or the defaults.
    pub fn load(dir: &Path) -> Result<Engagement, EngagementError> {
        let config = read_file(dir, ENGAGEMENT_FILE)?.ok_or_else(|| EngagementError::Missing {
            file: ENGAGEMENT_FILE.to_string(),
            dir: dir.to_path_buf(),
        })?;
        Ok(Engagement {
            dir: dir.to_path_buf(),
            config,
            assets: read_file(dir, ASSETS_FILE)?.unwrap_or_default(),
            overrides: read_file(dir, OVERRIDES_FILE)?.unwrap_or_default(),
            scoring: read_file(dir, SCORING_FILE)?.unwrap_or_default(),
        })
    }
}
