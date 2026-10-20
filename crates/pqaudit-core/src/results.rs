//! The results file (`.pqr`).

use crate::finding::{Finding, InventoryItem, ScanError};
use crate::messages;
use chrono::{DateTime, Utc};
use pqaudit_rules::install::PackOrigin;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};
use std::path::Path;
use uuid::Uuid;

/// The schema version that this tool reads and writes.
pub const SCHEMA_VERSION: u32 = 1;

/// The largest results file that the tool reads, in bytes. This applies after decompression too.
pub const MAX_RESULTS_BYTES: u64 = 1 << 30;

/// The first bytes of a zstd frame.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Which scanner made a results file or a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScannerKind {
    /// The file scanner.
    Files,
    /// The network scanner.
    Net,
    /// A merge of other results.
    Merged,
}

/// Where a rules pack came from. This records the key chain or an unsigned pack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PackOriginRef {
    /// The pack is part of the program.
    Embedded,
    /// The user installed the pack. The signature is correct.
    Installed {
        /// The directory of the pack.
        path: String,
        /// The ID of the key that signed the pack.
        signed_by: String,
        /// The key IDs from the trusted key to the signing key.
        rotation_chain: Vec<String>,
    },
    /// The pack has no valid signature. The user accepted it.
    Unsigned {
        /// The directory of the pack.
        path: String,
    },
}

impl From<&PackOrigin> for PackOriginRef {
    fn from(origin: &PackOrigin) -> Self {
        match origin {
            PackOrigin::Embedded => Self::Embedded,
            PackOrigin::Installed {
                path,
                signed_by,
                rotation_chain,
            } => Self::Installed {
                path: path.to_string_lossy().into_owned(),
                signed_by: signed_by.clone(),
                rotation_chain: rotation_chain.clone(),
            },
            PackOrigin::Unsigned { path } => Self::Unsigned {
                path: path.to_string_lossy().into_owned(),
            },
        }
    }
}

/// The rules pack that a scan used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct PackRef {
    /// The ID of the pack.
    pub id: String,
    /// The version of the pack.
    pub version: String,
    /// The hash of the pack content.
    pub content_hash: String,
    /// Where the pack came from.
    pub origin: PackOriginRef,
}

/// One scanner run that is part of the results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RunInfo {
    /// The ID of the run.
    pub run_id: Uuid,
    /// The scanner of the run.
    pub scanner: ScannerKind,
    /// The host that ran the scanner.
    pub host: String,
    /// The start time of the run.
    pub started: DateTime<Utc>,
}

/// The header of a results file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResultsHeader {
    /// The schema version.
    pub schema_version: u32,
    /// The name of the engagement.
    pub engagement: String,
    /// The version of the tool.
    pub tool_version: String,
    /// The rules pack.
    pub rules_pack: PackRef,
    /// The scanner.
    pub scanner: ScannerKind,
    /// The host that made the file.
    pub host: String,
    /// The operator.
    pub operator: String,
    /// The start time.
    pub started: DateTime<Utc>,
    /// The end time.
    pub finished: DateTime<Utc>,
    /// The hash of the scope file.
    pub scope_hash: Option<String>,
    /// The hash of the audit log.
    pub audit_log_hash: Option<String>,
    /// The runs in this file.
    pub runs: Vec<RunInfo>,
    /// True if the tool removed sensitive text.
    pub redacted: bool,
}

/// A results file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ResultsFile {
    /// The header.
    pub header: ResultsHeader,
    /// The findings.
    pub findings: Vec<Finding>,
    /// Each cryptographic item that the scan found.
    pub inventory: Vec<InventoryItem>,
    /// The errors during the scan.
    pub errors: Vec<ScanError>,
}

/// The part of a results file that the tool reads first to check the schema version.
#[derive(Deserialize)]
struct Probe {
    header: ProbeHeader,
}

/// The header part that the probe reads.
#[derive(Deserialize)]
struct ProbeHeader {
    schema_version: Option<u64>,
}

/// An error when the tool reads a results file.
#[derive(Debug)]
pub enum ResultsError {
    /// The tool cannot read the file.
    Io(io::Error),
    /// The file is not valid.
    Parse(String),
    /// The file is larger than the limit.
    TooLarge {
        /// The limit in bytes.
        limit: u64,
    },
    /// The file has a newer schema than the tool supports.
    UnsupportedSchema {
        /// The schema version in the file.
        found: u32,
        /// The newest schema version that the tool supports.
        supported: u32,
    },
}

impl std::fmt::Display for ResultsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::Io(e) => messages::RESULTS_IO.replace("{reason}", &e.to_string()),
            Self::Parse(reason) => messages::RESULTS_PARSE.replace("{reason}", reason),
            Self::TooLarge { limit } => {
                messages::RESULTS_TOO_LARGE.replace("{limit}", &limit.to_string())
            }
            Self::UnsupportedSchema { found, supported } => messages::UNSUPPORTED_SCHEMA
                .replace("{found}", &found.to_string())
                .replace("{supported}", &supported.to_string()),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for ResultsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ResultsError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl ResultsFile {
    /// Write the file as JSON. Compress it with zstd if `compress` is true.
    pub fn write(&self, path: &Path, compress: bool) -> io::Result<()> {
        let json = serde_json::to_vec(self).map_err(io::Error::other)?;
        let mut out = io::BufWriter::new(std::fs::File::create(path)?);
        if compress {
            let mut encoder = zstd::Encoder::new(&mut out, 0)?;
            encoder.write_all(&json)?;
            encoder.finish()?;
        } else {
            out.write_all(&json)?;
        }
        out.flush()
    }

    /// Read a file. Find zstd by the magic bytes. Refuse a newer schema.
    /// Refuse a file that is larger than `MAX_RESULTS_BYTES`, also after decompression.
    pub fn read(path: &Path) -> Result<Self, ResultsError> {
        Self::read_with_limit(path, MAX_RESULTS_BYTES)
    }

    /// Read a file with a size limit in bytes. The limit applies before and after decompression.
    pub fn read_with_limit(path: &Path, limit: u64) -> Result<Self, ResultsError> {
        let mut raw = Vec::new();
        std::fs::File::open(path)?
            .take(limit.saturating_add(1))
            .read_to_end(&mut raw)?;
        if raw.len() as u64 > limit {
            return Err(ResultsError::TooLarge { limit });
        }
        let json = if raw.starts_with(&ZSTD_MAGIC) {
            let mut text = Vec::new();
            zstd::Decoder::new(raw.as_slice())
                .and_then(|decoder| decoder.take(limit.saturating_add(1)).read_to_end(&mut text))
                .map_err(|e| ResultsError::Parse(e.to_string()))?;
            if text.len() as u64 > limit {
                return Err(ResultsError::TooLarge { limit });
            }
            text
        } else {
            raw
        };
        let probe: Probe =
            serde_json::from_slice(&json).map_err(|e| ResultsError::Parse(e.to_string()))?;
        let found = probe
            .header
            .schema_version
            .ok_or_else(|| ResultsError::Parse(messages::NO_SCHEMA_VERSION.into()))?;
        if found > u64::from(SCHEMA_VERSION) {
            return Err(ResultsError::UnsupportedSchema {
                found: u32::try_from(found).unwrap_or(u32::MAX),
                supported: SCHEMA_VERSION,
            });
        }
        serde_json::from_slice(&json).map_err(|e| ResultsError::Parse(e.to_string()))
    }
}
