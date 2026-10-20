//! The `self-cbom` task: make the CBOM of pqaudit from its SBOM and its crypto declaration.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::process::Command;

use chrono::DateTime;
use pqaudit_report::cbom::{render_tool, ToolCrate, ToolUse};
use pqaudit_rules::pack::RulesPack;
use serde::Deserialize;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// The file `docs/self-crypto.toml`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Declaration {
    #[serde(rename = "use")]
    uses: Vec<Use>,
    /// Crypto crates that are in the SBOM but not in the binary.
    #[serde(default, rename = "not-linked")]
    not_linked: Vec<NotLinked>,
}

/// A crypto crate that the SBOM lists but the build does not link.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotLinked {
    #[serde(rename = "crate")]
    name: String,
    /// The reason. The release workflow also checks the claim with `cargo tree`.
    #[allow(dead_code)]
    reason: String,
}

/// One purpose in the declaration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Use {
    purpose: String,
    algorithms: Vec<String>,
    crates: Vec<String>,
}

/// The time of the CBOM: `SOURCE_DATE_EPOCH`, else the time of the last Git commit.
fn build_time(root: &Path) -> Result<DateTime<chrono::Utc>> {
    let text = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value,
        Err(_) => {
            let output = Command::new("git")
                .args(["log", "-1", "--format=%ct"])
                .current_dir(root)
                .output()?;
            if !output.status.success() {
                return Err(
                    "Set SOURCE_DATE_EPOCH. The task cannot read the Git commit time.".into(),
                );
            }
            String::from_utf8(output.stdout)?
        }
    };
    let seconds: i64 = text.trim().parse()?;
    DateTime::from_timestamp(seconds, 0).ok_or_else(|| "The build time is not valid.".into())
}

/// Read the crate names and versions of an SBOM. The same crate can have more than one version.
fn sbom_crates(sbom: &Path) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let value: serde_json::Value = serde_json::from_str(&fs::read_to_string(sbom)?)?;
    let mut crates: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for component in value["components"].as_array().into_iter().flatten() {
        if let (Some(name), Some(version)) =
            (component["name"].as_str(), component["version"].as_str())
        {
            crates
                .entry(name.to_string())
                .or_default()
                .insert(version.to_string());
        }
    }
    Ok(crates)
}

/// Check the declaration against the SBOM. Write the CBOM to `out`.
///
/// The task fails when a crypto crate in the SBOM has no declaration.
/// It also fails when the declaration names a crate that the SBOM does not hold.
pub fn run(root: &Path, sbom: &Path, declaration: &Path, out: &Path) -> Result<()> {
    let rules = root.join("rules");
    let mut files = Vec::new();
    crate::pack_rules::collect(&rules, &rules, &mut files)?;
    let pack = RulesPack::from_files(files)?;
    let declared: Declaration = toml::from_str(&fs::read_to_string(declaration)?)?;
    let present = sbom_crates(sbom)?;
    let declared_names: BTreeSet<&str> = declared
        .uses
        .iter()
        .flat_map(|item| item.crates.iter().map(String::as_str))
        .collect();

    let undeclared: Vec<&str> = pack
        .crypto_crates
        .iter()
        .map(String::as_str)
        .filter(|name| {
            present.contains_key(*name)
                && !declared_names.contains(name)
                && !declared.not_linked.iter().any(|item| item.name == *name)
        })
        .collect();
    if !undeclared.is_empty() {
        return Err(format!(
            "The SBOM holds crypto crates that {} does not declare: {}",
            declaration.display(),
            undeclared.join(", ")
        )
        .into());
    }
    let absent: Vec<&str> = declared_names
        .iter()
        .copied()
        .chain(declared.not_linked.iter().map(|item| item.name.as_str()))
        .filter(|name| !present.contains_key(*name))
        .collect();
    if !absent.is_empty() {
        return Err(format!(
            "{} declares crates that the SBOM does not hold: {}",
            declaration.display(),
            absent.join(", ")
        )
        .into());
    }

    let uses: Vec<ToolUse> = declared
        .uses
        .iter()
        .map(|item| ToolUse {
            purpose: item.purpose.clone(),
            algorithms: item.algorithms.clone(),
            crates: item
                .crates
                .iter()
                .flat_map(|name| {
                    present[name].iter().map(|version| ToolCrate {
                        name: name.clone(),
                        version: version.clone(),
                    })
                })
                .collect(),
        })
        .collect();
    let cbom = render_tool(
        "pqaudit",
        env!("CARGO_PKG_VERSION"),
        build_time(root)?,
        &uses,
        &pack,
    );
    fs::write(out, serde_json::to_string_pretty(&cbom)? + "\n")?;
    Ok(())
}
