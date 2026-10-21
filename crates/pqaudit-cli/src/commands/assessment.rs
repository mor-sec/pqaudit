//! Load the results, the engagement, and the rules pack. Then assess the findings.

use std::path::Path;

use chrono::Local;
use pqaudit_core::assess::{assess, Assessment};
use pqaudit_core::engagement::Engagement;
use pqaudit_core::merge::{redacted, RedactKey};
use pqaudit_core::ResultsFile;
use pqaudit_rules::install::ActivePack;

use crate::cli::Cli;
use crate::commands::pack::load_active;
use crate::commands::scan_files::engagement_name;
use crate::exit::ExitCode;
use crate::messages;
use crate::output;

/// The name of the redaction key in the engagement directory.
const REDACT_KEY_FILE: &str = "redact.key";

/// Assess the findings of a results file.
///
/// The default results file is `results/merged.pqr` in the engagement directory.
/// On an error, this function prints an error message and returns the exit code.
pub fn load(cli: &Cli, results: Option<&Path>) -> Result<Assessment, ExitCode> {
    load_with_pack(cli, results).map(|(assessment, _)| assessment)
}

/// Assess the findings of a results file. Return the active rules pack too.
///
/// The default results file is `results/merged.pqr` in the engagement directory.
/// On an error, this function prints an error message and returns the exit code.
pub fn load_with_pack(
    cli: &Cli,
    results: Option<&Path>,
) -> Result<(Assessment, ActivePack), ExitCode> {
    let path = results
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cli.engagement.join("results").join("merged.pqr"));
    let results = ResultsFile::read(&path).map_err(|error| {
        eprintln!(
            "{}",
            messages::EXPLAIN_READ
                .replace("{path}", &path.display().to_string())
                .replace("{reason}", &error.to_string())
        );
        ExitCode::Error
    })?;
    let engagement = Engagement::load(&cli.engagement).map_err(|error| {
        eprintln!(
            "{}",
            messages::ENGAGEMENT_LOAD.replace("{reason}", &error.to_string())
        );
        ExitCode::Error
    })?;
    check_engagement(&results, &engagement)?;
    let active = load_active(cli)?;
    let today = Local::now().date_naive();
    let assessment = assess(&results, &engagement, &active.pack, today).map_err(|error| {
        eprintln!("{error}");
        ExitCode::Error
    })?;
    Ok((assessment, active))
}

/// Check that the results belong to the engagement directory.
///
/// Plain results must have the name of the engagement directory.
/// Redacted results must have the redacted form of that name.
/// The tool needs `redact.key` to make the redacted form.
/// Without the key, the tool writes a warning and continues.
fn check_engagement(results: &ResultsFile, engagement: &Engagement) -> Result<(), ExitCode> {
    let name = engagement_name(engagement);
    let expected = if results.header.redacted {
        let path = engagement.dir.join(REDACT_KEY_FILE);
        let missing = std::fs::symlink_metadata(&path)
            .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
        if missing {
            output::warn(messages::ENGAGEMENT_UNCHECKED);
            return Ok(());
        }
        let key = RedactKey::load(&path).map_err(|error| {
            eprintln!(
                "{}",
                messages::REDACT_KEY_LOAD.replace("{reason}", &error.to_string())
            );
            ExitCode::Error
        })?;
        redacted(&name, &key)
    } else {
        name.clone()
    };
    if results.header.engagement == expected {
        return Ok(());
    }
    eprintln!(
        "{}",
        messages::ENGAGEMENT_MISMATCH
            .replace("{results}", &results.header.engagement)
            .replace("{engagement}", &name)
    );
    Err(ExitCode::Error)
}
