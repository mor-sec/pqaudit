//! Load the results, the engagement, and the rules pack. Then assess the findings.

use std::path::Path;

use chrono::Local;
use pqaudit_core::assess::{assess_with_key, Assessment};
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
        output::error(
            &messages::EXPLAIN_READ
                .replace("{path}", &output::shown_path(&path))
                .replace("{reason}", &output::value(&error.to_string())),
        );
        ExitCode::Error
    })?;
    let engagement = Engagement::load(&cli.engagement).map_err(|error| {
        output::error(&messages::ENGAGEMENT_LOAD.replace("{reason}", &error.to_string()));
        ExitCode::Error
    })?;
    let key = if results.header.redacted {
        redaction_key(&engagement)?
    } else {
        None
    };
    check_engagement(&results, &engagement, key.as_ref())?;
    let active = load_active(cli)?;
    let today = Local::now().date_naive();
    let assessment = assess_with_key(&results, &engagement, &active.pack, today, key.as_ref())
        .map_err(|error| {
            output::error(&error.to_string());
            ExitCode::Error
        })?;
    if assessment.overrides_need_key {
        output::warn(messages::OVERRIDES_NEED_KEY);
    }
    Ok((assessment, active))
}

/// Read `redact.key` in the engagement directory. Return `None` if the file does not exist.
///
/// Redacted results need the key for the engagement check and for the overrides.
fn redaction_key(engagement: &Engagement) -> Result<Option<RedactKey>, ExitCode> {
    let path = engagement.dir.join(REDACT_KEY_FILE);
    let missing = std::fs::symlink_metadata(&path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound);
    if missing {
        return Ok(None);
    }
    RedactKey::load(&path).map(Some).map_err(|error| {
        output::error(&messages::REDACT_KEY_LOAD.replace("{reason}", &error.to_string()));
        ExitCode::Error
    })
}

/// Check that the results belong to the engagement directory.
///
/// Plain results must have the name of the engagement directory.
/// Redacted results must have the redacted form of that name.
/// The tool needs `redact.key` to make the redacted form.
/// Without the key, the tool writes a warning and continues.
fn check_engagement(
    results: &ResultsFile,
    engagement: &Engagement,
    key: Option<&RedactKey>,
) -> Result<(), ExitCode> {
    let name = engagement_name(engagement);
    let expected = if results.header.redacted {
        let Some(key) = key else {
            output::warn(messages::ENGAGEMENT_UNCHECKED);
            return Ok(());
        };
        redacted(&name, key)
    } else {
        name.clone()
    };
    if results.header.engagement == expected {
        return Ok(());
    }
    let text = if results.header.redacted {
        messages::ENGAGEMENT_MISMATCH_REDACTED
    } else {
        messages::ENGAGEMENT_MISMATCH
    };
    output::error(
        &text
            .replace("{results}", &output::value(&results.header.engagement))
            .replace("{engagement}", &output::value(&name)),
    );
    Err(ExitCode::Error)
}
