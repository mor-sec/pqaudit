//! Load the results, the engagement, and the rules pack. Then assess the findings.

use std::path::Path;

use chrono::Local;
use pqaudit_core::assess::{assess, Assessment};
use pqaudit_core::engagement::Engagement;
use pqaudit_core::ResultsFile;
use pqaudit_rules::install::{active_pack, ActivePack};

use crate::cli::Cli;
use crate::exit::ExitCode;
use crate::messages;

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
    let active = active_pack(cli.allow_unsigned_rules).map_err(|error| {
        eprintln!(
            "{}",
            messages::PACK_LOAD.replace("{reason}", &error.to_string())
        );
        ExitCode::Error
    })?;
    let today = Local::now().date_naive();
    let assessment = assess(&results, &engagement, &active.pack, today).map_err(|error| {
        eprintln!("{error}");
        ExitCode::Error
    })?;
    Ok((assessment, active))
}
