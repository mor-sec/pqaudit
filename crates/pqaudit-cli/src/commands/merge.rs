//! The `merge` command: combine results files into one file.

use std::path::{Path, PathBuf};

use pqaudit_core::merge::{merge, redact};
use pqaudit_core::ResultsFile;

use crate::cli::Cli;
use crate::commands::scan_files::write_results;
use crate::exit::ExitCode;
use crate::messages;

/// Run `merge`.
pub fn run(cli: &Cli, inputs: &[PathBuf], output: Option<&Path>, redact_output: bool) -> ExitCode {
    let mut files = Vec::with_capacity(inputs.len());
    for path in inputs {
        match ResultsFile::read(path) {
            Ok(file) => files.push(file),
            Err(error) => {
                eprintln!(
                    "{}",
                    messages::MERGE_READ
                        .replace("{path}", &path.display().to_string())
                        .replace("{reason}", &error.to_string())
                );
                return ExitCode::Error;
            }
        }
    }
    let mut merged = match merge(files) {
        Ok(merged) => merged,
        Err(error) => {
            eprintln!(
                "{}",
                messages::MERGE_FAILED.replace("{reason}", &error.to_string())
            );
            return ExitCode::Error;
        }
    };
    if redact_output {
        redact(&mut merged);
    }
    let path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cli.engagement.join("results").join("merged.pqr"));
    if let Err(error) = write_results(&merged, &path) {
        eprintln!(
            "{}",
            messages::RESULTS_WRITE
                .replace("{path}", &path.display().to_string())
                .replace("{reason}", &error.to_string())
        );
        return ExitCode::Error;
    }
    println!(
        "{}",
        messages::MERGE_SUMMARY
            .replace("{inputs}", &inputs.len().to_string())
            .replace("{findings}", &merged.findings.len().to_string())
            .replace("{inventory}", &merged.inventory.len().to_string())
            .replace("{errors}", &merged.errors.len().to_string())
    );
    if redact_output {
        println!("{}", messages::MERGE_REDACTED);
    }
    println!("{} {}", messages::SCAN_RESULTS, path.display());
    ExitCode::Success
}
