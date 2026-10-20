//! The `merge` command: combine results files into one file.

use std::path::{Path, PathBuf};

use pqaudit_core::merge::{merge, redact, RedactKey};
use pqaudit_core::ResultsFile;

use crate::cli::Cli;
use crate::commands::scan_files::write_results;
use crate::exit::ExitCode;
use crate::messages;

/// The arguments of `merge`.
pub struct MergeArgs<'a> {
    /// The results files to combine.
    pub inputs: &'a [PathBuf],
    /// The output file. `None` means the default in the results directory.
    pub output: Option<&'a Path>,
    /// True if the command must redact the output.
    pub redact: bool,
    /// The key file. `None` means `redact.key` in the engagement directory.
    pub key_file: Option<&'a Path>,
}

/// Run `merge`.
pub fn run(cli: &Cli, args: MergeArgs<'_>) -> ExitCode {
    let MergeArgs {
        inputs,
        output,
        redact: redact_output,
        key_file,
    } = args;
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
    let key_path = key_file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cli.engagement.join("redact.key"));
    // The tool makes a new key only for the default key file. A key file that the user names must exist.
    let key = if redact_output && key_file.is_none() {
        RedactKey::load_or_create(&key_path).map(Some)
    } else if redact_output || key_file.is_some() || key_path.exists() {
        RedactKey::load(&key_path).map(Some)
    } else {
        Ok(None)
    };
    let key = match key {
        Ok(key) => key,
        Err(error) => {
            eprintln!("{error}");
            return ExitCode::Error;
        }
    };
    if let Some(key) = key.as_ref().filter(|_| redact_output) {
        for file in &mut files {
            redact(file, key);
        }
    }
    let merged = match merge(files, key.as_ref()) {
        Ok(merged) => merged,
        Err(error) => {
            eprintln!(
                "{}",
                messages::MERGE_FAILED.replace("{reason}", &error.to_string())
            );
            return ExitCode::Error;
        }
    };
    let default_name = if redact_output {
        "merged.redacted.pqr"
    } else {
        "merged.pqr"
    };
    let path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cli.engagement.join("results").join(default_name));
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
