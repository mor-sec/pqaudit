//! The `scan files` command: scan files for X.509 certificates.

use std::path::{Path, PathBuf};

use chrono::Utc;
use pqaudit_core::engagement::{Engagement, PasswordSource};
use pqaudit_core::{PackRef, ResultsFile, ResultsHeader, RunInfo, ScannerKind, SCHEMA_VERSION};
use pqaudit_rules::install::active_pack;
use pqaudit_scan_files::{scan, ScanOptions};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::cli::Cli;
use crate::exit::ExitCode;
use crate::messages;

/// The most scan errors that the command shows on the screen.
const MAX_SHOWN_ERRORS: usize = 50;

/// The arguments of `scan files`.
pub struct FilesArgs<'a> {
    /// The files and directories to scan.
    pub paths: &'a [PathBuf],
    /// The size limit for each file, in bytes.
    pub max_file_size: u64,
    /// True if the scan follows symbolic links.
    pub follow_symlinks: bool,
    /// The results file. `None` means a new file in the results directory.
    pub output: Option<&'a Path>,
}

/// Run `scan files`.
pub fn run(cli: &Cli, args: FilesArgs<'_>) -> ExitCode {
    let started = Utc::now();
    let engagement = match Engagement::load(&cli.engagement) {
        Ok(engagement) => engagement,
        Err(error) => return fail(messages::ENGAGEMENT_LOAD, &error.to_string()),
    };
    let active = match active_pack(cli.allow_unsigned_rules) {
        Ok(active) => active,
        Err(error) => return fail(messages::PACK_LOAD, &error.to_string()),
    };
    let passwords = match read_passwords(engagement.config.passwords.as_ref(), &engagement.dir) {
        Ok(passwords) => passwords,
        Err(source) => {
            eprintln!(
                "{}",
                messages::PASSWORDS_UNAVAILABLE.replace("{source}", &source)
            );
            return ExitCode::Error;
        }
    };

    let options = ScanOptions {
        max_file_size: args.max_file_size,
        follow_symlinks: args.follow_symlinks,
        passwords,
    };
    let run_id = Uuid::new_v4();
    let output = scan(args.paths, &options, &active.pack, run_id);
    let finished = Utc::now();

    let host = host_name();
    let results = ResultsFile {
        header: ResultsHeader {
            schema_version: SCHEMA_VERSION,
            engagement: engagement_name(&engagement),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            rules_pack: PackRef {
                id: active.pack.id.clone(),
                version: active.pack.version.to_string(),
                content_hash: active.pack.content_hash.clone(),
                origin: (&active.origin).into(),
            },
            scanner: ScannerKind::Files,
            host: host.clone(),
            operator: engagement.config.assessor.clone(),
            started,
            finished,
            scope_hash: None,
            audit_log_hash: None,
            runs: vec![RunInfo {
                run_id,
                scanner: ScannerKind::Files,
                host,
                started,
            }],
            redacted: false,
        },
        findings: output.findings.clone(),
        inventory: output.inventory.clone(),
        errors: output.errors.clone(),
    };

    let path = match args.output {
        Some(path) => path.to_path_buf(),
        None => engagement
            .dir
            .join("results")
            .join(format!("files-{}.pqr", started.format("%Y%m%dT%H%M%S"))),
    };
    if let Err(error) = write_results(&results, &path) {
        return fail(
            &messages::RESULTS_WRITE.replace("{path}", &path.display().to_string()),
            &error.to_string(),
        );
    }

    for error in output.errors.iter().take(MAX_SHOWN_ERRORS) {
        eprintln!(
            "{}",
            messages::SCAN_ERROR_LINE
                .replace("{location}", &error.location)
                .replace("{reason}", &error.reason)
        );
    }
    if output.errors.len() > MAX_SHOWN_ERRORS {
        eprintln!(
            "{}",
            messages::SCAN_ERRORS_HIDDEN.replace(
                "{count}",
                &(output.errors.len() - MAX_SHOWN_ERRORS).to_string()
            )
        );
    }
    println!(
        "{}",
        messages::SCAN_SUMMARY
            .replace("{files}", &output.files_read.to_string())
            .replace("{findings}", &output.findings.len().to_string())
            .replace("{inventory}", &output.inventory.len().to_string())
            .replace("{errors}", &output.errors.len().to_string())
    );
    println!("{} {}", messages::SCAN_RESULTS, path.display());

    if output.skipped_symlinks > 0 {
        println!(
            "{}",
            messages::SCAN_SYMLINKS_SKIPPED
                .replace("{count}", &output.skipped_symlinks.to_string())
        );
    }
    if output.files_not_read > 0 {
        println!(
            "{}",
            messages::SCAN_NOT_READ.replace("{count}", &output.files_not_read.to_string())
        );
    }

    if output.files_read == 0 {
        eprintln!("{}", messages::SCAN_NO_FILES);
        ExitCode::Error
    } else if output.errors.is_empty() {
        ExitCode::Success
    } else {
        ExitCode::Partial
    }
}

fn fail(text: &str, reason: &str) -> ExitCode {
    eprintln!("{}", text.replace("{reason}", reason));
    ExitCode::Error
}

fn write_results(results: &ResultsFile, path: &Path) -> std::io::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    results.write(path, true)
}

/// The name of the engagement is the name of its directory.
fn engagement_name(engagement: &Engagement) -> String {
    std::fs::canonicalize(&engagement.dir)
        .ok()
        .and_then(|dir| {
            dir.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| engagement.config.client.clone())
}

fn host_name() -> String {
    ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|value| !value.is_empty()))
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|text| text.trim().to_string())
                .filter(|text| !text.is_empty())
        })
        .unwrap_or_else(|| String::from("unknown"))
}

/// Read the passwords. Return the name of the source if it does not work.
///
/// The error never holds a password. Each line is one password.
fn read_passwords(
    source: Option<&PasswordSource>,
    dir: &Path,
) -> Result<Vec<Zeroizing<String>>, String> {
    let text: Zeroizing<String> = match source {
        None => return Ok(Vec::new()),
        Some(PasswordSource::Env { env }) => {
            Zeroizing::new(std::env::var(env).map_err(|_| env.clone())?)
        }
        Some(PasswordSource::File { file }) => {
            let path = dir.join(file);
            Zeroizing::new(std::fs::read_to_string(&path).map_err(|_| path.display().to_string())?)
        }
    };
    Ok(text
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| Zeroizing::new(line.to_string()))
        .collect())
}
