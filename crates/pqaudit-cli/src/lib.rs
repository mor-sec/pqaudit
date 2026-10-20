//! The pqaudit command-line library.
//!
//! The binary calls [`run`]. Tests can call it too.

pub mod cli;
pub mod commands;
pub mod exit;
pub mod messages;

use clap::Parser;

use cli::{Cli, Command, LogFormat, ScanCommand};
use exit::ExitCode;

/// Run pqaudit with the given arguments. Return the exit code.
pub fn run<I, T>(args: I) -> ExitCode
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            let is_info = !error.use_stderr();
            // If the reader closes the output stream, there is nothing more to do.
            let _ = error.print();
            return if is_info {
                ExitCode::Success
            } else {
                ExitCode::Error
            };
        }
    };
    init_logging(&cli);
    dispatch(&cli)
}

/// Set up the log output from the global flags.
fn init_logging(cli: &Cli) {
    let level = if cli.quiet {
        tracing::Level::ERROR
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    let builder = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(std::io::stderr)
        .with_ansi(!cli.no_color);
    // A second call fails when a subscriber exists. This is safe to ignore.
    let _ = match cli.log_format {
        LogFormat::Text => builder.try_init(),
        LogFormat::Json => builder.json().try_init(),
    };
}

/// Run one command. Each command is a stub until its task replaces it.
fn dispatch(cli: &Cli) -> ExitCode {
    match &cli.command {
        Command::Profiles { command } => commands::profiles::run(command),
        Command::Rules { command } => commands::rules::run(command, cli.allow_unsigned_rules),
        Command::Init { name, dir } => commands::init::run(name, dir),
        Command::Scan {
            command:
                ScanCommand::Files {
                    paths,
                    max_file_size,
                    follow_symlinks,
                    output,
                },
        } => commands::scan_files::run(
            cli,
            commands::scan_files::FilesArgs {
                paths,
                max_file_size: *max_file_size,
                follow_symlinks: *follow_symlinks,
                output: output.as_deref(),
            },
        ),
        Command::Scan {
            command: ScanCommand::Net { dry_run, output },
        } => commands::scan_net::run(cli, *dry_run, output.as_deref()),
        Command::Merge {
            inputs,
            output,
            redact,
            redact_key_file,
        } => commands::merge::run(
            cli,
            commands::merge::MergeArgs {
                inputs,
                output: output.as_deref(),
                redact: *redact,
                key_file: redact_key_file.as_deref(),
            },
        ),
        Command::Explain {
            finding_id,
            results,
        } => commands::explain::run(cli, finding_id, results.as_deref()),
        Command::Report | Command::Cbom => not_implemented(),
    }
}

fn not_implemented() -> ExitCode {
    eprintln!("{}", messages::NOT_IMPLEMENTED);
    ExitCode::Error
}
