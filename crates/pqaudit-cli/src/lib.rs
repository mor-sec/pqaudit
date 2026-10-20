//! The pqaudit command-line library.
//!
//! The binary calls [`run`]. Tests can call it too.

pub mod cli;
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
    dispatch(&cli.command)
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
fn dispatch(command: &Command) -> ExitCode {
    match command {
        Command::Init
        | Command::Merge
        | Command::Report
        | Command::Cbom
        | Command::Explain
        | Command::Rules
        | Command::Profiles
        | Command::Scan {
            command: ScanCommand::Files | ScanCommand::Net,
        } => not_implemented(),
    }
}

fn not_implemented() -> ExitCode {
    eprintln!("{}", messages::NOT_IMPLEMENTED);
    ExitCode::Error
}
