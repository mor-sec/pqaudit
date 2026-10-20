//! The command-line interface of pqaudit.

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

/// Audit the readiness of a system for post-quantum cryptography.
#[derive(Debug, Parser)]
#[command(name = "pqaudit", version)]
pub struct Cli {
    /// Use this directory as the engagement directory.
    #[arg(long, global = true, value_name = "DIR", default_value = ".")]
    pub engagement: PathBuf,

    /// Show errors only.
    #[arg(long, global = true, conflicts_with = "verbose")]
    pub quiet: bool,

    /// Show debug messages.
    #[arg(long, global = true)]
    pub verbose: bool,

    /// Set the format of the log output.
    #[arg(long, global = true, value_enum, default_value = "text")]
    pub log_format: LogFormat,

    /// Do not use colors in the output.
    #[arg(long, global = true)]
    pub no_color: bool,

    /// Accept a rules pack that has no valid signature. Use this flag for tests only.
    #[arg(long, global = true)]
    pub allow_unsigned_rules: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// The format of the log output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Plain text for people.
    Text,
    /// One JSON object for each line.
    Json,
}

/// The commands of pqaudit.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Make the engagement directory and its template files.
    Init,
    /// Scan files or the network for cryptography.
    Scan {
        #[command(subcommand)]
        command: ScanCommand,
    },
    /// Combine results files into one results file.
    Merge,
    /// Make a report from a results file.
    Report,
    /// Make a cryptography bill of materials (CBOM).
    Cbom,
    /// Explain a finding or a rule.
    Explain,
    /// Show or check the rules pack.
    Rules,
    /// Show the deadline profiles.
    Profiles,
}

/// The scan commands.
#[derive(Debug, Subcommand)]
pub enum ScanCommand {
    /// Scan files on disk. This command does not use the network.
    Files,
    /// Scan network endpoints that the scope file lists.
    Net,
}
