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

    /// Accept a rules pack that has no correct signature. The results record this choice.
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
    /// Show, check, or update the rules pack.
    Rules {
        #[command(subcommand)]
        command: RulesCommand,
    },
    /// Show the deadline profiles.
    Profiles {
        #[command(subcommand)]
        command: ProfilesCommand,
    },
}

/// The rules commands.
#[derive(Debug, Subcommand)]
pub enum RulesCommand {
    /// Show the active rules pack and the installed packs.
    List,
    /// Check the signature of a rules pack archive.
    Verify {
        /// The pack archive, for example `rules-1.0.0.tar.zst`.
        archive: PathBuf,
        /// The signature file. The default is the archive name and `.sig.json`.
        #[arg(long, value_name = "FILE")]
        sig: Option<PathBuf>,
    },
    /// Check a rules pack archive and install it.
    Update {
        /// The pack archive to install.
        #[arg(long, value_name = "ARCHIVE")]
        from: PathBuf,
        /// The signature file. The default is the archive name and `.sig.json`.
        #[arg(long, value_name = "FILE")]
        sig: Option<PathBuf>,
    },
}

/// The profiles commands.
#[derive(Debug, Subcommand)]
pub enum ProfilesCommand {
    /// List the deadline profiles.
    List,
    /// Show the milestones of one deadline profile.
    Show {
        /// The ID of the profile, for example `uk`.
        id: String,
    },
}

/// The scan commands.
#[derive(Debug, Subcommand)]
pub enum ScanCommand {
    /// Scan files on disk. This command does not use the network.
    Files,
    /// Scan network endpoints that the scope file lists.
    Net,
}
