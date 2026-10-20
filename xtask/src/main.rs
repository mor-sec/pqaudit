//! Build tasks for pqaudit.

mod check_offline;
mod keygen;
mod pack_rules;
mod sign;
mod strings;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// The xtask commands.
#[derive(Debug, Parser)]
struct Xtask {
    #[command(subcommand)]
    command: Task,
}

#[derive(Debug, Subcommand)]
enum Task {
    /// Check that the offline scanner has no network crates.
    CheckOfflineDeps,
    /// Make a hybrid key pair (Ed25519 and ML-DSA-65) as PEM files.
    Keygen {
        /// Write the four key files to this directory.
        #[arg(long)]
        out: PathBuf,
    },
    /// Sign a file with a hybrid key pair.
    Sign {
        /// Read the private keys from this directory.
        #[arg(long)]
        keys: PathBuf,
        /// The file to sign.
        file: PathBuf,
    },
    /// Make the archive of the rules pack.
    PackRules {
        /// Write the archive to this directory.
        #[arg(long)]
        out: PathBuf,
        /// Read the project from this directory.
        #[arg(long, default_value = ".")]
        root: PathBuf,
    },
    /// Write all project text to Markdown files for the STE lint.
    Strings {
        /// Write the files to this directory.
        #[arg(long, default_value = "target/ste")]
        out: PathBuf,
        /// Read the project from this directory.
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Read the commit messages in this Git range.
        #[arg(long)]
        commits: Option<String>,
    },
}

fn finish(result: Result<(), Box<dyn std::error::Error>>) -> ExitCode {
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("xtask: {error}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    match Xtask::parse().command {
        Task::CheckOfflineDeps => finish(check_offline::run()),
        Task::Keygen { out } => finish(keygen::run(&out)),
        Task::Sign { keys, file } => finish(sign::run(&keys, &file)),
        Task::PackRules { out, root } => finish(pack_rules::run(&root, &out)),
        Task::Strings { out, root, commits } => match strings::run(&root, &out, commits.as_deref())
        {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("xtask: {error}");
                ExitCode::FAILURE
            }
        },
    }
}
