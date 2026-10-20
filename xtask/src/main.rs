//! Build tasks for pqaudit.

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

fn main() -> ExitCode {
    match Xtask::parse().command {
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
