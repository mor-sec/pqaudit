//! Build tasks for pqaudit.

mod check_offline;
mod keygen;
mod pack_rules;
mod self_cbom;
mod sign;
mod sign_release;
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
    /// Make the CBOM of pqaudit from its SBOM and `docs/self-crypto.toml`.
    SelfCbom {
        /// Read the SBOM (CycloneDX JSON) from this file.
        #[arg(long)]
        sbom: PathBuf,
        /// Write the CBOM to this file.
        #[arg(long)]
        out: PathBuf,
        /// Read the project from this directory.
        #[arg(long, default_value = ".")]
        root: PathBuf,
        /// Read the crypto declaration from this file. The default is `docs/self-crypto.toml` in the project.
        #[arg(long)]
        declaration: Option<PathBuf>,
    },
    /// Check the Sigstore bundles of a downloaded release. Write and sign the checksum files.
    SignRelease {
        /// Read the private keys from this directory.
        #[arg(long)]
        keys: PathBuf,
        /// The directory with the downloaded release files.
        #[arg(long)]
        dir: PathBuf,
        /// The GitHub repository that built the release, as `owner/name`.
        #[arg(long)]
        repo: String,
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
        Task::SelfCbom {
            sbom,
            out,
            root,
            declaration,
        } => {
            let declaration = declaration.unwrap_or_else(|| root.join("docs/self-crypto.toml"));
            finish(self_cbom::run(&root, &sbom, &declaration, &out))
        }
        Task::SignRelease { keys, dir, repo } => finish(sign_release::run(&keys, &dir, &repo)),
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
