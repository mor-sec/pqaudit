//! Output helpers for the global flags.
//!
//! Summary lines go to stdout. The flag --quiet stops them.
//! Warnings and diagnostic events go to the log on stderr.
//! The flags --verbose and --log-format control the log.

use crate::cli::Cli;

/// Show a summary line on stdout, unless the user gave the flag --quiet.
pub fn summary(cli: &Cli, text: &str) {
    if !cli.quiet {
        println!("{text}");
    }
}

/// Write a warning to the log. The flag --quiet does not stop warnings.
pub fn warn(text: &str) {
    tracing::warn!("{text}");
}

/// Write a diagnostic event to the log. Only the flag --verbose shows it.
pub fn debug(text: &str) {
    tracing::debug!("{text}");
}
