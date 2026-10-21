//! Output helpers for the global flags.
//!
//! Summary lines go to stdout. The flag --quiet stops them.
//! Warnings and diagnostic events go to the log on stderr.
//! The flags --verbose and --log-format control the log.
//!
//! Paths, host names, and locations can hold control characters. A control character can
//! change the terminal or add a false line. Thus each helper here cleans its text first.

use std::path::Path;

use pqaudit_core::text::clean;

use crate::cli::Cli;

/// Clean each line of a text for the terminal. The line ends stay.
pub fn shown(text: &str) -> String {
    text.split('\n').map(clean).collect::<Vec<_>>().join("\n")
}

/// Clean a path for the terminal.
pub fn shown_path(path: &Path) -> String {
    clean(&path.display().to_string())
}

/// Show a summary line on stdout, unless the user gave the flag --quiet.
pub fn summary(cli: &Cli, text: &str) {
    if !cli.quiet {
        println!("{}", shown(text));
    }
}

/// Show a line on stdout. The flag --quiet does not stop it.
pub fn line(text: &str) {
    println!("{}", shown(text));
}

/// Show an error line on stderr.
pub fn error(text: &str) {
    eprintln!("{}", shown(text));
}

/// Write a warning to the log. The flag --quiet does not stop warnings.
pub fn warn(text: &str) {
    tracing::warn!("{}", shown(text));
}

/// Write a diagnostic event to the log. Only the flag --verbose shows it.
pub fn debug(text: &str) {
    tracing::debug!("{}", shown(text));
}
