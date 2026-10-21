//! Output helpers for the global flags.
//!
//! Summary lines go to stdout. The flag --quiet stops them.
//! Warnings and diagnostic events go to the log on stderr.
//! The flags --verbose and --log-format control the log.
//!
//! Paths, host names, and locations can hold control characters. A control character can
//! change the terminal or add a false line. Thus each helper here cleans its text first.
//! A line break in a value from outside the tool can also add a false line. Thus the
//! callers clean each such value with [`value`] before it goes into a message.

use std::path::Path;

use pqaudit_core::text::clean;

use crate::cli::Cli;

/// Clean each line of a text for the terminal. The line ends stay.
///
/// Use this function only for the line breaks that the tool writes itself.
/// Clean each value from outside the tool with [`value`] first.
pub fn shown(text: &str) -> String {
    text.split('\n').map(clean).collect::<Vec<_>>().join("\n")
}

/// Clean one value from outside the tool before it goes into a message.
///
/// Examples are a location, a host name, a subject, an alias, or a comment.
/// The function also replaces each line break, so the value cannot add a false line.
pub fn value(text: &str) -> String {
    clean(text)
}

/// Clean a path for the terminal. A line break in the path becomes `?`.
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
