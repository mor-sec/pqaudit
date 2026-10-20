//! Reports for pqaudit.

pub mod cbom;
pub mod messages;
pub mod technical;

/// The output format of a report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// One HTML file with inline styles.
    Html,
    /// Markdown text.
    Md,
    /// The assessment as JSON.
    Json,
}

/// An error while the tool makes a report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportError(pub String);

impl std::fmt::Display for ReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ReportError {}
