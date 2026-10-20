//! Exit codes of the pqaudit binary.

/// The exit code of a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExitCode {
    /// The command succeeded.
    Success = 0,
    /// The command failed.
    Error = 1,
    /// The tool refused the command because of scope or safety.
    Refused = 2,
    /// The command gave partial results.
    Partial = 3,
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(code: ExitCode) -> Self {
        std::process::ExitCode::from(code as u8)
    }
}

#[cfg(test)]
mod tests {
    use super::ExitCode;

    #[test]
    fn codes_have_the_documented_values() {
        assert_eq!(ExitCode::Success as u8, 0);
        assert_eq!(ExitCode::Error as u8, 1);
        assert_eq!(ExitCode::Refused as u8, 2);
        assert_eq!(ExitCode::Partial as u8, 3);
    }
}
