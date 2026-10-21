//! Clean text that comes from files and network peers.
//!
//! Such text can go to a terminal, a log, or a report.
//! A control character in it can change how the text shows, or add a false line.

/// Replace each control character with `?`. Keep the printable Unicode characters.
///
/// The function also replaces the line and paragraph separators and the
/// bidirectional controls, because they can change how the text shows.
pub fn clean(text: &str) -> String {
    text.chars()
        .map(|c| if is_unsafe(c) { '?' } else { c })
        .collect()
}

/// Clean bytes that can be text. A byte sequence that is not UTF-8 becomes U+FFFD first.
pub fn clean_bytes(bytes: &[u8]) -> String {
    clean(&String::from_utf8_lossy(bytes))
}

fn is_unsafe(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}' | '\u{2029}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
        )
}
