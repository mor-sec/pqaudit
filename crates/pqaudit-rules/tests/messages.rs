//! Tests of the user-facing text of the rules crate.

use pqaudit_rules::archive::ArchiveError;
use pqaudit_rules::install::InstallError;
use pqaudit_rules::messages::ALL;
use pqaudit_rules::pack::PackError;
use pqaudit_rules::verify::VerifyError;

#[test]
fn error_texts_come_from_the_message_list() {
    let texts = [
        InstallError::NoDataDir.to_string(),
        InstallError::BadFile("x".into()).to_string(),
        ArchiveError::TooLarge.to_string(),
        VerifyError::BadSignature("Ed25519").to_string(),
        PackError::Missing {
            path: "pack.toml".into(),
        }
        .to_string(),
        PackError::Io {
            path: "a".into(),
            message: "b".into(),
        }
        .to_string(),
    ];
    for text in texts {
        assert!(
            ALL.iter().any(|(_, message)| fits(message, &text)),
            "{text} is not in the message list"
        );
    }
}

/// True if the text is the template with each `{name}` filled in.
fn fits(template: &str, text: &str) -> bool {
    let mut rest = text;
    let count = template.split('{').count();
    for (index, part) in template.split('{').enumerate() {
        let fixed = if index == 0 {
            part
        } else {
            match part.split_once('}') {
                Some((_, after)) => after,
                None => return false,
            }
        };
        if index + 1 == count && index > 0 {
            return rest.ends_with(fixed);
        }
        match rest.find(fixed) {
            Some(at) if index > 0 || at == 0 => rest = &rest[at + fixed.len()..],
            _ => return false,
        }
    }
    rest.is_empty()
}

#[test]
fn each_text_has_a_subject() {
    for (id, text) in ALL {
        assert!(!text.starts_with("Cannot"), "{id}: {text}");
    }
    assert!(ALL.len() >= 20, "the list has only {} texts", ALL.len());
}
