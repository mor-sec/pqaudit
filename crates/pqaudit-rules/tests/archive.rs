//! Hostile-input tests of the archive reader. Each archive must fail.

use pqaudit_rules::archive::{read_archive, ArchiveError, MAX_ENTRIES, MAX_UNPACKED_BYTES};

fn compress(tar_bytes: Vec<u8>) -> Vec<u8> {
    zstd::encode_all(tar_bytes.as_slice(), 3).unwrap()
}

/// A header with a raw name. This skips the safety checks of `set_path`.
fn raw_header(name: &[u8], kind: tar::EntryType, size: u64) -> tar::Header {
    let mut header = tar::Header::new_ustar();
    header.as_old_mut().name[..name.len()].copy_from_slice(name);
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(0o644);
    header.set_cksum();
    header
}

fn archive_with(entries: Vec<(tar::Header, Vec<u8>)>) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (header, data) in entries {
        builder.append(&header, data.as_slice()).unwrap();
    }
    compress(builder.into_inner().unwrap())
}

fn file(name: &str, data: &[u8]) -> (tar::Header, Vec<u8>) {
    (
        raw_header(name.as_bytes(), tar::EntryType::Regular, data.len() as u64),
        data.to_vec(),
    )
}

#[test]
fn good_archive_reads() {
    let bytes = archive_with(vec![file("pack.toml", b"x"), file("rules/a.yaml", b"y")]);
    assert_eq!(read_archive(&bytes).unwrap().len(), 2);
}

#[test]
fn symlink_entry_fails() {
    let mut header = raw_header(b"link", tar::EntryType::Symlink, 0);
    header.set_link_name("/etc/passwd").unwrap();
    header.set_cksum();
    let result = read_archive(&archive_with(vec![(header, vec![])]));
    assert!(
        matches!(result, Err(ArchiveError::NotAFile(_))),
        "{result:?}"
    );
}

#[test]
fn hardlink_entry_fails() {
    let mut header = raw_header(b"link", tar::EntryType::Link, 0);
    header.set_link_name("pack.toml").unwrap();
    header.set_cksum();
    let entries = vec![file("pack.toml", b"x"), (header, vec![])];
    let result = read_archive(&archive_with(entries));
    assert!(
        matches!(result, Err(ArchiveError::NotAFile(_))),
        "{result:?}"
    );
}

#[test]
fn parent_directory_path_fails() {
    for name in ["../x", "rules/../../x"] {
        let result = read_archive(&archive_with(vec![file(name, b"x")]));
        assert!(
            matches!(result, Err(ArchiveError::BadPath(_))),
            "{result:?}"
        );
    }
}

#[test]
fn absolute_path_fails() {
    let result = read_archive(&archive_with(vec![file("/etc/x", b"x")]));
    assert!(
        matches!(result, Err(ArchiveError::BadPath(_))),
        "{result:?}"
    );
}

#[test]
fn duplicate_path_fails() {
    let entries = vec![file("pack.toml", b"a"), file("pack.toml", b"b")];
    let result = read_archive(&archive_with(entries));
    assert!(
        matches!(result, Err(ArchiveError::Duplicate(_))),
        "{result:?}"
    );
}

#[test]
fn too_many_entries_fail() {
    let entries = (0..=MAX_ENTRIES)
        .map(|n| file(&format!("rules/{n}.yaml"), b""))
        .collect();
    let result = read_archive(&archive_with(entries));
    assert!(matches!(result, Err(ArchiveError::TooLarge)), "{result:?}");
}

#[test]
fn entry_over_the_size_limit_fails() {
    let big = vec![0u8; MAX_UNPACKED_BYTES as usize + 1];
    let result = read_archive(&archive_with(vec![file("pack.toml", &big)]));
    assert!(matches!(result, Err(ArchiveError::TooLarge)), "{result:?}");
}

#[test]
fn small_stream_that_expands_past_the_limit_fails() {
    // Three entries of 30 MiB each. Each is under the limit; the sum is not.
    let part = vec![0u8; 30 * 1024 * 1024];
    let entries = (0..3)
        .map(|n| file(&format!("rules/{n}.yaml"), &part))
        .collect();
    let bytes = archive_with(entries);
    assert!(bytes.len() < 1024 * 1024, "the stream must be small");
    let result = read_archive(&bytes);
    assert!(matches!(result, Err(ArchiveError::TooLarge)), "{result:?}");
}
