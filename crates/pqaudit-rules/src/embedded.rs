//! The default rules pack. The build puts the pack files inside the program.

use std::sync::OnceLock;

use include_dir::{include_dir, Dir};

use crate::pack::RulesPack;

static RULES_DIR: Dir<'static> = include_dir!("$CARGO_MANIFEST_DIR/../../rules");

fn collect(dir: &Dir<'static>, files: &mut Vec<(String, Vec<u8>)>) {
    for file in dir.files() {
        files.push((
            file.path().to_string_lossy().replace('\\', "/"),
            file.contents().to_vec(),
        ));
    }
    for sub in dir.dirs() {
        collect(sub, files);
    }
}

/// Return the default rules pack. The first call parses it.
///
/// # Panics
/// Panics if the files in `rules/` are wrong. A test finds this error.
pub fn default_pack() -> &'static RulesPack {
    static PACK: OnceLock<RulesPack> = OnceLock::new();
    PACK.get_or_init(|| {
        let mut files = Vec::new();
        collect(&RULES_DIR, &mut files);
        RulesPack::from_files(files).expect("the embedded rules pack is valid")
    })
}
