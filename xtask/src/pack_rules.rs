//! The `pack-rules` task: make the pack archive of the `rules/` directory.

use std::fs;
use std::path::Path;

use pqaudit_rules::archive::build_archive;
use pqaudit_rules::pack::RulesPack;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Read all files of a directory. Skip the trust list.
pub fn collect(root: &Path, dir: &Path, files: &mut Vec<(String, Vec<u8>)>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(root, &path, files)?;
            continue;
        }
        let name = path
            .strip_prefix(root)?
            .components()
            .map(|part| part.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if !name.starts_with("trust/") {
            files.push((name, fs::read(&path)?));
        }
    }
    Ok(())
}

/// Make `rules-<version>.tar.zst` in `out` from the `rules/` directory of `root`.
///
/// The task checks that the files make a valid pack. The archive is the same each time.
pub fn run(root: &Path, out: &Path) -> Result<()> {
    let rules = root.join("rules");
    let mut files = Vec::new();
    collect(&rules, &rules, &mut files)?;
    let pack = RulesPack::from_files(files.clone())?;
    let archive = build_archive(files)?;
    fs::create_dir_all(out)?;
    let path = out.join(format!("rules-{}.tar.zst", pack.version));
    fs::write(&path, archive)?;
    println!("{}", path.display());
    Ok(())
}
