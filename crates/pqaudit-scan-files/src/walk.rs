//! Walk files and directories. The walk uses no ignore files.

use std::path::{Path, PathBuf};

use pqaudit_core::ScanError;
use walkdir::WalkDir;

use crate::messages;

/// Call `visit` for each regular file below the paths. Add an error for each path that fails.
///
/// The walk sorts names. The order of the results does not change between runs.
/// The walk skips a symbolic link unless `follow_symlinks` is true.
/// Return the number of symbolic links that the walk skipped.
pub fn walk(
    paths: &[PathBuf],
    follow_symlinks: bool,
    errors: &mut Vec<ScanError>,
    mut visit: impl FnMut(&Path, &mut Vec<ScanError>),
) -> u64 {
    let mut skipped_symlinks = 0;
    for root in paths {
        let walker = WalkDir::new(root)
            .follow_links(follow_symlinks)
            .sort_by_file_name();
        for entry in walker {
            match entry {
                Ok(entry) => {
                    if entry.file_type().is_file() {
                        visit(entry.path(), errors);
                    } else if entry.file_type().is_symlink() {
                        skipped_symlinks += 1;
                    }
                }
                Err(error) => {
                    let location = error
                        .path()
                        .unwrap_or(root.as_path())
                        .to_string_lossy()
                        .into_owned();
                    let reason = if error.loop_ancestor().is_some() {
                        messages::SYMLINK_LOOP.to_string()
                    } else {
                        let cause = error
                            .io_error()
                            .map_or_else(|| error.to_string(), ToString::to_string);
                        messages::CANNOT_READ.replace("{reason}", &cause)
                    };
                    errors.push(ScanError { location, reason });
                }
            }
        }
    }
    skipped_symlinks
}
