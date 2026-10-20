//! User-facing text of the CLI crate.

/// The text of a command that is not ready yet.
pub const NOT_IMPLEMENTED: &str = "This command is not implemented yet.";

/// The error when the tool cannot merge. The tool fills in {reason}.
pub const MERGE_FAILED: &str = "The tool cannot merge the results files. {reason}";

/// The error when the tool cannot read an input file. The tool fills in {path} and {reason}.
pub const MERGE_READ: &str = "The tool cannot read the results file {path}. {reason}";

/// The summary of a merge. The tool fills in {inputs}, {findings}, {inventory}, and {errors}.
pub const MERGE_SUMMARY: &str =
    "Merged {inputs} files. The result has {findings} findings, {inventory} inventory items, and {errors} errors.";

/// The note that the output has no sensitive names.
pub const MERGE_REDACTED: &str = "The output file has no host names, addresses, paths, or banners.";

/// The text when a profile ID is not in the rules pack.
pub const UNKNOWN_PROFILE: &str = "This profile does not exist:";

/// The text when the signature of a pack is correct.
pub const RULES_SIGNATURE_OK: &str = "The signature is correct.";

/// The warning when the tool uses a pack without a valid signature.
pub const RULES_UNSIGNED_WARNING: &str = "Warning: this pack has no valid signature. The tool accepts it because you gave the flag --allow-unsigned-rules.";

/// The hint when the signature check fails.
pub const RULES_UNSIGNED_HINT: &str =
    "To accept a pack without a valid signature, use the flag --allow-unsigned-rules.";

/// The text before the directory of an installed pack.
pub const RULES_INSTALLED: &str = "Installed the pack in:";

/// The text before the directory that `init` made.
pub const INIT_CREATED: &str = "Made the engagement directory:";

/// The text that tells the user what to do after `init`.
pub const INIT_NEXT: &str =
    "Edit the files engagement.toml, scope.toml, and assets.toml. Then run a scan.";

/// The error when the directory for `init` is not empty. The tool fills in {dir}.
pub const INIT_NOT_EMPTY: &str =
    "The directory {dir} is not empty. The command init does not change it.";

/// The error when `init` cannot make a file or directory. The tool fills in {dir} and {reason}.
pub const INIT_IO: &str = "The tool cannot make the engagement directory {dir}. {reason}";

/// The error when the tool cannot load the engagement files. The tool fills in {reason}.
pub const ENGAGEMENT_LOAD: &str = "The tool cannot load the engagement. {reason}";

/// The error when the tool cannot load the rules pack. The tool fills in {reason}.
pub const PACK_LOAD: &str = "The tool cannot load the rules pack. {reason}";

/// The error when the password source does not work. The tool fills in {source}.
pub const PASSWORDS_UNAVAILABLE: &str =
    "The tool cannot read the passwords from {source}. Check the table passwords in engagement.toml.";

/// The error when the tool cannot write the results file. The tool fills in {path} and {reason}.
pub const RESULTS_WRITE: &str = "The tool cannot write the results file {path}. {reason}";

/// The text before the path of the results file.
pub const SCAN_RESULTS: &str = "Wrote the results to:";

/// The summary of a file scan. The tool fills in {files}, {findings}, {inventory}, and {errors}.
pub const SCAN_SUMMARY: &str =
    "Read {files} files. Found {findings} findings and {inventory} other items. {errors} paths gave errors.";

/// The text before each scan error. The tool fills in {location} and {reason}.
pub const SCAN_ERROR_LINE: &str = "Scan error at {location}: {reason}";

/// The text when the tool hides more scan errors. The tool fills in {count}.
pub const SCAN_ERRORS_HIDDEN: &str =
    "The tool does not show {count} more errors. The results file lists them.";

/// The error when the tool could read no file.
pub const SCAN_NO_FILES: &str = "The tool could read no file.";

/// The summary line for skipped symbolic links. The tool fills in {count}.
pub const SCAN_SYMLINKS_SKIPPED: &str =
    "The tool skipped {count} symbolic links. Use the flag --follow-symlinks to scan them.";

/// The summary line for files with PEM data but no certificate. The tool fills in {count}.
pub const SCAN_NOT_READ: &str =
    "The tool did not read {count} files as certificates. They have PEM data but no certificate.";

/// The error when the tool cannot load the scope file. The tool fills in {reason}.
pub const SCOPE_LOAD: &str = "The tool cannot load the scope. {reason}";

/// A planned target with a host name. The tool fills in {host}, {ip}, {port}, {protocol}, and {connections}.
pub const NET_TARGET_NAMED: &str = "Target: host {host}, address {ip}, port {port}, protocol {protocol}, connections {connections}.";

/// A planned target without a host name. The tool fills in {ip}, {port}, {protocol}, and {connections}.
pub const NET_TARGET_IP: &str =
    "Target: address {ip}, port {port}, protocol {protocol}, connections {connections}.";

/// A refused target. The tool fills in {target} and {reason}.
pub const NET_REFUSED: &str = "Refused: {target}. {reason}";

/// The summary of the plan. The tool fills in {targets} and {refused}.
pub const NET_SUMMARY: &str = "The plan has {targets} targets and {refused} refusals.";

/// The text when the plan has no targets.
pub const NET_NO_TARGETS: &str = "The plan has no targets. Add a target to the file scope.toml.";

/// The text when the plan has a refusal.
pub const NET_REFUSED_STOP: &str = "The tool refuses the full scan.";

/// The error when the tool cannot open the audit log. The tool fills in {path} and {reason}.
pub const AUDIT_OPEN: &str = "The tool cannot open the audit log {path}. {reason}";

/// The error when the audit log does not work during the scan.
pub const AUDIT_FAILED: &str =
    "The tool could not write all connections to the audit log. Do not use these results.";

/// The error when the tool cannot hash the audit log. The tool fills in {path} and {reason}.
pub const AUDIT_HASH: &str = "The tool cannot read the audit log {path}. {reason}";

/// The text before the path of the audit log.
pub const NET_AUDIT_LOG: &str = "Wrote the audit log to:";

/// The error when the tool cannot start the network runtime. The tool fills in {reason}.
pub const NET_RUNTIME: &str = "The tool cannot start the network runtime. {reason}";

/// The summary of a network scan. The tool fills in {targets}, {findings}, {inventory}, and {errors}.
pub const NET_SCAN_SUMMARY: &str =
    "Probed {targets} targets. Found {findings} findings and {inventory} other items. {errors} targets gave errors.";

/// The error when the plan has no targets and the tool makes no scan.
pub const NET_NOTHING_TO_SCAN: &str =
    "The plan has no targets. The tool made no connection. Add a target to the file scope.toml.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("SCOPE_LOAD", SCOPE_LOAD),
    ("AUDIT_OPEN", AUDIT_OPEN),
    ("AUDIT_FAILED", AUDIT_FAILED),
    ("AUDIT_HASH", AUDIT_HASH),
    ("NET_AUDIT_LOG", NET_AUDIT_LOG),
    ("NET_RUNTIME", NET_RUNTIME),
    ("NET_SCAN_SUMMARY", NET_SCAN_SUMMARY),
    ("NET_NOTHING_TO_SCAN", NET_NOTHING_TO_SCAN),
    ("NET_TARGET_NAMED", NET_TARGET_NAMED),
    ("NET_TARGET_IP", NET_TARGET_IP),
    ("NET_REFUSED", NET_REFUSED),
    ("NET_SUMMARY", NET_SUMMARY),
    ("NET_NO_TARGETS", NET_NO_TARGETS),
    ("NET_REFUSED_STOP", NET_REFUSED_STOP),
    ("NOT_IMPLEMENTED", NOT_IMPLEMENTED),
    ("MERGE_FAILED", MERGE_FAILED),
    ("MERGE_READ", MERGE_READ),
    ("MERGE_SUMMARY", MERGE_SUMMARY),
    ("MERGE_REDACTED", MERGE_REDACTED),
    ("UNKNOWN_PROFILE", UNKNOWN_PROFILE),
    ("RULES_SIGNATURE_OK", RULES_SIGNATURE_OK),
    ("RULES_UNSIGNED_WARNING", RULES_UNSIGNED_WARNING),
    ("RULES_UNSIGNED_HINT", RULES_UNSIGNED_HINT),
    ("RULES_INSTALLED", RULES_INSTALLED),
    ("INIT_CREATED", INIT_CREATED),
    ("INIT_NEXT", INIT_NEXT),
    ("INIT_NOT_EMPTY", INIT_NOT_EMPTY),
    ("INIT_IO", INIT_IO),
    ("ENGAGEMENT_LOAD", ENGAGEMENT_LOAD),
    ("PACK_LOAD", PACK_LOAD),
    ("PASSWORDS_UNAVAILABLE", PASSWORDS_UNAVAILABLE),
    ("RESULTS_WRITE", RESULTS_WRITE),
    ("SCAN_RESULTS", SCAN_RESULTS),
    ("SCAN_SUMMARY", SCAN_SUMMARY),
    ("SCAN_ERROR_LINE", SCAN_ERROR_LINE),
    ("SCAN_ERRORS_HIDDEN", SCAN_ERRORS_HIDDEN),
    ("SCAN_NO_FILES", SCAN_NO_FILES),
    ("SCAN_SYMLINKS_SKIPPED", SCAN_SYMLINKS_SKIPPED),
    ("SCAN_NOT_READ", SCAN_NOT_READ),
];
