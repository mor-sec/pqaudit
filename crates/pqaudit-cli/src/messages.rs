//! User-facing text of the CLI crate.

/// The error when the tool cannot write the CBOM. The tool fills in {path} and {reason}.
pub const CBOM_WRITE: &str = "The tool cannot write the CBOM {path}. {reason}";

/// The text after the tool writes the CBOM. The tool fills in {path}.
pub const CBOM_WRITTEN: &str = "Wrote the CBOM to {path}.";

/// The error when the tool cannot merge. The tool fills in {reason}.
pub const MERGE_FAILED: &str = "The tool cannot merge the results files. {reason}";

/// The error when the tool cannot read an input file. The tool fills in {path} and {reason}.
pub const MERGE_READ: &str = "The tool cannot read the results file {path}. {reason}";

/// The summary of a merge. The tool fills in {inputs}, {findings}, {inventory}, and {errors}.
pub const MERGE_SUMMARY: &str =
    "Merged {inputs} files. The result has {findings} findings, {inventory} inventory items, and {errors} errors.";

/// The note about the content of a redacted output file.
pub const MERGE_REDACTED: &str = "The output file has hashes in place of host names, addresses, paths, names, banners, and key comments. Certificate and key fingerprints stay in the file. They can identify a public certificate or key. Endpoint fingerprints and finding IDs can also confirm a guessed host name. For an IP address target, they show the IPv4 address, because a person can hash all 2^32 addresses.";

/// The text when a profile ID is not in the rules pack.
pub const UNKNOWN_PROFILE: &str = "This profile does not exist:";

/// The text when the signature of a pack is correct.
pub const RULES_SIGNATURE_OK: &str = "The signature is correct.";

/// The warning when the tool uses a pack without a valid signature.
pub const RULES_UNSIGNED_WARNING: &str = "Warning: this pack has no valid signature. The tool accepts it because you gave the flag --allow-unsigned-rules.";

/// The warning for an installed pack that the tool did not use. The tool fills in {version}, {path}, and {reason}.
pub const PACK_SKIPPED: &str =
    "Warning: the tool did not use the installed rules pack {version} in {path}. {reason}";

/// The log event that tells which pack the tool uses. The tool fills in {id}, {version}, and {origin}.
pub const LOG_PACK_ORIGIN: &str = "The active rules pack is {id} {version}. Origin: {origin}.";

/// The log event for the skipped files. The tool fills in {symlinks} and {not_read}.
pub const LOG_FILES_SKIPPED: &str =
    "The tool skipped {symlinks} symbolic links. It did not read {not_read} files as certificates.";

/// The error when the results file belongs to a different engagement. The tool fills in {results} and {engagement}.
pub const ENGAGEMENT_MISMATCH: &str = "The results file belongs to the engagement {results}. The engagement directory is {engagement}. Use a results file of this engagement.";

/// The warning when the tool cannot check the engagement name of redacted results.
pub const ENGAGEMENT_UNCHECKED: &str = "Warning: the tool cannot check the engagement name of the redacted results. The engagement directory has no file redact.key.";

/// The error when the tool cannot read the redaction key. The tool fills in {reason}.
pub const REDACT_KEY_LOAD: &str = "The tool cannot read the redaction key. {reason}";

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

/// The error when the tool cannot read the results file. The tool fills in {path} and {reason}.
pub const EXPLAIN_READ: &str = "The tool cannot read the results file {path}. {reason}";

/// The error for a finding ID that the results file does not have. The tool fills in {id}.
pub const EXPLAIN_UNKNOWN_ID: &str = "The results file has no finding with the ID {id}.";

/// The title line. The tool fills in {id} and {title}.
pub const EXPLAIN_TITLE: &str = "Finding {id}: {title}";

/// The rule line. The tool fills in {rule}.
pub const EXPLAIN_RULE: &str = "Rule: {rule}";

/// The description line. The tool fills in {text}.
pub const EXPLAIN_DESCRIPTION: &str = "Description: {text}";

/// The threat line. The tool fills in {threat}.
pub const EXPLAIN_THREAT: &str = "Threat type: {threat}";

/// The heading of the occurrences. The tool fills in {count}.
pub const EXPLAIN_OCCURRENCES: &str = "Occurrences ({count}):";

/// One occurrence. The tool fills in {location} and {evidence}.
pub const EXPLAIN_OCCURRENCE: &str = "  {location}: {evidence}";

/// The heading of the context.
pub const EXPLAIN_CONTEXT: &str = "Context:";

/// The asset line. The tool fills in {asset}.
pub const EXPLAIN_ASSET: &str = "  asset: {asset}";

/// One context field. The tool fills in {name} and {value}.
pub const EXPLAIN_CONTEXT_LINE: &str = "  {name}: {value}";

/// The value of a context field that the customer did not set.
pub const EXPLAIN_UNASSESSED: &str = "unassessed";

/// The value when no asset matches.
pub const EXPLAIN_NO_ASSET: &str = "none";

/// The flag for a finding with unassessed context.
pub const EXPLAIN_UNASSESSED_FLAG: &str =
    "The context has unassessed fields. The tool uses cautious values for them.";

/// The deadline line. The tool fills in {date} and {profile}.
pub const EXPLAIN_DEADLINE: &str = "Deadline: {date} (profile {profile})";

/// The source of the deadline. The tool fills in {title}, {url}, and {description}.
pub const EXPLAIN_DEADLINE_SOURCE: &str = "  Source: {title}, {url}. {description}";

/// The deadline line when no deadline applies.
pub const EXPLAIN_DEADLINE_NONE: &str = "Deadline: none applies";

/// The CWE line. The tool fills in {ids}.
pub const EXPLAIN_CWE: &str = "CWE: {ids}";

/// The ATT&CK line. The tool fills in {ids}.
pub const EXPLAIN_ATTACK: &str = "ATT&CK: {ids}";

/// The heading of the score factors.
pub const EXPLAIN_SCORE: &str = "Score factors (value x weight = contribution):";

/// One score factor. The tool fills in {name}, {value}, {weight}, {contribution}, and {note}.
pub const EXPLAIN_FACTOR: &str = "  {name}: {value} x {weight} = {contribution}. {note}";

/// The total line. The tool fills in {total} and {band}.
pub const EXPLAIN_TOTAL: &str = "Total: {total} of 100. Suggested band: {band}.";

/// The override line. The tool fills in {band}, {reason}, {by}, and {date}.
pub const EXPLAIN_OVERRIDE: &str = "Override: {band}. Reason: {reason} By {by} on {date}.";

/// The override line when there is no override.
pub const EXPLAIN_NO_OVERRIDE: &str = "Override: none";

/// The complexity line. The tool fills in {size}, {change}, and {years}.
pub const EXPLAIN_COMPLEXITY: &str =
    "Complexity: {size}. Change type: {change}. Migration time: {years} years.";

/// One reason for the complexity. The tool fills in {reason}.
pub const EXPLAIN_REASON: &str = "  - {reason}";

/// The tests line. The tool fills in {tests}.
pub const EXPLAIN_TESTS: &str = "Necessary tests: {tests}";

/// The remediation line. The tool fills in {text}.
pub const EXPLAIN_REMEDIATION: &str = "Remediation: {text}";

/// The error for a feature that comes in a later release.
pub const LATER_RELEASE: &str = "This feature comes in a later release.";

/// The error when the tool cannot write the report. The tool fills in {path} and {reason}.
pub const REPORT_WRITE: &str = "The tool cannot write the report {path}. {reason}";

/// The text after the tool writes the report. The tool fills in {path}.
pub const REPORT_WRITTEN: &str = "Wrote the report to {path}.";

/// Pairs of ID and text. The STE lint reads this list.
pub const ALL: &[(&str, &str)] = &[
    ("LATER_RELEASE", LATER_RELEASE),
    ("REPORT_WRITE", REPORT_WRITE),
    ("REPORT_WRITTEN", REPORT_WRITTEN),
    ("EXPLAIN_READ", EXPLAIN_READ),
    ("EXPLAIN_UNKNOWN_ID", EXPLAIN_UNKNOWN_ID),
    ("EXPLAIN_TITLE", EXPLAIN_TITLE),
    ("EXPLAIN_RULE", EXPLAIN_RULE),
    ("EXPLAIN_DESCRIPTION", EXPLAIN_DESCRIPTION),
    ("EXPLAIN_THREAT", EXPLAIN_THREAT),
    ("EXPLAIN_OCCURRENCES", EXPLAIN_OCCURRENCES),
    ("EXPLAIN_OCCURRENCE", EXPLAIN_OCCURRENCE),
    ("EXPLAIN_CONTEXT", EXPLAIN_CONTEXT),
    ("EXPLAIN_ASSET", EXPLAIN_ASSET),
    ("EXPLAIN_CONTEXT_LINE", EXPLAIN_CONTEXT_LINE),
    ("EXPLAIN_UNASSESSED", EXPLAIN_UNASSESSED),
    ("EXPLAIN_NO_ASSET", EXPLAIN_NO_ASSET),
    ("EXPLAIN_UNASSESSED_FLAG", EXPLAIN_UNASSESSED_FLAG),
    ("EXPLAIN_DEADLINE", EXPLAIN_DEADLINE),
    ("EXPLAIN_DEADLINE_SOURCE", EXPLAIN_DEADLINE_SOURCE),
    ("EXPLAIN_DEADLINE_NONE", EXPLAIN_DEADLINE_NONE),
    ("EXPLAIN_CWE", EXPLAIN_CWE),
    ("EXPLAIN_ATTACK", EXPLAIN_ATTACK),
    ("EXPLAIN_SCORE", EXPLAIN_SCORE),
    ("EXPLAIN_FACTOR", EXPLAIN_FACTOR),
    ("EXPLAIN_TOTAL", EXPLAIN_TOTAL),
    ("EXPLAIN_OVERRIDE", EXPLAIN_OVERRIDE),
    ("EXPLAIN_NO_OVERRIDE", EXPLAIN_NO_OVERRIDE),
    ("EXPLAIN_COMPLEXITY", EXPLAIN_COMPLEXITY),
    ("EXPLAIN_REASON", EXPLAIN_REASON),
    ("EXPLAIN_TESTS", EXPLAIN_TESTS),
    ("EXPLAIN_REMEDIATION", EXPLAIN_REMEDIATION),
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
    ("CBOM_WRITE", CBOM_WRITE),
    ("CBOM_WRITTEN", CBOM_WRITTEN),
    ("MERGE_FAILED", MERGE_FAILED),
    ("MERGE_READ", MERGE_READ),
    ("MERGE_SUMMARY", MERGE_SUMMARY),
    ("MERGE_REDACTED", MERGE_REDACTED),
    ("UNKNOWN_PROFILE", UNKNOWN_PROFILE),
    ("RULES_SIGNATURE_OK", RULES_SIGNATURE_OK),
    ("RULES_UNSIGNED_WARNING", RULES_UNSIGNED_WARNING),
    ("RULES_UNSIGNED_HINT", RULES_UNSIGNED_HINT),
    ("PACK_SKIPPED", PACK_SKIPPED),
    ("LOG_PACK_ORIGIN", LOG_PACK_ORIGIN),
    ("LOG_FILES_SKIPPED", LOG_FILES_SKIPPED),
    ("ENGAGEMENT_MISMATCH", ENGAGEMENT_MISMATCH),
    ("ENGAGEMENT_UNCHECKED", ENGAGEMENT_UNCHECKED),
    ("REDACT_KEY_LOAD", REDACT_KEY_LOAD),
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
