# pqaudit user guide

This guide describes the engagement folder, each key of each file, each command and flag, and the exit codes. It also tells how to read the technical report and how the tool calculates the score. The text of the command descriptions is the same as the CLI help. When this guide and the CLI help differ, the CLI help is correct.

## Contents

- The engagement folder
- The engagement files and their keys
- Commands and flags
- Exit codes
- The file scan
- The network scan
- Merge and redaction
- Assessment: how the tool uses your context
- How to read the technical report
- How the tool calculates the score
- How the tool selects deadlines
- Overrides
- Rules packs
- Known limits

## The engagement folder

An engagement is a folder. The command `init` makes it. The folder holds the files of one audit.

```text
acme-2026q4/
  engagement.toml   the main facts of the audit
  scope.toml        the only source of network targets
  assets.toml       the context of your systems
  overrides.toml    your changes to suggested priorities
  scoring.toml      the formula for the suggested priority
  results/          the results files (.pqr)
  reports/          the reports and the CBOM
  audit.log         one line for each network connection (made by scan net)
  redact.key        the key for redaction (made by merge --redact)
```

Most commands read the folder that the flag `--engagement` names. The default is the current folder. The command `init` is different. It makes a new folder, and it needs a name.

The file `engagement.toml` must exist. The tool uses the default values when the other files do not exist.

The command `init` stops with exit code 1 if the target folder exists and is not empty. It never changes an existing folder.

Keep `redact.key` private. Do not put it in a shared folder, in a ticket, or in an email. Refer to the section "Merge and redaction".

## The engagement files and their keys

All engagement files use TOML. The command `init` writes each file with comments. The tool stops with an error if a file has a key that it does not know.

### engagement.toml

| Key | Meaning |
| --- | --- |
| `client` | The name of your client. The key must exist |
| `assessor` | Your name and your company. The key must exist |
| `assessment_date` | The date of the assessment, in the format YEAR-MONTH-DAY. The default is the local date |
| `[deadlines] profiles` | The list of deadline profiles. The values are `us`, `uk`, and `au`. The default is an empty list |
| `[deadlines] sector` | An optional sector overlay, for example `government` |
| `[assumptions] crqc_year` | The year in which a cryptographically relevant quantum computer (CRQC) can exist. The key must exist. The `init` template uses 2035 |
| `[passwords] env` | The name of an environment variable that holds the passwords of key stores |
| `[passwords] file` | The path of a file that holds the passwords of key stores. A relative path starts in the engagement folder. Put one password on each line |

Use only one of the keys `env` and `file` in the table `[passwords]`. An empty `[passwords]` table is an error. The tool never reads a password from the command line. The tool wipes the password text that it reads. A password in an environment variable stays in the process environment, and libraries get copies.

If you select more than one profile, each finding shows the earliest date of all the profiles.

### scope.toml

The file `scope.toml` is the only source of network targets. The template has no targets, so `scan net` does nothing until you add one.

| Key | Meaning |
| --- | --- |
| `require_ip_in_cidr` | If the value is `true`, each address of a host name must be in an allowed range. The default is `true` when `allowed_cidrs` or a CIDR target exists. A scope with host names and no range is an error, unless this value is `false` |
| `allowed_cidrs` | The address ranges that host names can resolve to. These ranges are not targets. The CIDR ranges of the targets are also allowed. A scope with host names needs this key or a CIDR target |
| `allowed_hours` | The local-time window in which the tool can start, for example `"09:00-17:00"`. The window can cross midnight, for example `"22:00-06:00"` |
| `override_limits` | If the value is `true`, you can set limits past their defaults. The default is `false` |
| `legacy_tls_check` | If the value is `true`, the tool makes one more TLS connection for each port. That connection checks for old protocol versions. The check needs `tls_handshakes` of 3. A lower limit stops the scan with exit code 1. The default is `false` |
| `[limits]` | The network limits. Refer to the table below |
| `[[target]]` | A target. Refer to the keys below |
| `[[exclude]]` | An exclusion. It has a `host` key or a `cidr` key |

The keys of `[[target]]`:

| Key | Meaning |
| --- | --- |
| `host` | A host name or an IP address. Use `host` or `cidr`, not both. Write each IP address in its canonical form, for example `10.0.0.1`. The tool rejects forms such as `10.1`, `167772161`, `010.0.0.1`, and `0x0a.0.0.1`. A name with one label must end with a dot, for example `printer.` |
| `cidr` | An address range. A range can have 256 addresses at most. With `override_limits`, the maximum is 65536 |
| `ports` | The list of ports, from 1 to 65535. The list must have at least one port |
| `protocol` | `tls` or `ssh` |

The keys of `[limits]`. All keys are optional. The values here are the defaults.

| Key | Default | Rule |
| --- | --- | --- |
| `concurrency` | 4 | The most connections at the same time in total |
| `per_host` | 1 | The most connections at the same time to one IP address |
| `min_interval_ms` | 1000 | The least time between two connections to one host |
| `tls_handshakes` | 3 | The most TLS handshakes for each IP address and port |
| `connect_timeout_ms` | 5000 | The connect timeout |
| `read_timeout_ms` | 10000 | The read timeout |
| `retries` | 0 | The number of retries |

You can make a limit gentler without a flag. You can make a limit lower than its default. For `min_interval_ms`, gentler means higher, so you can set a higher value.

A setting that is less gentle than the default needs `override_limits = true`. Without it, the tool refuses to start and exits with code 2. A limit of 0 is not valid, except for `retries`. With `override_limits = true`, `min_interval_ms = 0` is valid.

### assets.toml

An asset gives the context that the tool cannot find itself. Add one `[[asset]]` block for each asset.

| Key | Meaning |
| --- | --- |
| `name` | The name of the asset. The key must exist |
| `business_unit` | The business unit that owns the asset |
| `match` | The rules that match a finding to this asset. Use `hosts`, `cidrs`, and `paths`. Each list is optional. `paths` are glob patterns |
| `classification` | The classification of the data, in your own scheme. `scoring.toml` gives a value to each name |
| `data_lifespan_years` | The number of years that the data must stay secret |
| `exposure` | `internet`, `partner`, `internal`, or `isolated` |
| `owner` | The team or person that owns the asset |
| `vendor` | If the value is `true`, a vendor supplies the asset. Each fix then becomes a question for the vendor |
| `priority_tier` | `high` or `standard`. The tier selects the deadline milestones that apply |
| `hardware_constrained` | If the value is `true`, the fix needs a hardware change |

If a finding matches more than one asset, the finding takes the first of these assets in `assets.toml`. Put the most specific asset first.

If a finding matches no asset, each context field has the value `unassessed`. Refer to the section "Assessment: how the tool uses your context".

### overrides.toml

An override replaces the band and the score of one finding. Refer to the section "Overrides". Add one `[[override]]` block for each finding.

| Key | Meaning |
| --- | --- |
| `fingerprint` | The fingerprint of the finding. The technical report shows it |
| `priority` | The new band: `critical`, `high`, `medium`, or `low` |
| `reason` | The reason for the change |
| `by` | The name of the person who made the change |
| `date` | The date of the change, in the format YEAR-MONTH-DAY |

All five keys must exist. Two overrides with the same fingerprint are an error.

### scoring.toml

The file `scoring.toml` sets the formula. If you remove a key, the tool uses its default value. Refer to the section "How the tool calculates the score".

| Table | Keys | Defaults |
| --- | --- | --- |
| `[weights]` | `threat`, `exposure`, `sensitivity`, `mosca`, `deadline`, `scale` | 0.25, 0.20, 0.20, 0.15, 0.10, 0.10 |
| `[classification]` | One key for each classification name. Each value is from 0 to 1 | `public` 0.1, `internal` 0.4, `confidential` 0.7, `secret` 1.0, `restricted` 1.0 |
| `[bands]` | `critical`, `high`, `medium`. The lowest score of each band | 80, 60, 40 |
| `[migration_years]` | `S`, `M`, `L`, `XL`. The time in years for a fix of each size | 0.25, 0.5, 1, 2 |

The tool checks the values of `scoring.toml` when it loads the engagement. Each command that loads the engagement can stop with an error. The rules are:

- Each weight is a finite number of 0 or more. The sum of the weights is more than 0.
- Each classification value is from 0 to 1.
- Each band is from 0 to 100. The value of `critical` is more than `high`. The value of `high` is more than `medium`.
- Each migration time is more than 0.

If you add a classification to `[classification]`, the tool uses only your list. Keep all the names that your assets use. A name that is not in the list has the cautious value 1.0.

## Commands and flags

The command is `pqaudit [OPTIONS] <COMMAND>`. The descriptions below are the same as the CLI help. Run `pqaudit <command> --help` to see them on your computer.

### Global flags

Each command accepts these flags.

- `--engagement <DIR>`: Use this directory as the engagement directory. The default is `.`.
- `--quiet`: Do not show the summary lines on stdout. Errors and warnings still show on stderr.
- `--verbose`: Also show diagnostic events in the log on stderr, for example the origin of the rules pack.
- `--log-format <LOG_FORMAT>`: Set the format of the log on stderr. The log has the warnings and the diagnostic events. The default is `text`.
  - `text`: Plain text for people.
  - `json`: One JSON object for each line.
- `--no-color`: Do not use colors in the log.
- `--allow-unsigned-rules`: Accept a rules pack that has no correct signature. The results record this choice.

The tool writes three types of output.

Summary lines go to stdout. Examples are the number of findings and the path of the results file. The flag `--quiet` stops them. The output of `init`, `explain`, `rules`, `profiles`, and `scan net --dry-run` is not a summary. The flag `--quiet` does not stop it.

Errors go to stderr. No flag stops them.

The log goes to stderr. It has the warnings, for example a rules pack that has no valid signature. With `--verbose`, the log also has diagnostic events. These events show the origin of the active rules pack, the size of the scan plan, and the number of skipped files. With `--log-format json`, each log line is one JSON object.

### pqaudit init

Make the engagement directory and its template files.

- `<NAME>`: The name of the new engagement directory.
- `--dir <PARENT>`: Make the new directory in this parent directory. The default is `.`.

### pqaudit scan files

Scan files on disk. This command does not use the network.

- `<PATHS>...`: The files and directories to scan.
- `--max-file-size <BYTES>`: Skip each file that is larger than this number of bytes. The default is 10485760.
- `--follow-symlinks`: Follow symbolic links.
- `--output <FILE>`: Write the results to this file. The default is a new file in the results directory.

### pqaudit scan net

Scan network endpoints that the scope file lists.

- `--dry-run`: Show the planned targets and the refusals. Then stop. The tool makes no connection.
- `--output <FILE>`: Write the results to this file. The default is a new file in the results directory.

### pqaudit merge

Combine results files into one results file.

- `<INPUTS>...`: The results files to combine.
- `--output <FILE>`: Write the merged results to this file. The default is `results/merged.pqr`, or `results/merged.redacted.pqr` with `--redact`, in the engagement directory.
- `--redact`: Replace host names, addresses, paths, names, banners, and key comments with hashes.
- `--redact-key-file <PATH>`: Use this key file for redaction. The default is `redact.key` in the engagement directory.

### pqaudit report

Make a report from a results file.

- `--audience <AUDIENCE>`: The reader of the report. The default is `technical`.
  - `technical`: The technical team of the client.
  - `board`: The board of the client. This comes in a later release.
- `--format <FORMAT>`: The format of the report. The default is `html`.
  - `html`: One HTML file.
  - `md`: Markdown text.
  - `json`: The assessment as JSON.
  - `pdf`: A PDF file. This comes in a later release.
- `--results <FILE>`: Read this results file. The default is `results/merged.pqr` in the engagement directory.
- `--output <FILE>`: Write the report to this file. The default is `reports/technical.<ext>` in the engagement directory.

The commands `report`, `cbom`, and `explain` check the results file. The results must belong to the engagement directory. The tool stops with an error if the engagement name in the results file is different.

Redacted results have a redacted engagement name. To check it, the tool needs the file `redact.key` in the engagement directory. The key must be the key that made the redacted results. If the file does not exist, the tool gives a warning and does not check the name.

### pqaudit cbom

Make a cryptography bill of materials (CBOM).

- `--results <FILE>`: Read this results file. The default is `results/merged.pqr` in the engagement directory.
- `-o`, `--output <FILE>`: Write the CBOM to this file. The default is `reports/cbom.cdx.json` in the engagement directory.

The CBOM has the CycloneDX 1.6 format.

### pqaudit explain

Explain a finding: its score, complexity, tests, and fix.

- `<FINDING_ID>`: The ID of the finding, for example `F-1a2b3c4d`.
- `--results <FILE>`: Read this results file. The default is `results/merged.pqr` in the engagement directory.

### pqaudit rules

Show, check, or update the rules pack.

- `rules list`: Show the active rules pack and the installed packs.
- `rules verify <ARCHIVE>`: Check the signature of a rules pack archive, for example `rules-1.0.0.tar.zst`.
- `rules update --from <ARCHIVE>`: Check a rules pack archive and install it.
- `--sig <FILE>`: The signature file for `rules verify` and `rules update`. The default is the archive name and `.sig.json`.
- `--from <ARCHIVE>`: The pack archive to install.

### pqaudit profiles

Show the deadline profiles.

- `profiles list`: List the deadline profiles.
- `profiles show <ID>`: Show the milestones of one deadline profile. The ID is for example `uk`.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The command succeeded |
| 1 | An error. The command failed |
| 2 | The tool refused to continue because of the scope or a safety rule |
| 3 | Partial results. Some files or targets gave errors. The results file lists them |

Some cases to know:

- A `scan files` run that reads no file exits with code 1.
- A `scan files` run that skips symbolic links exits with code 3. Use `--follow-symlinks` to scan them.
- A `scan files` run with an unreadable path or a bad file exits with code 3. The other files are still scanned.
- A `scan net` run with a refused target exits with code 2. The tool makes no connection.
- A `scan net` run outside `allowed_hours` exits with code 2.
- A `scan net` run with no target exits with code 1.
- If you stop `scan net` with Ctrl-C, the tool exits with code 3. Refer to the section "The network scan".
- The commands `report --audience board` and `report --format pdf` exit with code 1. These features come in a later release.

## The file scan

The command `scan files` reads files and folders that you name. It does not use the network. It never changes a file that it scans.

The scan reads these formats:

- PEM and DER certificates,
- PKCS#12 key stores,
- JKS and JCEKS key stores,
- OpenSSH keys, `authorized_keys` files, and `known_hosts` files,
- PEM and DER private keys and public keys,
- exported GPG keys (not `.kbx` files).

For a key, the tool records the type, the size or curve, and the public parts. It never writes private key bytes to the results, the logs, the reports, or the error messages. The tool reads key files into buffers that it wipes after use. The PKCS#12 library decrypts key bags into memory that the tool cannot wipe, and the tool drops them early. A call to a library can leave a short copy on the stack.

If a key store has encryption and the tool has no correct password, it records "encrypted - not inspected". To give passwords, use the table `[passwords]` in `engagement.toml`.

A PKCS#12 file sets its own key derivation work. A hostile file can ask for so much work that the scan stops for a long time. Thus the tool checks the work before it opens the file:

- It never runs scrypt.
- It accepts at most 100000 iterations for one key derivation.
- It accepts at most 16 key derivations in one file. The MAC, each encrypted safe, and each encrypted bag count.
- It accepts at most 1600000 iterations for one file, for all passwords together.
- It accepts at most 5000000 iterations for all PKCS#12 files of one scan.

If a file is past a limit, the tool records "The key store asks for too much work" and does not open the file. The tool counts the file as not inspected.

A bad file is a scan error with a reason. The scan continues and the exit code is 3.

Limits of the file scan:

- The scan stops at the first private-key entry of a JCEKS key store. It loses the later entries.
- The tool does not read `.kbx` GPG key stores.
- The tool does not read an RSA public exponent that is longer than 4 bytes.
- The tool skips a file that is larger than `--max-file-size`.

## The network scan

The command `scan net` connects only to the targets in `scope.toml`. Use `--dry-run` first.

Before the first connection, the tool does these steps:

1. It loads `scope.toml` and checks the limits.
2. It resolves each host name one time. It uses the addresses from this lookup for the full scan.
3. It applies the exclusions.
4. It checks each resolved address against `allowed_cidrs`, if `require_ip_in_cidr` is `true`.
5. It checks each resolved address for a special type: loopback, link-local, multicast, or unspecified.
6. It checks `allowed_hours`.

If `require_ip_in_cidr` is `true` and any address is outside `allowed_cidrs`, the tool refuses the full scan and exits with code 2. It does not scan the other targets. The same is true for a host name that does not resolve and for a CIDR range that is too large. The same is true for a limit past its default. The option `--dry-run` shows each refusal with its reason.

The default of `require_ip_in_cidr` is `true` only if `allowed_cidrs` or a CIDR target exists. A scope with host names and no range stops with exit code 1. Set `allowed_cidrs` to pin names to known ranges. To accept all addresses, set `require_ip_in_cidr = false`.

A host name must not resolve to a loopback, link-local, multicast, or unspecified address. Examples are `127.0.0.1`, `::1`, `169.254.0.0/16`, and `fe80::/10`. If it does, the tool refuses the full scan and exits with code 2. This rule also applies when `require_ip_in_cidr` is `false`. An entry in `allowed_cidrs` does not change the rule. To scan such an address, add it, or a CIDR range that holds it, as a target.

The tool resolves a name with one label, such as `printer.`, with the final dot. Thus the resolver adds no search domain. The TLS server name has no final dot.

An exclusion does not match the NAT64 form or the 6to4 form of an IPv4 address. This is a known limit.

The tool does not follow redirects. It does not follow SRV or MX records. It does not use SNI to move to other hosts.

### TLS targets

For each IP address and port, the tool does at most `tls_handshakes` TLS handshakes. This limit counts all the host names that point to that address and port. The order is:

1. A hybrid handshake. It offers only the hybrid post-quantum key exchange.
2. A classical handshake.
3. An old-protocol check, only if `legacy_tls_check` is `true`.

If the budget is 1, the tool does only the hybrid handshake. If other host names use part of the budget, the probe of a later name can be incomplete. The tool records this.

### SSH targets

The tool makes one connection for each IP address and SSH port. This limit counts all the host names that point to that address and port. A second name gets a scan error. The tool reads the key exchange list of the server and the host key algorithms. It does not log in.

### The audit log

The tool adds lines to `audit.log` in the engagement folder. It never overwrites the file. Each connection has two lines: a "started" line before the connection, and a final line with the result.

A line is a JSON object. It has these fields: the time, the run ID, the source address, the destination host and address, the port, and the protocol. It also has the probe, the outcome, the bytes sent and received, and the duration. The results file holds the SHA-256 hash of the log and of `scope.toml`.

If the tool cannot write a line, it makes no more connections and exits with code 1. Do not use the results of that run.

### Stop a scan

If you press Ctrl-C, the tool stops the open connections. It keeps the results of the targets that it finished. It lists the targets that it did not finish as errors in the results file. It writes the final audit lines and exits with code 3.

## Merge and redaction

The command `merge` combines results files of one engagement into one file. It removes duplicate findings. The results files must come from the same engagement name. The name of the engagement is the name of its folder.

If the input files used different rules packs, the tool gives a warning. The merged file names the pack with the highest version.

### Redaction

With `--redact`, the tool replaces these items with hashes: host names, addresses, paths, names, banners, and key comments. Use a redacted file when the results must leave the client network.

The hash is a keyed hash. The key is in the file `<engagement>/redact.key`. The tool makes the key the first time that you use `--redact` with the default key file. With `--redact-key-file`, the file must exist already. It must hold 64 hex digits.

Rules for redaction:

- Keep `redact.key` private. Never send it with a redacted file. A person with the key can test guesses against the hashes.
- IP addresses map into the ranges 198.18.0.0/15 (IPv4) and 2001:db8::/32 (IPv6).
- The tool redacts the name of the engagement.
- Each fingerprint becomes a keyed hash. The kind at the start stays, for example `cert:`.
- Certificate hashes and key hashes also become keyed hashes.
- Each finding ID comes from the keyed fingerprint. Thus a redacted file has other IDs than the plain file.
- Without the key, a person cannot compare a fingerprint with a known certificate, key, or address.
- The same key gives the same values. Thus `merge` joins redacted files that use one key.
- Do not treat a redacted file as anonymous. The algorithms, dates, and counts stay.
- A mix of plain inputs and redacted inputs needs `--redact`. Without it, the tool stops with an error.
- The default output is `results/merged.redacted.pqr`.

A report from a redacted file cannot match assets to findings. All context fields show as `Unassessed`.

Overrides use plain fingerprints. For a redacted file, `report`, `cbom`, and `explain` read `redact.key` in the engagement folder. They calculate the keyed form of each override fingerprint and match that form. An override that already has the keyed form also matches. The report then shows only keyed fingerprints.

Without `redact.key`, no plain override matches. The report tells why. It gives only the number of orphaned overrides. It does not show their fingerprints or their reasons, because a plain fingerprint can confirm a guess. In the JSON report, `orphaned_overrides` is empty and `orphaned_override_count` has the number.

## Assessment: how the tool uses your context

The commands `report`, `cbom`, and `explain` assess the findings. They read the results file, the engagement files, and the rules pack.

- The rules pack must be the pack that made the results. If not, the tool stops with an error.
- In that case, scan again, or make the correct pack active. Refer to the section "Rules packs".
- Two overrides with the same fingerprint are an error.
- The tool checks `scoring.toml` when it loads the engagement.
- A finding that matches more than one asset takes the first of these assets in `assets.toml`.
- A context field that you did not set is `unassessed`. The tool uses a cautious value and shows a flag.
- The cautious values are 1.0 for exposure and sensitivity, and 25 years for the data lifespan.
- For deadlines, the cautious tier is `high`.
- The report shows how many findings use unassessed context.

## How to read the technical report

The command `report` makes the technical report. The default format is HTML, in `reports/technical.html`. The HTML file has all its content in one file. The formats `md` and `json` are also available.

The report has these sections:

1. **Header.** The client, the assessor, the date, the engagement, the tool version, and the rules pack.
2. **Method.** A short description of how the tool works.
3. **Scope and coverage.** The runs, the hashes of the scope and the audit log, the counts, and each scan error.
4. **Assumptions.** The CRQC year, the profiles, the sector, and the planning milestones of the profiles.
5. **Summary.** The number of findings in each effective band.
6. **Findings.** The findings, from the highest priority to the lowest. Each one has the sections that the next paragraph lists.
7. **Fix now (not quantum).** The findings with an algorithm that is weak today. This section lists them for all scores.
8. **Ready for post-quantum cryptography.** The items that already use a post-quantum algorithm.
9. **Questions for vendors.** One question for each finding that a vendor must fix.
10. **Overrides log** and **Orphaned overrides.** The overrides in use, and the overrides that match no finding.
11. **Appendix: risk register.** A table that you can put in a risk register.

Each finding shows its evidence, its context, its deadline and source, and its score table. It also shows its complexity with the reasons, the necessary tests, and the fix.

Each finding has a stable ID (for example `F-1a2b3c4d`) and a fingerprint. The ID is for `explain`. The fingerprint is for `overrides.toml`. The command `explain <finding-id>` shows the same score table in plain text, with the rule, the references (CWE and ATT&CK), and the fix text.

The suggested band comes from the score. The effective band is the band after an override. The report shows both.

## How the tool calculates the score

The score is the weighted sum of six factors. Each factor has a value from 0 to 1. The contribution of a factor is 100 times its weight, divided by the sum of the weights, times its value. The score is the sum of the contributions. With the default weights, the sum of the weights is 1, so the score is 100 times the weighted sum.

| Factor | Value | Default weight |
| --- | --- | --- |
| Threat type | `hndl` 1.0, `forgery-long-lived` 0.8, `classical-weak-now` 1.0, `forgery-short-lived` 0.3 | 0.25 |
| Exposure | `internet` 1.0, `partner` 0.7, `internal` 0.4, `isolated` 0.2 | 0.20 |
| Sensitivity | The value of the classification in `scoring.toml` | 0.20 |
| Mosca margin | 1.0 if the margin is 0 or more. Otherwise 1 plus the margin divided by 10, with a minimum of 0 | 0.15 |
| Deadline proximity | 1 minus the years to the deadline divided by 10, from 0 to 1. A deadline in the past gives 1. No deadline gives 0 | 0.10 |
| Scale | The base-10 logarithm of the number of occurrences plus 1, divided by 2, with a maximum of 1 | 0.10 |

The Mosca margin is: data lifespan, plus the migration time of the fix, minus the years until the CRQC year. The years until the CRQC year is the CRQC year minus the current year. The migration time comes from the complexity size and `[migration_years]`. For a `forgery-long-lived` finding on a certificate, the tool uses the time to the end of the certificate if this is longer than the lifespan.

The bands: a score of 80 or more is critical. A score of 60 or more is high. A score of 40 or more is medium. A lower score is low. You can change these values in `[bands]`.

### Worked example

A `hndl` finding has one occurrence. Its asset has the classification `confidential`, a data lifespan of 5 years, and the exposure `internal`. The deadline is 2030-12-31.

The complexity is M (0.5 years). The CRQC year is 2035. The date is 2026-10-20. The weights are the defaults.

| Factor | Value | Weight | Contribution |
| --- | --- | --- | --- |
| threat | 1.00 | 0.25 | 25.00 |
| exposure | 0.40 | 0.20 | 8.00 |
| sensitivity | 0.70 | 0.20 | 14.00 |
| mosca | 0.65 | 0.15 | 9.75 |
| deadline | 0.58 | 0.10 | 5.80 |
| scale | 0.15 | 0.10 | 1.51 |

- Mosca: the margin is 5 plus 0.5 minus 9, or minus 3.5. The value is 0.65.
- Deadline: 1533 days, or 4.2 years, remain. The value is 0.58.
- Scale: the base-10 logarithm of 2, divided by 2, is 0.15.
- The total is 64.06. This is in the high band.

## How the tool selects deadlines

The rules pack holds the deadline profiles. Each milestone has a date, a description, a source with a URL, and an `as_of` date. A milestone is of the kind `planning` or `migration`.

The tool selects the deadline of a finding in these steps:

1. It takes the `migration` milestones of all the profiles that the engagement selects.
2. It keeps the milestones whose `applies_to` conditions match the finding.
3. It selects the earliest date. If two dates are the same, the first profile in `engagement.toml` wins.
4. The finding shows the date, the profile, and the source.

The conditions of `applies_to`:

- `tier`: the tier `high` applies to assets with `priority_tier = "high"` and to assets with no tier.
- `tier`: the value `all` applies to every asset.
- A milestone with no `tier` condition applies to every tier.
- `threat_types`: the milestone applies only to findings of these threat types.
- `sector`: the milestone applies only if the sector of the engagement is the same.

The tool never attaches a planning milestone to a finding. The reports show planning milestones for the whole engagement, in the section "Assumptions". A finding with no matching milestone shows "Deadline: none applies" and has the value 0 for the deadline factor.

The profiles in Stage 1 are `us`, `uk`, and `au`. Run `pqaudit profiles show <id>` to see the milestones, the sources, and the `as_of` dates. Compare the dates with the primary documents before you use them in a report to a client.

## Overrides

An override changes the band of one finding. You make it in `overrides.toml`. The key is the fingerprint of the finding.

The report shows the original band, the new band, the reason, the person, and the date. The override replaces the band and the score in the priority list. The override does not change the score table.

If an override matches no finding, the report lists it in "Orphaned overrides". Two overrides for one fingerprint are an error.

## Rules packs

A rules pack is a folder of YAML files. It holds the rules for each file format and protocol, the algorithm map, and the text for threats and fixes. It also holds the CWE and ATT&CK references, the complexity rules, and the deadline profiles.

The binary has a default pack. Each result and each report records the version and hash of the pack.

### Signatures

The maintainers sign each pack with a hybrid key pair: Ed25519 and ML-DSA-65. Both signatures must be correct. The build puts the trusted public keys into the binary. The check does not use the network and does not become out of date. The pack key pair is not the same as the release keys.

A pack can carry a rotation statement: "key B replaces key A". Key A signs the statement. The tool then trusts key B for that pack and for later packs. The results record the chain of keys.

### Commands

- `pqaudit rules list` shows the active pack and the installed packs. The active pack is the valid pack with the highest version.
- `pqaudit rules verify <archive>` checks the signature of an archive. The signature file is `<archive>.sig.json` unless you use `--sig`.
- `pqaudit rules update --from <archive>` checks an archive and installs it in your data folder.
- The data folder is `PQAUDIT_DATA_DIR`, or the data folder of your user account.

The tool does not get packs from the network. Download a pack and its signature file yourself. Refer to [verifying.md](verifying.md) for the checks of a pack.

### Unsigned packs

By default, the tool refuses an unsigned pack and a changed pack. It does not read the files of such a pack. It reports only that the signature check failed.

The flag `--allow-unsigned-rules` accepts a pack without a correct signature. Use it only for a pack that you wrote yourself or that you trust by other means. The tool prints a warning. Each result and each report records that the pack had no valid signature.

With `rules verify`, the flag does not change the result. The command exits with code 1 for a pack without a correct signature, and it prints a warning.

Use the same pack for the scan and for the report. If you install a newer pack between the scan and the report, the report stops with an error.

## Known limits

- Stage 1 has no code scan, no board report, and no PDF output.
- Stage 1 has no `export` command. Use `report --format json` for the data.
- The file scan has the limits in the section "The file scan". It does not read `.kbx` files.
- The network scan has the limits in the section "The network scan".
- An exclusion does not match the NAT64 form or the 6to4 form of an IPv4 address.
- The hybrid handshake offers only two fixed groups: X25519MLKEM768 and SecP256r1MLKEM768.
- A server that supports only other post-quantum groups shows as "no post-quantum key exchange".
- The tool finds only what its rules pack knows. A finding is evidence, not proof.
- Context that you do not give is `unassessed`. The score then uses cautious values and can be too high.
