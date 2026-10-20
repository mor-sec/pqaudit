# pqaudit — Post-Quantum Readiness Auditor: Design

Date: 2026-10-20
Status: Approved
Name: `pqaudit` is a working name. Before the first release, make sure that the name is available on crates.io and GitHub.

This document uses ASD-STE100 Simplified Technical English (STE). Section 19 gives the rules.

## 1. Intent

An organisation must know where it uses quantum-vulnerable cryptography. It must know this before it can plan a migration. Today, people do this discovery work by hand, with many different tools. The results are difficult to give to a board or a risk committee.

`pqaudit` is an open-source command-line tool. It is one binary file. Two groups of users operate it:

- a **security team in a company**,
- a **consultant who does a readiness assessment for a client**.

The tool does three tasks:

1. It finds cryptography in source code, dependencies, and configuration files.
2. It examines certificates, key stores, and SSH and GPG keys on disk.
3. It examines live TLS and SSH endpoints.

The tool makes these outputs:

- a **CycloneDX CBOM** of all the cryptography that it finds,
- a **readiness report in two versions**: a **board report** (summary) and a **technical report** (findings with a suggested priority).

The report is **input to the customer's own risk assessment**. It does not replace that assessment. The report gives evidence and risk factors. It gives a suggested priority for each finding, from a formula that the customer can see and override. It also gives an estimate of the complexity of each fix and the tests that the fix needs.

Users take the tool into client environments. Thus the tool **must be safe to operate and easy to trust**:

- It operates only on targets in the agreed scope.
- It sends little traffic to the network.
- It records all of its connections.
- Each release has signatures, build provenance, an SBOM, and a CBOM of the tool itself.

## 2. Goals

- Supply one static binary for Linux, macOS, and Windows. The binary needs no runtime and no installer. It operates without a network connection.
- Supply three scan modes: code, files, and network. Each scan writes a results file. A user can move the file to a different computer and merge it with other results.
- Give each finding a suggested priority from a documented formula. The user can change the formula settings. If a customer overrides a priority, the tool records the reason.
- Give each finding a complexity size (S, M, L, or XL) and a list of the necessary tests. Show the reasons.
- Supply a board report, a technical report, a CBOM, and CSV or JSON export for GRC tools.
- Supply deadline profiles for each region, plus sector overlays. The user selects the profiles for each engagement.
- Make releases that a customer can verify: Sigstore signing without long-term keys, SLSA build provenance, an SBOM, a CBOM of the tool itself, a hybrid post-quantum signature, and the native code signature for each operating system.

## 3. Non-goals for v1

- **Host discovery and port discovery.** The tool does not sweep networks. It examines only the targets that the scope file lists.
- **Vulnerability probes or exploits** of any type. The tool does not do downgrade attacks. It does not do fuzzing. It does not try each cipher suite in turn.
- Scans of C, C++, and Rust source code. Analysis of compiled binaries or firmware images.
- Full data-flow analysis or taint analysis. The code scan finds patterns of API calls only.
- Automatic fixes or changes to code.
- Records of quantum attack proof-of-concept (PoC) code. No practical attack on RSA-2048 or P-256 exists. Thus a "PoC available" flag gives incorrect information. (Section 9.4 describes known CVEs for classical cryptography libraries. That is a different feature, after v1.)
- A final risk rating. The customer makes the risk decision.
- A server, an agent, or a graphical interface. The tool is a command-line tool only. Reports are files.

## 4. Anti-goals

These results are failures, even if the tool operates correctly in other ways:

- **The tool causes an alarm in the client IDS or IPS**, because of the quantity of traffic or unusual traffic.
- **The tool causes a problem on a production system**, for example too many connections, exhausted resources, or bad packets.
- **The tool connects to a target that is not in the agreed scope.** This includes a DNS name that resolves to an unexpected address, and a redirect.
- **The tool copies private key material** into results, logs, or reports.
- **The board report shows false precision**, for example exact risk numbers that have no real basis, or a quantum timeline that the report shows as a fact.
- **The tool makes an assumption about customer context and does not tell the user.** If classification, data lifespan, or exposure is missing, the report must show "unassessed". The tool must not use an invented value.
- **A customer cannot verify the tool** before the customer brings it into the customer environment.

## 5. Users and workflow

This is a typical engagement:

```
pqaudit init acme-2026q4            # make an engagement folder with templates
  → edit scope.toml, assets.toml, engagement.toml
pqaudit scan net --dry-run          # show each target that the scan will connect to
pqaudit scan net                    # person A, on a computer with network access
pqaudit scan code ./repos/...       # person B, offline, on a build server
pqaudit scan files /etc /opt/app    # person C, on target hosts
pqaudit merge results/*.pqr         # merge the results from all scans
pqaudit report --audience board     --format pdf
pqaudit report --audience technical --format html
pqaudit cbom -o acme.cdx.json
pqaudit export --format csv         # for the client GRC tool or risk register
```

Scans and reports are separate steps. Thus different persons and different computers can do each step. Also, the client can examine the raw results before the results go out of the client network.

## 6. Commands

| Command | Function | Network? |
|---|---|---|
| `init <name>` | Make an engagement folder. Put templates with comments in it for `engagement.toml`, `scope.toml`, `assets.toml`, `overrides.toml`, and `scoring.toml`. | No |
| `scan code <path>...` | Scan source code, dependency manifests, lockfiles, and configuration files. | No |
| `scan files <path>...` | Scan certificates, key stores, and SSH and GPG keys. | No |
| `scan net` | Do TLS and SSH handshakes with the targets in the scope file. | Yes, scope only |
| `merge <results>...` | Merge results files into one assessment. Remove duplicate findings. | No |
| `report --audience board\|technical --format html\|pdf\|md\|json` | Make a report. | No |
| `cbom` | Make a CycloneDX CBOM (JSON; XML is optional). | No |
| `export --format csv\|json` | Make a flat table of findings for GRC tools. | No |
| `explain <finding-id>` | Show the evidence, the score calculation, the deadline source, and the CWE and ATT&CK references for one finding. | No |
| `rules list\|verify\|update --from <file>` | Show, verify, or install a signed rules pack. | No (`update` uses a local file) |
| `profiles list\|show <id>` | Show the deadline profiles and their sources. | No |

Global flags: `--engagement <dir>`, `--quiet/--verbose`, `--log-format text|json`, `--no-color`.

Exit codes:

- `0`: success.
- `1`: error.
- `2`: the tool refused to continue because of scope or safety.
- `3`: partial results. Some targets or files failed. The results file gives the details.

## 7. Engagement files

All engagement files use TOML. The `init` command makes them, with comments.

**`engagement.toml`** contains the client name, the assessor, dates, the deadline profiles, and the CRQC assumption. (A CRQC is a cryptographically relevant quantum computer.)

```toml
client   = "Acme Corp"
assessor = "Jane Doe, Example Consulting"

[deadlines]
profiles = ["au", "uk"]      # you can select more than one; findings show the earliest date
sector   = "government"      # optional overlay

[assumptions]
crqc_year = 2035             # the customer sets this assumption for the Mosca test; each report shows it
```

**`scope.toml`** is the only source of network targets. Refer to section 8.

**`assets.toml`** contains customer context. The tool cannot find this context itself. An asset matches findings by host, CIDR, path glob, or repository:

```toml
[[asset]]
name                = "Payments API"
business_unit       = "Retail Banking"     # the board report groups results by this field
match               = { hosts = ["pay.acme.example"], paths = ["repos/payments/**"] }
classification      = "confidential"       # the customer's own scheme; scoring.toml maps it to a value
data_lifespan_years = 10
exposure            = "internet"           # internet | partner | internal | isolated
owner               = "Payments Platform team"
vendor              = false                # true → each fix becomes a question for the vendor
priority_tier       = "high"               # high | standard — selects the deadline milestones that apply (section 13)
hardware_constrained = false               # true → the fix needs a hardware change
```

If a finding matches no asset, each context field is `unassessed`. For deadlines, the tool uses `high` when `priority_tier` is unassessed. This is the cautious choice. The report shows a flag for it.

**`overrides.toml`** contains the customer overrides of suggested priorities. Each override has a stable finding fingerprint, `priority`, `reason`, `by`, and `date`. The technical report shows each override and its reason.

**`scoring.toml`** contains the formula weights and the classification map. Refer to section 10.

## 8. Safety model

1. **The scope is explicit. The tool refuses all other targets.** `scan net` connects only to the `host:port` pairs in `scope.toml`. These can be host names, IP addresses, or CIDRs with explicit ports. The tool does not warn about other targets — it refuses them. The tool resolves each host name one time, at the start. If `require_ip_in_cidr = true`, each resolved IP address must also be in an allowed CIDR. This setting is true by default when the scope lists a CIDR. The tool does not follow redirects. It does not follow SRV or MX records. It does not use SNI to move to other hosts.
2. **Exclusions have priority.** An `exclude` entry in the scope file overrides an include entry.
3. **The default settings are gentle.** You can decrease each setting. You cannot increase a setting above its default unless the scope file has an explicit flag:
   - a maximum of 4 connections at the same time in total, and 1 for each host,
   - a minimum of 1 second between two connections to the same host,
   - a maximum of 3 TLS handshakes for each port (refer to section 9.3), and 1 connection for each SSH port,
   - a connect timeout of 5 seconds and a read timeout of 10 seconds, with no retries by default,
   - an optional time window (`allowed_hours`). The tool does not start outside this window.
4. **`--dry-run`** shows each resolved target, port, protocol, and number of connections. Then the tool stops.
5. **Audit log.** The tool adds a line to `audit.log` for each connection attempt. Each line is JSON and contains the time, the source interface or IP address, the destination, the port, the protocol, the result, and the number of bytes sent and received. The results file refers to the log. A consultant can give the log to the client as proof of each connection.
6. **Offline modes never open sockets.** `scan code` and `scan files` must not do DNS, HTTP, or other network input/output. A test makes sure of this.
7. **No private key material goes out of the file.** The file scan reads the key type, the key size or curve, and the public parts only. The tool never writes private key bytes to results, logs, or reports. If a key store is encrypted and the user gives no password, the tool records "encrypted — not inspected".
8. **Read only.** No scanner writes outside the engagement folder.

## 9. Scanners

All scanners write findings to a common results file (`.pqr`). Refer to section 11.

### 9.1 `scan code` — source code, dependencies, and configuration

**Languages for v1:** Java, Python, Go, JavaScript/TypeScript, and C#.

**Source code:** The tool uses tree-sitter to parse the code. It finds calls to known cryptography APIs. The rules pack defines these APIs. Examples:

| Language | Example patterns |
|---|---|
| Java | `KeyPairGenerator.getInstance("RSA")`, `KeyAgreement.getInstance("ECDH")`, `Signature.getInstance("SHA256withECDSA")`, BouncyCastle equivalents |
| Python | `cryptography` `rsa.generate_private_key`, `ec.generate_private_key`, `x25519`, PyCryptodome `RSA.generate` |
| Go | `crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/tls` `CurvePreferences`, `golang.org/x/crypto/ssh` |
| JS/TS | Node `crypto.generateKeyPairSync('rsa'\|'ec')`, `createECDH`, WebCrypto `subtle.generateKey`, `jsonwebtoken` alg `RS256/ES256`, `node-forge` |
| C# | `RSA.Create()`, `ECDsa.Create()`, `ECDiffieHellman.Create()`, `RSACryptoServiceProvider`, BouncyCastle .NET |

Each finding records these items:

- the file and the line,
- the rule that matched,
- the algorithm,
- the key size or curve, if the code has a literal value for it,
- the **purpose**: key exchange, encryption, signature, or hash,
- whether the algorithm is **hard-coded** or comes from a **parameter**.

Sometimes the algorithm comes from a variable or a configuration value that the rule cannot resolve. Then the finding records `algorithm: unresolved`. The tool does not guess.

The tool also finds:

- hard-coded keys and secrets that match a key format (CWE-321, CWE-798),
- weak hashes (MD5, SHA-1) that a signature uses.

**Dependencies:** The tool parses these files: `pom.xml`, Gradle (`build.gradle[.kts]`, `gradle.lockfile`), `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `go.mod`/`go.sum`, `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `*.csproj`, `packages.lock.json`, and `Directory.Packages.props`. It finds cryptography libraries and their versions. The rules record whether a library version supports ML-KEM or ML-DSA. This shows a "quick win".

**Configuration:** The tool reads nginx and Apache TLS directives, HAProxy, `openssl.cnf`, Java `java.security`, `sshd_config` and `ssh_config`, and the .NET TLS settings in `appsettings.json`.

By default, the tool obeys `.gitignore`. Use `--no-ignore` to scan ignored files too. By default, the tool skips vendor folders and generated folders that the rules pack lists. For example, it does not scan source code in `node_modules`, but it counts the lockfile entries.

### 9.2 `scan files` — certificates and keys

Inputs:

- PEM and DER certificates and chains,
- PKCS#12 files (`.p12`, `.pfx`),
- Java key stores (JKS, JCEKS, and PKCS#12 key stores),
- OpenSSH public key files, and OpenSSH private key files (the type header only),
- `authorized_keys` and `known_hosts`,
- GPG public keyrings and exported GPG keys.

For each item, the tool records the algorithm, the key size or curve, the signature algorithm, the issuer and subject, the validity dates, the CA flag, the path length and key usage, the position in the chain, the SHA-256 fingerprint, and the file path. A classical key with a long validity period is an important signal. An example is a root CA that is valid after the earliest deadline that applies.

The user can supply passwords for key stores in an environment variable, or in a password file that `engagement.toml` refers to. The user must never put a password on the command line.

### 9.3 `scan net` — TLS and SSH endpoints

**TLS (direct TLS on the listed ports):** By default, the tool does a maximum of 3 handshakes for each port:

1. It offers only hybrid post-quantum groups (`X25519MLKEM768`, plus the other standard hybrid groups in the rules pack). This shows whether the server agrees to a post-quantum key exchange.
2. It offers only classical groups, as a normal modern client does. This shows the group that the server selects. The tool also gets the certificate chain.
3. It does a check for legacy versions (TLS 1.0 and 1.1) with a minimal ClientHello. This check is optional and is off by default.

The tool records the TLS version, the group, the cipher suite, whether the server supports a post-quantum hybrid, the certificate chain (with the same fields as section 9.2), and handshake failures. The builder selects how to make the probes. A possible method: rustls with the aws-lc-rs provider for TLS 1.3, plus a minimal ClientHello made by hand for the legacy check.

STARTTLS (SMTP, IMAP, POP3, LDAP, PostgreSQL) is **not in v1**. A scope entry can only have `protocol = "tls"` or `protocol = "ssh"`. STARTTLS comes later.

**SSH:** The tool connects and sends its version banner. It reads the `KEXINIT` message from the server. Then it disconnects before the key exchange is complete. One connection shows these items:

- the key exchange algorithms (for example `mlkem768x25519-sha256` and `sntrup761x25519-sha512`),
- the host key types,
- the ciphers,
- the MACs.

The tool can also get the host key type and size from a complete key exchange. This option is off by default, because it must complete the handshake.

### 9.4 After v1: known CVEs for classical libraries

This feature is not in v1. It needs a data source that the project can bundle, a licence check, and a person who keeps the data up to date. When this feature is available, and the user enables it, the tool adds known CVEs to each dependency finding. It also adds CISA KEV membership and the EPSS score. This data comes from the rules pack. The tool does not get data from the network during a scan. This feature is off by default. The reports show the date of the data.

## 10. Findings, scoring, and complexity

### 10.1 Finding model

**One finding is:**

- **for code, dependencies, and configuration:** one finding for each **rule and asset** pair (or rule and repository, if no asset matches). The finding lists each call site or line as an *occurrence*. The Scale factor counts the occurrences. This keeps reports easy to read for large codebases.
- **for certificates and keys:** one finding for each **certificate or key**. The key for the finding is the **SHA-256 fingerprint** of the certificate or key. If `scan files` and `scan net` both find the same certificate, `merge` makes one finding with the two sightings.
- **for endpoints:** one finding for each **host:port and issue** pair. Examples of issues are "no post-quantum key exchange" and "TLS 1.0 enabled".

**Fingerprints.** The tool uses fingerprints to apply overrides, and to compare scans in the future.

- For code, the fingerprint is a hash of the rule family ID, the asset, the file path, and the enclosing symbol (class or function). It does **not** use line numbers. Thus an override stays correct when lines move.
- Each rule has a stable family ID and a list of `aliases`. Thus, if a new pack changes the name of a rule or divides a rule, the overrides stay correct.
- v1 does not follow files that move. If an override matches no finding, the report shows it as an "orphaned override". The user can then change the override key.
- The tool calculates fingerprints **before** `--redact`. Thus redacted results have the same fingerprints.

Each finding contains:

- an `id` (short, for one assessment) and a `fingerprint` (as above),
- the source (`code`, `dependency`, `config`, `file`, or `net`), the location, and a part of the evidence,
- the algorithm, the key size or curve, and the purpose,
- the **threat type**:
  - `hndl` — key exchange or encryption. An attacker can record the data now and decrypt it later ("harvest now, decrypt later").
  - `forgery-long-lived` — CA certificates, firmware keys, code-signing keys, and certificates with a long validity period.
  - `forgery-short-lived` — other signatures.
  - `classical-weak-now` — for example RSA-1024, SHA-1 signatures, TLS 1.0 and 1.1, and 3DES. These are risks now, without a quantum computer.
- agility (`hard-coded`, `config`, or `library-default`), whether the library is ready for post-quantum cryptography, the fix owner (`in-house`, `open-source`, or `vendor`), and a hardware constraint flag,
- the asset that matches and its context (classification, lifespan, exposure, business unit, owner), or `unassessed`,
- the deadline that applies (refer to section 13), with its profile and source,
- references: CWE IDs and MITRE ATT&CK IDs (refer to section 10.5),
- the suggested priority and the full score calculation, and the override (if there is one),
- the complexity size with its reasons, and the necessary tests.

### 10.2 Suggested priority — a formula that the user can see

The default formula is a **weighted sum of factor scores**. Each factor score is between 0 and 1. The tool multiplies the sum by 100, to give a score from 0 to 100. The weights are in `scoring.toml`. Each report and the `explain` command show the value, the weight, and the contribution of each factor.

Default factors (the builder can tune the default weights; these are the starting values):

| Factor | Values (0–1) | Default weight |
|---|---|---|
| Threat type | hndl 1.0, forgery-long-lived 0.8, classical-weak-now 1.0, forgery-short-lived 0.3 | 0.25 |
| Exposure | internet 1.0, partner 0.7, internal 0.4, isolated 0.2 | 0.20 |
| Data sensitivity | from the classification map in `scoring.toml` | 0.20 |
| Mosca margin | 1.0 if `lifespan + migration_years > crqc_year − now`; a lower value if not. The complexity size gives `migration_years`. | 0.15 |
| Deadline proximity | the number of years until the deadline that applies, as a value from 0 to 1 | 0.10 |
| Scale | the number of occurrences of the same pattern in the asset, on a log scale | 0.10 |

Rules:

- If a context field is **unassessed**, the tool uses a cautious value: 1.0 for exposure and sensitivity, and a long lifespan. The finding also shows the flag "context unassessed". Reports show how many findings use unassessed context.
- The report also lists each `classical-weak-now` finding in a separate section: **"Fix now (not quantum)"**. It does this for all scores.
- Priority bands: Critical is 80 or more. High is 60 or more. Medium is 40 or more. Low is less than 40. The user can change these values.
- An override replaces the band and the score in the priority list. The report shows the original value, the override, the reason, the person, and the date.

### 10.3 Complexity (S, M, L, XL)

The tool calculates the complexity size from rules. It shows the reasons. It does not show a number that looks more exact than it is.

- **Change type.** This is the most important factor. From the easiest to the most difficult: configuration change → library upgrade → code change → protocol or partner coordination → hardware, HSM, or firmware replacement → vendor dependency.
- **Agility.** A hard-coded algorithm at many call sites increases the size.
- **The size of post-quantum algorithms.** For example, an ML-DSA-65 signature is approximately 3.3 KB. An Ed25519 signature is 64 bytes. An ML-KEM-768 ciphertext is approximately 1 KB. The tool shows flags for a larger certificate chain, for MTU and UDP limits, and for size limits in database columns, tokens, or headers.
- **Interoperation.** External partners or clients must also change.

The tool converts each complexity size to an approximate `migration_years` value for the Mosca factor. The defaults are: S 0.25, M 0.5, L 1, XL 2. The user can change these values.

### 10.4 Necessary tests

For each finding, the tool lists the types of test that the fix will probably need:

- unit tests,
- integration tests,
- interoperation tests (with the name of the partner or client, if known),
- performance tests (handshake time, message size),
- certification and compliance (FIPS 140-3, Common Criteria).

The tool shows this as a checklist. It does not show a score.

### 10.5 References

- CWE:
  - **CWE-327** (Use of a Broken or Risky Cryptographic Algorithm) — for quantum-vulnerable primitives,
  - **CWE-326** (Inadequate Encryption Strength) — for short keys,
  - **CWE-328** (weak hash),
  - **CWE-321** and **CWE-798** (hard-coded keys or credentials).
- MITRE ATT&CK. These give threat context. They are not exact matches.
  - **T1040** Network Sniffing and **T1557** Adversary-in-the-Middle — for "harvest now, decrypt later",
  - **T1552.004** Unsecured Credentials: Private Keys — for key files that other persons can read.
- Method references:
  - the NIST SP 800-30 and ISO/IEC 27005 terms for likelihood factors and impact factors,
  - the migration guidance of the PQC Coalition (which MITRE leads),
  - the CycloneDX CBOM specification.

During the build, the builder must compare all IDs with the current CWE and ATT&CK catalogs. The rules pack contains the mappings.

## 11. Results file (`.pqr`)

- The file is JSON. It can also be zstd-compressed. It has a `schema_version` field.
- The header contains:
  - the engagement name,
  - the tool version,
  - the rules pack version and hash,
  - the scanner type,
  - the host where the scan ran,
  - the start time and the end time,
  - the operator,
  - the scope file hash (for network scans),
  - the audit log hash.
- The body contains:
  - findings,
  - scan errors and partial results,
  - inventory items that are *not* findings, for example endpoints that are ready for post-quantum cryptography. The CBOM and the list "what is already good" need these items.
- The `--redact` option changes host names and paths into hashes. Use it when you share results outside the client.
- `merge` removes duplicate findings by fingerprint. It records the scan that made each item.
- The repository contains a JSON Schema for `.pqr` files.

## 12. Outputs

### 12.1 Board report

The board report has 2 to 4 pages. It uses plain language. It does not list many algorithm names.

The board report contains:

- A summary of readiness, and the earliest deadlines that apply, for each region.
- Exposure for each **business unit** (from `assets.toml`): the number of findings in each priority band, and the part of the exposure that is "harvest now, decrypt later".
- The number of "Fix now (not quantum)" findings.
- Effort: the number of findings for each complexity size, and the items that depend on a vendor.
- How much of the result uses unassessed context.
- The decisions that the board must make. Examples: approve work with a vendor, pay for the replacement of an HSM, set the CRQC planning assumption.
- The assumptions (the CRQC year, the profiles, the scope coverage) and the items that were out of scope.

### 12.2 Technical report

The technical report contains:

- The method, the scope, the coverage, the assumptions, the rules pack version, and a summary of the audit log.
- The findings, in the order of the suggested (or overridden) priority. Each finding shows the evidence, the score calculation, the threat type, the deadline and its source, the CWE and ATT&CK IDs, the complexity and its reasons, the necessary tests, and the fix guidance (from the rules pack).
- A "Fix now (not quantum)" section.
- A list of the items that are already ready for post-quantum cryptography.
- A list of questions for vendors (for findings that a vendor must fix).
- A log of overrides.
- An appendix: a table that the customer can put into a risk register. It shows the likelihood factors and the impact factors for each finding.

### 12.3 Formats

- `html`: one file that contains all its content. It has inline CSS and does not get data from other locations. It prints correctly.
- `pdf`: the binary makes the PDF itself. It does not need a browser or LaTeX. The builder selects the engine. (One possible method is Typst as a library in the binary.)
- `md` and `json`. The `export` command gives flat CSV or JSON tables.
- `cbom`: a CycloneDX 1.6 (or later) CBOM in JSON. It has `cryptographic-asset` components (algorithms, certificates, related crypto material, protocols). Each component has links to the components or services where the tool found it.

## 13. Deadline profiles

The rules pack contains the deadline profiles, with one file for each profile. Each milestone has these fields:

- `date`, `description`, `source_title`, `source_url`, and `as_of`,
- `kind`: `planning` (discovery, roadmaps, plans) or `migration` (systems must move to new algorithms),
- `applies_to` (only for migration milestones). This field can have one or more of these conditions:
  - `tier`: `high` or `all`. The tool compares this with the `priority_tier` of the asset (section 7).
  - `threat_types`: for example, the CNSA 2.0 milestone for software and firmware signing applies only to `forgery-long-lived` findings for code signing.
  - `sector`: the milestone applies only when the sector overlay of the engagement is the same.

Users can add their own profiles, for example the internal targets of a company.

**How the tool selects the deadline for a finding:** The tool looks at the `migration` milestones in all the selected profiles. It uses only the milestones where `applies_to` matches the finding. From these, it selects the earliest date. The finding shows the profile and the source. **The tool never attaches a planning milestone to a finding.** Planning milestones are shown only for the engagement: in the summary of the board report, and in the method section of the technical report. An example is "The UK NCSC tells organisations to complete discovery and a plan by 2028".

The first profiles are below. The dates come from the sources at the time of this design. **During the build, compare each date with the primary documents again.** Give each profile an `as_of` date.

| Profile | Milestones |
|---|---|
| `us` | NIST IR 8547: RSA, ECDSA, ECDH, and DSA are deprecated in 2030 and disallowed in 2035. (Make sure whether the document is a draft or final.) The NSM-10 goal is 2035. |
| `us-nss` (sector overlay) | CNSA 2.0 milestones: new NSS acquisitions from 2027; software and firmware signing and network equipment at approximately 2030; full migration at 2033 or 2035. Secondary sources do not agree on the exact dates. Take the dates from the NSA CNSA 2.0 FAQ and CNSSP 15. |
| `uk` | NCSC: discovery and a plan by 2028; migrations with the highest priority by 2031; full migration by 2035. |
| `au` | ASD ISM: stop the use of traditional asymmetric cryptography (RSA, DH, ECDH, ECDSA) by the end of 2030. |
| `eu` | The EU coordinated roadmap (NIS Cooperation Group, June 2025): national roadmaps and a start by the end of 2026; high-risk use cases by the end of 2030; all use cases by the end of 2035. |
| `ca` | CCCS ITSM.40.001 (federal): first plans in April 2026; systems with high priority by the end of 2031; all other systems by the end of 2035. |

## 14. Rules pack

- The rules pack is a folder of YAML files. It contains:
  - API patterns for each language,
  - facts about libraries (which versions support post-quantum algorithms),
  - configuration directives,
  - the algorithm map for each file format,
  - the text for threat types and fixes,
  - CWE and ATT&CK mappings,
  - complexity rules,
  - deadline profiles,
  - (after v1) CVE, KEV, and EPSS data.
- The binary contains a default pack. New packs come as signed archive files. The user installs a new pack with `rules update --from <file>`. The tool does not get packs from the network.
- **How the tool trusts a pack without a network connection:** Maintainers sign each pack with a **hybrid Ed25519 + ML-DSA-65 key pair for packs**. This key pair is **not the same as the release keys**. The maintainers keep it offline. Both signatures must be correct. The binary contains a list of the trusted public keys for packs. Thus the check does not need a Sigstore trusted root, and the check does not become out of date. The CI also makes a Sigstore attestation for each pack, for persons who verify by hand. The binary does not use that attestation.
- **Key rotation:** A pack can contain a rotation statement — "key B replaces key A". Key A signs this statement (hybrid). Then the binary trusts key B for that pack and for later packs. The results record the chain of keys. If a key is compromised, the project releases a new binary with a new list of keys.
- `rules verify` checks the signatures. The tool refuses an unsigned pack or a changed pack, unless the user gives `--allow-unsigned-rules`. The results and reports record this flag.
- Each result and each report records the rules pack version and hash.
- The repository contains test examples for each rule: code that must match and code that must not match.

## 15. Release, supply chain, and trust

The project is open source. The licence is Apache-2.0 OR MIT (the builder's decision; this is usual for Rust projects). The GitHub repository is public.

**Platforms:** Linux x86_64 and aarch64 (static musl), macOS (universal binary for x86_64 and arm64), Windows x86_64 (and arm64 if the toolchain permits it).

**Build:** GitHub Actions, with a pinned toolchain. The repository contains `Cargo.lock`. Builds use `--locked`. The project tries to make builds reproducible. The documentation tells how to reproduce a build.

**Each release contains:**

1. **SLSA build provenance**, from `actions/attest-build-provenance`. This uses Sigstore without long-term keys. The repository is public, so the public Rekor transparency log records each attestation.
2. **An SBOM** (CycloneDX), from `cargo-cyclonedx`. `actions/attest-sbom` attaches the SBOM to each binary. Also, `cargo-auditable` puts the list of dependencies **into the binary**. (The builder must check the current behaviour of these two tools.)
3. **A CBOM of the tool itself.** The release process runs `pqaudit scan code` on the pqaudit repository, then runs `pqaudit cbom`. For this, v1 includes **parsing of `Cargo.toml` and `Cargo.lock`, and rules for Rust cryptography crates** (rustls, aws-lc-rs, ring, RustCrypto `rsa`, `p256`, `ed25519-dalek`, `ml-kem`, `ml-dsa`, and others). Scans of Rust *source code* are not in v1 (section 3). Thus the CBOM of the tool shows dependencies only. A short file in the repository adds a declaration of the algorithms that the binary itself uses for each purpose (TLS probes, signature checks). The CI compares this declaration with the dependency scan.
4. **A Sigstore bundle** for each file, for `cosign verify-blob` (with or without a network connection).
5. **A hybrid post-quantum signature**: separate Ed25519 and ML-DSA-65 signatures for a checksums file (SHA-256 and SHA3-256). Both signatures must be correct. Standard OpenSSL 3.5 (or later) can verify them. The maintainers keep the keys offline, not in CI. The public keys are in the repository, on the website, and in the release notes. Maintainers sign the release after the CI makes the files and after they verify the provenance of the files.
6. **The native signature for each operating system**: Windows Authenticode, and macOS Developer ID signing with notarization. (These need paid certificates and accounts. Refer to section 17.)
7. `SHA256SUMS` and `SHA3-256SUMS`.

**The release notes must contain a section "Verifying this release".** This section tells how to:

- use `gh attestation verify` and `cosign verify-blob`, with the expected certificate identity (the workflow path) and the OIDC issuer,
- **verify without a network connection**: keep the Sigstore bundle with the release, get the Sigstore `trusted_root.json` and make it current (it changes without a warning), and use a pinned version of cosign (the offline flags changed between versions),
- verify the hybrid post-quantum signature with OpenSSL 3.5 or later (with the exact commands),
- check Authenticode and notarization,
- find the SBOM and the CBOM, and compare the SBOM with the `cargo-auditable` data in the binary,
- find the rules pack version in the release, and verify a pack that you download separately.

The product README contains a short section **"Trusting pqaudit in your environment"**. This section is for client security teams. It gives a summary of the items above and of the safety model (section 8).

## 16. Architecture (guidance)

Use a Cargo workspace. These are the suggested crates:

- `pqaudit-cli` — argument parsing (clap), commands, output.
- `pqaudit-core` — the finding model, the `.pqr` schema, merge, fingerprints, scoring, complexity, profiles.
- `pqaudit-rules` — loading, verification, and the embedded default of the rules pack.
- `pqaudit-scan-code` — tree-sitter grammars, manifest and lockfile parsers, configuration parsers.
- `pqaudit-scan-files` — parsers for certificates, key stores, SSH keys, and GPG keys.
- `pqaudit-scan-net` — scope enforcement, rate limits, TLS and SSH probes, the audit log.
- `pqaudit-report` — board and technical reports (HTML, Markdown, PDF, JSON), the CBOM, CSV export.

The offline scanner crates must not depend on network crates. A CI check of the dependency graph makes sure of this. A test also makes sure that these scanners open no sockets.

## 17. Decisions

**Decisions of the requester:**

- Users: security teams in companies, and consultants.
- Outputs: a readiness report with priorities, in a board version and a technical version, plus a CBOM.
- One tool does three tasks: the code and dependency inventory, the TLS and SSH endpoint audit, and the certificate and key store audit.
- Rust. Linux, macOS, and Windows.
- Safety: no IDS alarms, no problems on production systems, no connections outside the scope. No host discovery.
- Code languages: Java, Python, Go, JS/TS, and C#.
- The priority comes from data sensitivity or classification, data lifespan, and exposure. The report is input to the customer's own risk assessment. The report includes complexity estimates and test estimates.
- A suggested priority from a formula that the user can see and override.
- Deadlines that the user can configure for each region.
- Open source.
- Releases in stages, in the order of section 18.
- All documentation, user-facing text, code comments, and commit messages use ASD-STE100 Simplified Technical English (section 19).
- The tool has its own SBOM and CBOM and has signatures. The release notes and the product notes describe all of this.

**Decisions of the designer (for review):**

- The code scan uses tree-sitter to find patterns. It does no data-flow analysis. It records unresolved algorithms as unresolved.
- Scans and reports are separate. Scans write `.pqr` results files, and `merge` combines them.
- No records of quantum PoC code. The customer sets a CRQC year. (Known CVE, KEV, and EPSS data comes after v1.)
- A weighted-sum formula with the default factors and weights in section 10.2. Cautious values for unassessed context.
- Complexity sizes S, M, L, and XL. Tests as a checklist.
- A hybrid Ed25519 + ML-DSA-65 release signature, with offline maintainer keys.
- No STARTTLS in v1. The legacy TLS check is off by default. A maximum of 3 TLS handshakes for each port.
- The default network limits in section 8.
- The binary makes PDF files itself.
- The licence is Apache-2.0 OR MIT.
- Milestones have `kind` and `applies_to`. Assets have `priority_tier`. Planning milestones are shown only for the engagement (sections 13 and 7).
- The binary trusts packs through hybrid pack keys that it contains. These keys are not the release keys. Signed rotation statements replace keys (section 14).
- v1 parses Cargo dependencies for the CBOM of the tool, plus a declaration that the CI checks (section 15).
- The size of a finding, the fingerprint design, and the merge of certificates by SHA-256 (section 10.1).
- Known CVE, KEV, and EPSS data comes after v1 (section 9.4).
- Assets have a `hardware_constrained` field. This field is the source of the hardware constraint flag (section 10.1).

**The builder decides:** the crates (other than the crates that this document names), the TLS probe method, the PDF engine, the exact default weights after tests with example data, the visual design of the reports, the details of the CLI, and the CI layout.

**Open items for the requester (these do not stop v1):**

- Who pays for and owns the Apple Developer certificate and the Windows code-signing certificate, and who keeps the offline post-quantum signing keys.
- The final product name.

## 18. Delivery stages

v1 comes in three releases, in this order. Each release is signed and is useful by itself.

**Stage 1 — files, network, and the trust pipeline**

- `init`, `scan files`, `scan net` (TLS and SSH), `merge`, `explain`, `rules`, `profiles`.
- The engagement files (section 7), the full safety model (section 8), and the audit log.
- The finding model, fingerprints, scoring, complexity, and necessary tests.
- The technical report (HTML, Markdown, JSON) and the CBOM.
- Deadline profiles: `us`, `uk`, `au`.
- The full release pipeline (section 15): all platforms, provenance, SBOM, hybrid post-quantum signature, operating system signatures, and the "Verifying this release" notes. Signatures and checks for rules packs (section 14).
- In this stage, the CBOM of the tool comes from the declaration (which the CI checks) and from the cryptography crates in the SBOM. Cargo parsing comes in Stage 2.
- The STE tools (section 19).

**Stage 2 — code scans**

- `scan code`: source code rules for Java, Python, Go, JS/TS, and C#; all the dependency formats in section 9.1, plus `Cargo.toml` and `Cargo.lock`; configuration files.
- The CBOM of the tool changes to the full `scan code` method.
- Stage 2 is complete when these conditions are true:
  - Each language has test examples that must match and must not match, for each row of the table in section 9.1 and for the most-used cryptography libraries of that language.
  - The tool scans a set of large public repositories for each language without a crash and with limited memory.

**Stage 3 — board report and integration**

- The board report. PDF output for both reports.
- `export` to CSV and JSON for GRC tools.
- Deadline profiles `eu` and `ca`, and the `us-nss` sector overlay. Documentation for user profiles.

After v1: STARTTLS, known CVEs for classical libraries (section 9.4), and `diff` between two assessments to show progress.

## 19. Language standard: ASD-STE100 Simplified Technical English

**All** text in the project uses **ASD-STE100 Simplified Technical English (STE)**, current issue. This includes:

- design documents and implementation plans, such as this document,
- the README, the user guide, the release notes (with "Verifying this release"), the "Trusting pqaudit" section, and the description of the safety model,
- CLI help: command summaries, the description of each parameter and flag, and examples,
- error messages, warning messages, refusal messages, and log messages for persons,
- the comments in the templates that `init` makes,
- the report text: the fixed headings, explanations, method, and assumptions in the board report and the technical report,
- the rules-pack text that users see: finding descriptions, fix guidance, threat-type explanations, and milestone descriptions,
- **code comments** (including Rust doc comments),
- **git commit messages** and pull request descriptions.

The rules (this is a summary; the STE specification has the full rules):

- Use only approved words, with their approved meaning. Technical names and technical verbs are permitted, as STE permits them. Examples of technical names: `ML-KEM-768`, `X25519MLKEM768`, `scope.toml`, and command and flag names.
- Procedural sentences (instructions): a maximum of 20 words, one instruction in each sentence, in the imperative form.
- Descriptive sentences: a maximum of 25 words. Paragraphs: a maximum of 6 sentences.
- Use the active voice. Write warnings and cautions as STE tells you: first the instruction, then the reason.
- Commit messages: a subject line in the imperative form (for example `Add the SSH probe`), then a body that obeys the rules above.

An example flag description in STE:

```
--dry-run    Show the targets that the scan will connect to. Do not connect to the targets.
```

How the project enforces STE:

- A contributor guide, **`docs/style/ste.md`**. It contains the technical names of the project and examples.
- A **CI lint** (for example Vale with a custom rule set). It checks sentence length, paragraph length, the passive voice, and a project word list. It checks Markdown documents, clap help text, message catalogs, rules-pack text, code comments, and commit messages. Each crate keeps its user-facing text in one location (a message catalog), so that the lint can find it.
- A person reviews STE compliance in each pull request that changes text.
- ASD gives the STE specification free, on request. Before the builder puts dictionary content in the public repository, the builder must check the licence terms. If the licence does not permit this, the lint contains only the project word list and the structure rules.
