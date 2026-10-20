# pqaudit — Post-Quantum Readiness Auditor: Design

Date: 2026-10-20
Status: Draft for approval
Name: `pqaudit` is a working name (check crates.io / GitHub availability before first release).

## 1. Intent

Organisations need to know where they are exposed to quantum-vulnerable cryptography before they can plan a migration. Today that discovery work is manual, spread across many tools, and hard to turn into something a board or a risk committee can act on.

`pqaudit` is an open-source, single-binary CLI that a **corporate security team** or a **consultant doing a client readiness assessment** runs to:

1. inventory cryptography in source code, dependencies, and configuration,
2. audit certificates, key stores, and SSH/GPG keys on disk,
3. audit live TLS and SSH endpoints,

and then produce:

- a **CycloneDX CBOM** of what was found,
- a **readiness report in two versions**: a **board-level** summary and a **technical** findings report with a suggested priority ranking.

The report is **input to the customer's own risk assessment**, not a replacement for it. It supplies evidence, factors, a transparent suggested ranking the customer can override, and complexity/testing estimates for the fixes.

Because the tool is carried into client environments, **it must be safe to run and easy to trust**: strictly scoped, gentle on the network, fully auditable, and shipped with signatures, provenance, an SBOM and its own CBOM.

## 2. Goals

- One static binary for Linux, macOS, and Windows. No runtime, no installer, works air-gapped.
- Three scan modes (code, files, network) that write portable results files, merged later into one assessment.
- Suggested priority per finding from a documented, configurable formula; customer overrides recorded with a reason.
- Complexity (S/M/L/XL) and testing-scope estimate per finding, with stated reasons.
- Board report, technical report, CBOM, and CSV/JSON export for GRC tools.
- Deadline profiles per region (and sector overlay), selectable per engagement.
- Verifiable releases: Sigstore keyless signing + SLSA build provenance, SBOM, the tool's own CBOM, a hybrid post-quantum signature, and OS-native code signing.

## 3. Non-goals (v1)

- **Host or port discovery.** No sweeps. The tool audits only targets explicitly listed in scope.
- **Vulnerability probing / exploitation** of any kind. No downgrade attacks, no fuzzing, no cipher-suite brute enumeration.
- C, C++ and Rust source scanning; analysis of compiled binaries or firmware images.
- Full dataflow / taint analysis. Code scanning is API pattern matching.
- Automatic remediation or code rewriting.
- Tracking quantum attack proof-of-concept code. No practical attack on RSA-2048 or P-256 exists; a "PoC available" flag would mislead. (Classical CVE data for crypto libraries is a separate, optional feature — §9.4.)
- Producing a final risk rating. The customer owns the risk decision.
- A server, agent, or GUI. CLI only; reports are files.

## 4. Anti-goals (failure even if it "works")

- **Triggering client IDS/IPS alarms** through scan volume or unusual traffic.
- **Disrupting production systems** (connection floods, resource exhaustion, malformed packets).
- **Touching anything outside the agreed scope**, including via DNS resolution to unexpected addresses or redirects.
- **Extracting or copying private key material** into results, logs, or reports.
- **Scaring a board with false precision** — fake-exact risk numbers, or quantum timelines presented as fact.
- **Silently assuming customer context.** Missing classification/lifespan/exposure must show as "unassessed", never as an invented value.
- A tool that customers can't verify before bringing it into their environment.

## 5. Users and workflow

Typical engagement:

```
pqaudit init acme-2026q4            # creates engagement folder with templates
  → edit scope.toml, assets.toml, engagement.toml
pqaudit scan net --dry-run          # show exactly what would be contacted
pqaudit scan net                    # person A, on a network-access box
pqaudit scan code ./repos/...       # person B, offline, on a build server
pqaudit scan files /etc /opt/app    # person C, on target hosts
pqaudit merge results/*.pqr         # combine all runs
pqaudit report --audience board     --format pdf
pqaudit report --audience technical --format html
pqaudit cbom -o acme.cdx.json
pqaudit export --format csv         # for the client's GRC / risk register
```

Scanning and reporting are separate so different people (and machines) can do each, and so the client can review raw results before anything leaves their network.

## 6. Commands

| Command | Purpose | Network? |
|---|---|---|
| `init <name>` | Create engagement folder with commented templates for `engagement.toml`, `scope.toml`, `assets.toml`, `overrides.toml`, `scoring.toml` | No |
| `scan code <path>...` | Source, dependency manifests/lockfiles, config files | No |
| `scan files <path>...` | Certificates, key stores, SSH and GPG keys | No |
| `scan net` | TLS and SSH handshakes against scope targets | Yes, scope-limited |
| `merge <results>...` | Combine results files into one assessment; dedupe findings | No |
| `report --audience board\|technical --format html\|pdf\|md\|json` | Render reports | No |
| `cbom` | Emit CycloneDX CBOM (JSON; XML optional) | No |
| `export --format csv\|json` | Flat findings table for GRC tools | No |
| `explain <finding-id>` | Show evidence, score breakdown, deadline source, CWE/ATT&CK refs | No |
| `rules list\|verify\|update --from <file>` | Inspect / verify / install a signed rules pack | No (update takes a local file) |
| `profiles list\|show <id>` | Show deadline profiles and their sources | No |

Global flags: `--engagement <dir>`, `--quiet/--verbose`, `--log-format text|json`, `--no-color`.

Exit codes: `0` success, `1` error, `2` scope/safety refusal, `3` partial results (some targets/files failed; details in results file).

## 7. Engagement files

All TOML, all created by `init` with comments.

**`engagement.toml`** — client name, assessor, dates, deadline profiles, CRQC assumption:

```toml
client   = "Acme Corp"
assessor = "Jane Doe, Example Consulting"

[deadlines]
profiles = ["au", "uk"]      # several allowed; findings show the strictest
sector   = "government"      # optional overlay

[assumptions]
crqc_year = 2035             # customer-set assumption for Mosca; shown in every report
```

**`scope.toml`** — the only source of network targets (§8).

**`assets.toml`** — customer context the tool cannot infer. Assets match findings by host, CIDR, path glob, or repo:

```toml
[[asset]]
name               = "Payments API"
business_unit      = "Retail Banking"     # board report rolls up by this
match              = { hosts = ["pay.acme.example"], paths = ["repos/payments/**"] }
classification     = "confidential"       # customer's own scheme, mapped in scoring.toml
data_lifespan_years = 10
exposure           = "internet"           # internet | partner | internal | isolated
owner              = "Payments Platform team"
vendor             = false                # true → fixes become vendor questions
priority_tier      = "high"               # high | standard — selects which deadline milestones apply (§13)
```

Unmatched findings get `unassessed` for every context field. An unassessed `priority_tier` is treated as `high` for deadline purposes (conservative) and flagged.

**`overrides.toml`** — customer overrides of suggested priority, keyed by stable finding fingerprint, each with `priority`, `reason`, `by`, `date`. Overrides and reasons appear in the technical report.

**`scoring.toml`** — formula weights and classification mapping (§10).

## 8. Safety model

1. **Explicit scope, hard refusal.** `scan net` only contacts `host:port` pairs listed in `scope.toml` (hostnames, IPs, CIDRs with explicit ports). Anything else is refused, not warned. Hostnames are resolved once at start; every resolved IP must also fall inside an allowed CIDR if `require_ip_in_cidr = true` (default true when any CIDR is listed). No redirects, no following SRV/MX, no SNI-driven pivoting.
2. **Exclusions win.** `exclude` entries in scope override includes.
3. **Gentle by default.** Defaults (all configurable down, capped upward unless `--i-know-what-im-doing`-style explicit flag in scope file):
   - global concurrency 4, per-host concurrency 1,
   - minimum 1 s between connections to the same host,
   - at most 3 TLS handshakes per port (see §9.3), 1 connection per SSH port,
   - connect timeout 5 s, read timeout 10 s, no retries by default,
   - optional time window (`allowed_hours`) — refuse to start outside it.
4. **`--dry-run`** prints every resolved target, port, protocol, and number of connections, then exits.
5. **Audit log.** Every connection attempt is appended to `audit.log` (JSON lines: timestamp, source interface/IP, destination, port, protocol, outcome, bytes sent/received). Included by reference in results; a consultant can hand it to the client as proof of what was touched.
6. **Offline modes never open sockets.** `scan code` and `scan files` must not perform DNS, HTTP, or any network I/O. A test enforces this.
7. **No private key material leaves the file.** File scanning reads key type, size/curve and public parts only. Private key bytes are never written to results, logs, or reports. Encrypted stores without a supplied password are recorded as "encrypted — not inspected".
8. **Read-only.** No scanner writes outside the engagement folder.

## 9. Scanners

All scanners emit findings into a common results file (`.pqr`, §11).

### 9.1 `scan code` — source, dependencies, config

**Languages (v1):** Java, Python, Go, JavaScript/TypeScript, C#.

**Source:** parse with tree-sitter; match calls to known crypto APIs defined in the rules pack. Examples:

| Language | Example patterns |
|---|---|
| Java | `KeyPairGenerator.getInstance("RSA")`, `KeyAgreement.getInstance("ECDH")`, `Signature.getInstance("SHA256withECDSA")`, BouncyCastle equivalents |
| Python | `cryptography` `rsa.generate_private_key`, `ec.generate_private_key`, `x25519`, PyCryptodome `RSA.generate` |
| Go | `crypto/rsa`, `crypto/ecdsa`, `crypto/ecdh`, `crypto/tls` `CurvePreferences`, `golang.org/x/crypto/ssh` |
| JS/TS | Node `crypto.generateKeyPairSync('rsa'\|'ec')`, `createECDH`, WebCrypto `subtle.generateKey`, `jsonwebtoken` alg `RS256/ES256`, `node-forge` |
| C# | `RSA.Create()`, `ECDsa.Create()`, `ECDiffieHellman.Create()`, `RSACryptoServiceProvider`, BouncyCastle .NET |

Each finding records: file, line, matched rule, algorithm, key size/curve if a literal is resolvable, **purpose** (key exchange, encryption, signature, hash), and whether the algorithm is **hard-coded** or **parameterised**. If the algorithm comes from a variable/config the rule can't resolve, the finding is `algorithm: unresolved` rather than a guess.

Also flag: hard-coded keys/secrets matching key formats (CWE-321/798), weak hashes (MD5/SHA-1) used for signatures.

**Dependencies:** parse `pom.xml`, Gradle (`build.gradle[.kts]`, `gradle.lockfile`), `requirements*.txt`, `pyproject.toml`, `poetry.lock`, `Pipfile.lock`, `uv.lock`, `go.mod`/`go.sum`, `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `*.csproj`, `packages.lock.json`, `Directory.Packages.props`. Flag crypto libraries and versions; rules record whether a version supports ML-KEM/ML-DSA (a "quick win" signal).

**Config:** nginx and Apache TLS directives, HAProxy, `openssl.cnf`, Java `java.security`, `sshd_config` / `ssh_config`, .NET `appsettings.json` TLS settings where present.

Respect `.gitignore` by default; `--no-ignore` to override. Skip vendored/generated directories per rules-pack defaults (e.g. `node_modules` source is skipped but its lockfile entries are counted).

### 9.2 `scan files` — certificates and keys

Inputs: PEM/DER certificates and chains, PKCS#12 (`.p12/.pfx`), Java KeyStore (JKS/JCEKS; PKCS#12 keystores), OpenSSH public/private key files (type header only for private keys), `authorized_keys`, `known_hosts`, GPG public keyrings / exported keys.

Records: algorithm, key size/curve, signature algorithm, issuer/subject, validity dates, CA flag, path-length / key usage, chain position, fingerprint (SHA-256), and file path. Long validity on a classical key (e.g. root CA beyond the strictest applicable deadline) is a strong signal.

Passwords for stores may be provided via env var or a password file referenced in `engagement.toml`; never on the command line.

### 9.3 `scan net` — TLS and SSH endpoints

**TLS (direct TLS on listed ports):** up to 3 handshakes per port by default:

1. Offer hybrid PQ groups only (`X25519MLKEM768`, plus other standardised hybrids in rules pack) → does the server negotiate a PQ key exchange?
2. Offer classical groups only (normal modern client) → what does it pick, and retrieve the certificate chain.
3. (Optional, off by default) Legacy-version check (TLS 1.0/1.1) with a minimal ClientHello.

Record: negotiated version, group, cipher suite, whether PQ hybrid is supported, certificate chain (same fields as §9.2), and handshake failures. Implementation choice for crafting probes is left to the builder (likely rustls with the aws-lc-rs provider for TLS 1.3 + a minimal hand-built ClientHello for the legacy check).

STARTTLS (SMTP, IMAP, POP3, LDAP, PostgreSQL) is **not in v1**; scope entries can declare `protocol = "tls"` or `"ssh"` only. Add later.

**SSH:** connect, exchange version banner, read the server's `KEXINIT`, and disconnect before key exchange completes. One connection reveals KEX algorithms (e.g. `mlkem768x25519-sha256`, `sntrup761x25519-sha512`), host key types, ciphers, MACs. Host key type/size via a completed KEX is optional (off by default) because it requires finishing the handshake.

### 9.4 Later (not v1): classical CVE context

Deferred until after v1 because it needs a bundleable data source, licence check, and a refresh owner. When built: if enabled, dependency findings are annotated with known CVEs for that library version, plus CISA KEV membership and EPSS score, from data bundled in the rules pack (offline; no lookup at scan time). Off by default; data freshness is shown in reports.

## 10. Findings, scoring, complexity

### 10.1 Finding model

**What one finding is:**

- **Code/dependency/config:** one finding per **rule × asset** (or rule × repo when no asset matches). Individual call sites/lines are listed as *occurrences* inside the finding; the Scale factor counts them. This keeps reports readable on large codebases.
- **Certificates and keys:** one finding per **certificate/key, keyed by its SHA-256 fingerprint**. If `scan files` and `scan net` both see the same certificate, `merge` produces one finding with both sightings.
- **Endpoints:** one finding per **host:port × issue** (e.g. "no PQ key exchange", "TLS 1.0 enabled").

**Fingerprints** (used for overrides and future re-scans):

- Code: hash of rule family ID + asset + file path + enclosing symbol (class/function), **not line numbers** — overrides survive line shifts.
- Rules carry stable family IDs and an `aliases` list, so renaming/splitting rules in new packs doesn't orphan overrides.
- File moves are not tracked in v1; an override that no longer matches is reported as "orphaned override" so the user can re-key it.
- Fingerprints are computed **before** `--redact`, so redacted results keep the same fingerprints.

Every finding has:

- `id` (short, per assessment) and `fingerprint` (above),
- source (`code` / `dependency` / `config` / `file` / `net`), location, evidence snippet,
- algorithm, key size/curve, purpose,
- **threat type**: `hndl` (key exchange / encryption — harvest-now-decrypt-later), `forgery-long-lived` (CA, firmware, code-signing, long-validity certs), `forgery-short-lived`, `classical-weak-now` (RSA-1024, SHA-1 signatures, TLS 1.0/1.1, 3DES etc. — risks today regardless of quantum),
- agility (`hard-coded` / `config` / `library-default`), library PQ-readiness, fix owner (`in-house` / `open-source` / `vendor`), hardware constraint flag,
- matched asset and its context (classification, lifespan, exposure, business unit, owner) or `unassessed`,
- applicable deadline (strictest across selected profiles) with profile and source,
- references: CWE and MITRE ATT&CK IDs (§10.5),
- suggested priority + full score breakdown, override (if any),
- complexity size + reasons, testing scope.

### 10.2 Suggested priority — transparent formula

Default formula is a **weighted sum of factor scores in [0,1]**, scaled to 0–100, with weights in `scoring.toml`. Every report and `explain` output shows each factor's value, weight, and contribution.

Default factors (builder may tune default weights; these are the starting point):

| Factor | Values (0–1) | Default weight |
|---|---|---|
| Threat type | hndl 1.0, forgery-long-lived 0.8, classical-weak-now 1.0, forgery-short-lived 0.3 | 0.25 |
| Exposure | internet 1.0, partner 0.7, internal 0.4, isolated 0.2 | 0.20 |
| Data sensitivity | from `scoring.toml` classification map | 0.20 |
| Mosca margin | 1.0 if `lifespan + migration_years > crqc_year − now`, scaled down otherwise (migration_years derived from complexity size) | 0.15 |
| Deadline proximity | years until strictest applicable deadline, scaled | 0.10 |
| Scale | number of occurrences of the same pattern in the asset, log-scaled | 0.10 |

Rules:

- **Unassessed** context fields use a conservative value (1.0 for exposure/sensitivity, lifespan treated as long) **and** the finding is visibly flagged "context unassessed". Reports show how many findings depend on unassessed context.
- `classical-weak-now` findings are also listed in a separate **"Fix now (not quantum)"** section regardless of score.
- Priority bands: Critical ≥ 80, High ≥ 60, Medium ≥ 40, Low < 40 (configurable).
- Overrides replace the band/score in rankings; the report shows original, override, reason, who, when.

### 10.3 Complexity (S / M / L / XL)

Derived from rules with listed reasons, not a pseudo-precise number:

- **Change type** (dominant factor), cheapest → hardest: config change → library upgrade → code change → protocol/partner coordination → hardware/HSM/firmware replacement → vendor dependency.
- Agility (hard-coded across many call sites raises size).
- Size impact of PQ algorithms (e.g. ML-DSA-65 signatures ~3.3 KB vs 64 B for Ed25519; ML-KEM-768 ciphertext ~1 KB): flags for certificate chain growth, MTU/UDP limits, DB column / token / header size limits.
- Interop reach (external partners/clients involved).

Each finding maps complexity size to an indicative `migration_years` used in the Mosca factor (default S 0.25, M 0.5, L 1, XL 2; configurable).

### 10.4 Testing scope

Per finding, a list of test types likely needed: unit, integration, interop (named partner/client side if known), performance (handshake latency, message size), certification/compliance (FIPS 140-3, Common Criteria). Output as checklist, not a score.

### 10.5 References

- CWE: **CWE-327** (broken/risky algorithm — quantum-vulnerable primitives), **CWE-326** (inadequate strength — short keys), **CWE-328** (weak hash), **CWE-321** / **CWE-798** (hard-coded keys/credentials).
- MITRE ATT&CK (threat context, not exact matches): **T1040** Network Sniffing and **T1557** Adversary-in-the-Middle (HNDL collection), **T1552.004** Unsecured Credentials: Private Keys (exposed key files).
- Methodology references: NIST SP 800-30 / ISO/IEC 27005 vocabulary for likelihood/impact factors; MITRE-led PQC Coalition inventory/migration guidance; CycloneDX CBOM spec.

Builder must verify all IDs against current CWE and ATT&CK catalogs during implementation; mappings live in the rules pack.

## 11. Results file (`.pqr`)

- JSON (optionally zstd-compressed), with a `schema_version`.
- Header: engagement name, tool version, rules pack version + hash, scanner type, host it ran on, start/end time, operator, scope file hash (for net scans), audit log hash.
- Body: findings, scan errors/partials, inventory items that are *not* findings (e.g. PQ-ready endpoints — needed for the CBOM and for "what's already good").
- `--redact` option hashes hostnames/paths for sharing outside the client.
- `merge` dedupes by fingerprint and keeps provenance of which run produced each item.
- A JSON Schema for `.pqr` is published in the repo.

## 12. Outputs

### 12.1 Board report

Target 2–4 pages. Plain language, no algorithm soup.

- Headline: readiness summary and the strictest applicable deadline(s) by region.
- Exposure by **business unit** (from `assets.toml`): counts by priority band, share of HNDL exposure.
- "Fix now (not quantum)" count.
- Effort view: findings by complexity size; vendor-dependent items.
- How much of the picture rests on unassessed context.
- Decisions needed (e.g. approve vendor engagement, fund HSM replacement, set CRQC planning assumption).
- Stated assumptions (CRQC year, profiles used, scope coverage) and what was out of scope.

### 12.2 Technical report

- Methodology, scope, coverage, assumptions, rules pack version, audit log summary.
- Findings ranked by suggested (or overridden) priority, each with evidence, score breakdown, threat type, deadline + source, CWE/ATT&CK, complexity + reasons, testing scope, remediation guidance (from rules pack).
- "Fix now (not quantum)" section.
- Already-PQ-ready inventory.
- Vendor questions list (for vendor-owned findings).
- Overrides log.
- Appendix: risk-register-ready table (likelihood-side factors / impact-side factors per finding).

### 12.3 Formats

- `html`: single self-contained file (inline CSS, no external fetches), prints well.
- `pdf`: rendered by the binary itself — no external browser or LaTeX. Builder chooses the engine (Typst as an embedded library is the suggested route).
- `md`, `json`; `export` gives CSV/JSON flat tables.
- `cbom`: CycloneDX 1.6+ CBOM JSON with `cryptographic-asset` components (algorithms, certificates, related crypto material, protocols) linked to the components/services where found.

## 13. Deadline profiles

Shipped in the rules pack, one file per profile; each milestone carries `date`, `description`, `source_title`, `source_url`, `as_of`, plus:

- `kind`: `planning` (discovery, roadmaps, plans) or `migration` (systems must be moved).
- `applies_to` (migration milestones only), any combination of:
  - `tier`: `high` / `all` — matched against the asset's `priority_tier` (§7).
  - `threat_types`: e.g. CNSA 2.0 software/firmware signing applies to `forgery-long-lived` code-signing findings only.
  - `sector`: only when the engagement's sector overlay matches.

Users can add custom profiles (e.g. internal company targets).

**How a finding gets its deadline:** among `migration` milestones from all selected profiles whose `applies_to` matches the finding, take the earliest date; the finding names the profile and source. **Planning milestones never attach to findings** — they appear only at engagement level (board report headline and technical report methodology), e.g. "UK NCSC expects discovery and a plan by 2028".

Initial profiles (dates verified against sources at design time; **re-verify against primary documents during implementation**, and mark profiles with an `as_of` date):

| Profile | Milestones |
|---|---|
| `us` | NIST IR 8547: quantum-vulnerable RSA/ECDSA/ECDH/DSA deprecated 2030, disallowed 2035 (confirm draft vs final status). NSM-10 goal 2035. |
| `us-nss` (sector overlay) | CNSA 2.0 milestones (new NSS acquisitions from 2027; software/firmware signing and networking equipment ~2030; full 2033/2035). Secondary sources disagree on exact dates — must take from NSA's CNSA 2.0 FAQ/CNSSP 15. |
| `uk` | NCSC: discovery and plan by 2028; highest-priority migrations by 2031; full migration by 2035. |
| `au` | ASD ISM: cease traditional asymmetric cryptography (RSA, DH, ECDH, ECDSA) by end of 2030. |
| `eu` | EU coordinated roadmap (NIS Cooperation Group, June 2025): national roadmaps and start by end-2026; high-risk use cases by end-2030; all by end-2035. |
| `ca` | CCCS ITSM.40.001 (federal): initial plans April 2026; high-priority systems by end-2031; remaining by end-2035. |

## 14. Rules pack

- Directory of YAML files: crypto API patterns per language, dependency/library facts (incl. PQ support by version), config directives, file-format handlers' algorithm mapping, threat-type and remediation text, CWE/ATT&CK mappings, complexity rules, deadline profiles, optional CVE/KEV/EPSS data.
- A default pack is embedded in the binary. Newer packs are distributed as signed archives and installed with `rules update --from <file>` — no network fetch by the tool.
- **Pack trust (offline):** packs are signed with a **hybrid Ed25519 + ML-DSA-65 pack-signing key pair, separate from the release keys**, held offline by maintainers. Both signatures must verify. The binary embeds the list of trusted pack-signing public keys, so verification needs no Sigstore trusted root and never goes stale. Packs are additionally Sigstore-attested in CI for people verifying by hand, but the binary does not depend on that.
- **Key rotation:** a pack may carry a rotation statement — "key B replaces key A" — signed by key A (hybrid). The binary then trusts B for that and later packs, and records the chain in results. Revocation of a compromised key is delivered by shipping a new binary with the updated embedded key list.
- `rules verify` checks signatures; the tool refuses unsigned or tampered packs unless `--allow-unsigned-rules` is passed (recorded in results and reports).
- Every result and report records the rules pack version and hash.
- Rules have test fixtures (positive/negative code samples) in the repo.

## 15. Release, supply chain, and trust

Open source (licence: Apache-2.0 OR MIT — builder's call, Rust ecosystem default), public GitHub repo.

**Platforms:** Linux x86_64 and aarch64 (static musl), macOS (universal binary: x86_64 + arm64), Windows x86_64 (arm64 if toolchain allows).

**Build:** GitHub Actions, pinned toolchain, `Cargo.lock` committed, `--locked` builds; aim for reproducible builds and document how to reproduce.

**Per release, publish:**

1. **SLSA build provenance** via `actions/attest-build-provenance` (Sigstore keyless; public repo → entries in the public Rekor transparency log).
2. **SBOM** (CycloneDX) generated with `cargo-cyclonedx`, attested to each binary with `actions/attest-sbom`; dependency list also **embedded in the binary** with `cargo-auditable` (builder verifies current behaviour of both tools).
3. **The tool's own CBOM**, produced by running `pqaudit scan code` on its own repo + `pqaudit cbom`. For this, v1 includes **`Cargo.toml` / `Cargo.lock` dependency parsing and rules for Rust crypto crates** (rustls, aws-lc-rs, ring, RustCrypto `rsa`/`p256`/`ed25519-dalek`/`ml-kem`/`ml-dsa`, etc.). Rust *source* scanning remains out of v1 (§3); the self-CBOM is dependency-level, supplemented by a short, checked-in declaration of which algorithms the binary itself uses for each purpose (TLS probing, signature verification), validated in CI against the dependency scan.
4. **Sigstore bundle** per artifact for `cosign verify-blob` (online and air-gapped).
5. **Hybrid post-quantum signature**: detached Ed25519 + ML-DSA-65 signatures over a SHA-256 / SHA3-256 checksums file. Both must verify. Verifiable with stock OpenSSL 3.5+. Keys are held offline by maintainers (not in CI); public keys published in the repo, on the website, and in release notes. Signing happens after CI artifacts are produced and their provenance verified.
6. **OS-native signing**: Windows Authenticode; macOS Developer ID signing + notarization. (Requires paid certificates/accounts — see §17.)
7. `SHA256SUMS` and `SHA3-256SUMS`.

**Release notes must include a "Verifying this release" section** covering:

- `gh attestation verify` and `cosign verify-blob` with expected certificate identity (workflow path) and OIDC issuer,
- **air-gapped verification**: shipping the Sigstore bundle, obtaining and refreshing Sigstore's `trusted_root.json` (it changes without notice), and a pinned cosign version (offline flags have changed across versions),
- verifying the hybrid PQ signature with OpenSSL 3.5+ (exact commands),
- checking Authenticode / notarization,
- where the SBOM and CBOM are and how to compare the SBOM with the embedded `cargo-auditable` data,
- the rules pack version shipped and how to verify a separately downloaded pack.

The product README gets a short **"Trusting pqaudit in your environment"** section summarising the above for client security teams, plus the safety model (§8).

## 16. Architecture (guidance)

Cargo workspace; suggested crates:

- `pqaudit-cli` — argument parsing (clap), commands, output.
- `pqaudit-core` — finding model, `.pqr` schema, merge, fingerprints, scoring, complexity, profiles.
- `pqaudit-rules` — rules pack loading, verification, embedded default.
- `pqaudit-scan-code` — tree-sitter grammars, manifest/lockfile parsers, config parsers.
- `pqaudit-scan-files` — cert/keystore/SSH/GPG parsers.
- `pqaudit-scan-net` — scope enforcement, rate limiting, TLS/SSH probes, audit log.
- `pqaudit-report` — board/technical rendering (HTML/MD/PDF/JSON), CBOM, CSV export.

Offline scanner crates must not depend on networking crates (enforced by a CI check on the dependency graph, in addition to the no-socket test).

## 17. Decided vs left to the builder

**Decided by the requester:**

- Users: corporate security teams and consultants.
- Outputs: prioritised readiness report in board and technical versions, plus CBOM.
- Combine code/dependency inventory, TLS/SSH endpoint audit, and cert/key-store audit in one tool.
- Rust; Linux, macOS, Windows.
- Safety: no IDS triggering, no production disruption, no out-of-scope contact. Host discovery dropped.
- Code languages: Java, Python, Go, JS/TS, C#.
- Prioritisation driven by data sensitivity/classification, lifespan, and exposure; report feeds the customer's own risk assessment; complexity and testing estimates included.
- Suggested ranking with a transparent, overridable formula.
- Deadlines configurable by region.
- Open source.
- Staged delivery in the order of §18.
- All product documentation and user-facing text in ASD-STE100 Simplified Technical English (§19).
- The tool ships with its own SBOM and CBOM and is signed; all of this documented in release/product notes.

**Designer's calls (flagged for review):**

- Tree-sitter pattern matching, no dataflow; unresolved algorithms reported as such.
- Scan/report split via `.pqr` results files and `merge`.
- No quantum PoC tracking; customer-set CRQC year instead; optional offline classical CVE/KEV/EPSS data.
- Weighted-sum formula with the default factors/weights in §10.2; conservative values for unassessed context.
- S/M/L/XL complexity; testing as a checklist.
- Hybrid Ed25519 + ML-DSA-65 release signature with offline maintainer keys.
- STARTTLS deferred; legacy-TLS check off by default; up to 3 TLS handshakes per port.
- Default network limits in §8.
- PDF rendered in-binary.
- Licence Apache-2.0 OR MIT.

- Milestone `kind`/`applies_to` and asset `priority_tier` (§13, §7); planning milestones shown at engagement level only.
- Rules packs trusted via embedded hybrid pack-signing keys (separate from release keys) with signed rotation statements (§14).
- Cargo dependency parsing in v1 for the self-CBOM, plus a CI-validated declaration (§15).
- Finding granularity, fingerprint design, and certificate merge by SHA-256 (§10.1).
- Classical CVE/KEV/EPSS data deferred past v1 (§9.4).

**Left to the builder:** crate choices beyond those named, TLS probe implementation, PDF engine, exact default weights after testing against fixtures, report visual design, CLI polish, CI layout.

**Open items needing the requester (not blocking v1 design):**

- Funding/ownership of Apple Developer and Windows code-signing certificates, and who holds the offline PQ signing keys.
- Final product name.

## 18. Delivery stages

v1 ships in three staged releases, in this order. Each stage is a usable, signed release.

**Stage 1 — files, network, trust pipeline**
- `init`, `scan files`, `scan net` (TLS + SSH), `merge`, `explain`, `rules`, `profiles`.
- Engagement files (§7), safety model (§8) complete, audit log.
- Finding model, fingerprints, scoring, complexity, testing scope.
- Technical report (HTML, Markdown, JSON) and CBOM.
- Deadline profiles: `us`, `uk`, `au`.
- Full release pipeline (§15): all platforms, provenance, SBOM, hybrid PQ signature, OS signing, "Verifying this release" notes. Rules-pack signing and verification (§14).
- Self-CBOM at this stage is the CI-validated declaration plus SBOM-derived crypto crates (Cargo parsing arrives in Stage 2).

**Stage 2 — code scanning**
- `scan code`: Java, Python, Go, JS/TS, C# source rules; all dependency formats in §9.1 plus `Cargo.toml`/`Cargo.lock`; config files.
- Self-CBOM switches to the full `scan code` path.
- Done when each language's rule set has positive and negative fixtures for every row of the §9.1 example table and the top crypto libraries in that ecosystem, and the tool runs clean (no crashes, bounded memory) on a set of large public repos per language.

**Stage 3 — board and integration**
- Board report; PDF output for both reports.
- `export` CSV/JSON for GRC tools.
- Deadline profiles `eu`, `ca`, `us-nss` sector overlay; custom profile docs.

After v1: STARTTLS, classical CVE context (§9.4), `diff` between assessments for progress tracking.

## 19. Language standard: ASD-STE100 Simplified Technical English

All product documentation and all user-facing text use **ASD-STE100 Simplified Technical English (STE)**, current issue. This includes:

- README, user guide, release notes (including "Verifying this release"), the "Trusting pqaudit" section, and the safety model description.
- CLI help: command summaries, every parameter/flag description, and examples.
- Error, warning, and refusal messages, and log messages meant for people.
- Comments in the templates that `init` creates.
- Report text: fixed headings, explanations, methodology, and assumptions in both board and technical reports.
- Rules-pack text shown to users: finding descriptions, remediation guidance, threat-type explanations, deadline milestone descriptions.

Rules to apply (summary — the STE specification governs):

- Use approved words with their approved meaning only. Technical names (e.g. `ML-KEM-768`, `X25519MLKEM768`, `scope.toml`, command and flag names) and technical verbs are permitted as STE allows.
- Procedural sentences: maximum 20 words, one instruction per sentence, imperative form.
- Descriptive sentences: maximum 25 words. Paragraphs: maximum 6 sentences.
- Use the active voice. Write warnings and cautions as STE requires (command first, then the reason).

Example flag description (STE):

```
--dry-run    Show the targets that the scan will connect to. Do not connect to the targets.
```

Enforcement:

- A **`docs/style/ste.md`** contributor guide with project-specific technical names and examples.
- A **CI lint** (e.g. Vale with a custom rule set) that checks sentence and paragraph length, passive voice, and a project word list, over Markdown docs, clap help strings, message catalogs, and rules-pack text. User-facing strings live in one place per crate (message catalog) so the lint can find them.
- Human review for STE compliance on every PR that changes user-facing text.
- The STE specification is obtained free from ASD on request; builder checks its licence terms before putting any dictionary content in the public repo. If redistribution is not allowed, the lint holds only the project's own word list and structural rules.

This design document itself is an internal engineering document and is not written in STE.
