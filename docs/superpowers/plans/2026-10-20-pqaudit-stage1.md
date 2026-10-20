# pqaudit Stage 1 Implementation Plan

<!-- vale STE.Words = NO -->
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
<!-- vale STE.Words = YES -->

This plan uses ASD-STE100 Simplified Technical English (STE).

**Goal:** Make pqaudit Stage 1. It is a signed CLI in one binary file. It scans certificates and keys on disk, and TLS and SSH endpoints in a strict scope. It gives a score to each finding. It makes a technical report and a CycloneDX CBOM.

**Architecture:** A Cargo workspace. Scanners write `.pqr` results files. A user can move these files to other computers. `merge` combines the files.

An assessment step adds customer context (assets, deadlines, overrides, score weights) to the results. The report and the CBOM use the assessment. A hybrid-signed rules pack contains the detection facts, the rule text, and the deadline profiles. The binary contains a default pack.

**Tech Stack:**

- Rust (stable, pinned), clap 4, serde/serde_json/toml/serde_yaml, schemars, chrono, tracing,
- tokio + tokio-rustls + rustls (aws-lc-rs provider), x509-parser, p12-keystore, ssh-key, pgp (rPGP),
- pkcs8/pkcs1, zeroize, ipnet, globset, walkdir, zstd, tar, ed25519-dalek, ml-dsa (RustCrypto),
- minijinja, include_dir, jsonschema (tests), assert_cmd + predicates (tests), Vale (text lint).

**Spec:** `docs/superpowers/specs/2026-10-20-pqaudit-design.md`. Section 18 defines Stage 1. Read the spec sections that each task names.

## Global Constraints

- Platforms:
  - Linux x86_64 and aarch64 (static musl),
  - macOS universal (x86_64 and arm64),
  - Windows x86_64 (and arm64 if the toolchain permits it).
- Pin the Rust toolchain in `rust-toolchain.toml` to the stable version on the day that Task 1 starts. Commit `Cargo.lock`. CI builds use `--locked`.
- Licence: `Apache-2.0 OR MIT`.
- **All text uses ASD-STE100 Simplified Technical English (spec section 19).**
  - This includes CLI help and each flag description, messages, `init` template comments, report text, and rules-pack text.
  - It also includes the README and documents, **code comments (including `///` doc comments), commit messages, and pull request descriptions.**
  - Procedural sentences: 20 words or fewer. Descriptive sentences: 25 words or fewer.
  - Paragraphs: 6 sentences or fewer.
  - Use the active voice. Put one instruction in each sentence.
  - You can use technical names (algorithm, file, command, and flag names).
- Commit messages: a subject line in the imperative form, in STE, with no type prefix. Example: `Add the SSH probe`.
  - A body is optional. If there is a body, it obeys STE.
- Each crate keeps its user-facing text in one `messages.rs` file.
  - The file has a list `pub const ALL: &[(&str, &str)]` (ID, text), so that the STE lint can find the text.
  - clap help comes from doc comments. The lint gets it from the rendered help.
- Exit codes: `0` success, `1` error, `2` refusal because of scope or safety, `3` partial results.
- The offline scanner crate (`pqaudit-scan-files`) must not depend on tokio, rustls, hyper, reqwest, socket2, or other network crates.
  - It must not open sockets.
- The tool never writes private key material to results, logs, reports, or error messages.
- The network defaults (spec section 8) are maximum values. Higher values need `override_limits = true` in `scope.toml`.
  - The defaults:
    - 4 connections at the same time in total,
    - 1 for each host,
    - a minimum of 1000 ms between two connections to the same host,
    - a maximum of 3 TLS handshakes for each port,
    - 1 connection for each SSH port,
    - a connect timeout of 5000 ms,
    - a read timeout of 10000 ms,
    - 0 retries.
- Hybrid signatures: Ed25519 (pure) + ML-DSA-65 (pure ML-DSA, FIPS 204, empty context string).
  - Both sign the raw file bytes. Both must be correct.
  - Keys are PKCS#8 and SPKI PEM files, so that OpenSSL 3.5 (or later) can check them.
- If a source says "by YEAR", store the date as `YEAR-12-31`.
- Stage 1 deadline profiles: `us`, `uk`, and `au` only.
- `report --audience board` and PDF output come in Stage 3.
  - In Stage 1, they must exit with `1` and show an STE message: the feature comes in a later release.

## Review Focus

1. **Bad files.** Examples:
   - truncated DER,
   - random data with the name `.pem`,
   - a 2 GB file,
   - a PEM file with 10 000 blocks.

   The tool records each file as a scan error with a reason. The scan continues. The tool does not panic. Memory use stays limited. Test: Task 7 `malformed_inputs_are_errors_not_panics`.
2. **Bad network peers.** Examples:
   - a server that sends banner lines without end,
   - a very large SSH packet length,
   - a server that accepts TCP and never sends data.

   The probe stops at the read timeout or the size limit. It records an error. Memory use stays limited. Tests: Task 11 `silent_server_times_out`, Task 12 `endless_banner_is_capped`, `oversized_packet_is_rejected`.
3. **A host name that resolves to an address outside the allowed CIDRs.**

   This includes a host name that resolves to many addresses, where one address is outside. The tool refuses the full scan before it makes a connection. It exits with 2. The dry-run shows the reason. Test: Task 10 `one_bad_resolved_ip_refuses_whole_scan`.
4. **Private keys in containers.** Examples:
   - unencrypted PKCS#8,
   - PKCS#12 key bags,
   - JKS private-key entries,
   - OpenSSH private keys,
   - parse errors on key files.

   No part of the private key goes into the `.pqr` file, logs, or error text. Tests: Task 8 `keystore_private_material_not_in_results`, Task 9 `private_key_material_never_in_results`.
5. **Paths that the tool cannot read.** Examples:
   - no permission,
   - a symlink loop,
   - a file name that is not UTF-8,
   - a path that goes away during the scan.

   The tool records a scan error and exits with 3. It scans the other files. Test: Task 7 `unreadable_paths_give_partial_exit_3`.

---

## File Structure

```
Cargo.toml                      workspace
rust-toolchain.toml
LICENSE-APACHE, LICENSE-MIT
README.md                       includes "Trusting pqaudit in your environment"
docs/user-guide.md
docs/verifying.md               "Verifying this release"
docs/style/ste.md               STE guide for contributors
docs/self-crypto.toml           declaration of the algorithms that the binary uses (CBOM of the tool)
schema/pqr.schema.json          generated, committed
.vale.ini, .github/vale/STE/*.yml
.github/workflows/ci.yml, release.yml
.github/release-notes-template.md
rules/                          default rules pack (in the binary)
  pack.toml
  algorithms.yaml
  rules/certs.yaml, keys.yaml, tls.yaml, ssh.yaml
  profiles/us.yaml, uk.yaml, au.yaml
  trust/keys.toml               trusted public keys for packs + revoked key IDs
crates/pqaudit-core/src/
  lib.rs, messages.rs
  finding.rs        Finding, enums, Occurrence, Location, CertInfo, KeyInfo, EndpointInfo
  fingerprint.rs    Fingerprint + constructors
  results.rs        ResultsFile (.pqr), header, read/write, zstd
  engagement.rs     parsers for EngagementConfig, AssetsFile, OverridesFile, ScoringConfig
  assets.rs         asset match
  deadlines.rs      milestone selection
  assess.rs         assessment pipeline
  scoring.rs        score + bands
  complexity.rs     change type → size, necessary tests
  merge.rs          merge + redact
  classify.rs       certificate classification (both scanners use it)
crates/pqaudit-rules/src/
  lib.rs, messages.rs
  pack.rs           RulesPack, RuleDef, AlgorithmFact, DeadlineProfile, Milestone
  embedded.rs       default pack in the binary
  verify.rs         hybrid signature, rotation chain, revocation
  install.rs        install to the user data folder + selection of the active pack
crates/pqaudit-scan-files/src/
  lib.rs, messages.rs, walk.rs, cert.rs, pkcs12.rs, jks.rs, ssh.rs, privkey.rs, gpg.rs
crates/pqaudit-scan-net/src/
  lib.rs, messages.rs
  scope.rs          ScopeFile parser, target plan, enforcement
  runtime.rs        limits, allowed_hours, control of the probes
  audit.rs          audit log + CountingStream
  tls.rs, tls_legacy.rs, ssh.rs
crates/pqaudit-report/src/
  lib.rs, messages.rs, technical.rs, cbom.rs
  templates/technical.html, technical.md.j2
crates/pqaudit-cli/src/
  main.rs, messages.rs, cli.rs (clap), exit.rs
  commands/{init,scan_files,scan_net,merge,report,cbom,explain,rules,profiles}.rs
  templates/{engagement,scope,assets,overrides,scoring}.toml
xtask/src/main.rs   keygen, sign, pack-rules, sign-release, strings, self-cbom, check-offline-deps
```

---

### Task 1: Workspace and CLI skeleton

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `LICENSE-APACHE`, `LICENSE-MIT`, `.gitignore`, the `Cargo.toml` and `lib.rs`/`main.rs` stub of each crate, `crates/pqaudit-cli/src/{main.rs,cli.rs,exit.rs,messages.rs}`, `xtask/`, `.github/workflows/ci.yml`
- Test: `crates/pqaudit-cli/tests/cli_basics.rs`

**Interfaces:**
- Produces:
  - `pqaudit_cli::exit::ExitCode { Success = 0, Error = 1, Refused = 2, Partial = 3 }`.
  - `cli::Cli` with the global flags `--engagement <DIR>` (default `.`), `--quiet`, `--verbose`, `--log-format text|json`, `--no-color`, `--allow-unsigned-rules`.
  - A subcommand enum with stubs for `init`, `scan files`, `scan net`, `merge`, `report`, `cbom`, `explain`, `rules`, and `profiles`.
  - Each stub returns `ExitCode::Error` with the message `messages::NOT_IMPLEMENTED`, until its task replaces it.
  - Each crate has a `messages.rs` that exports `pub const ALL: &[(&str, &str)]`.

- [ ] **Step 1:** If `cargo` is not installed, install rustup (`curl https://sh.rustup.rs -sSf | sh -s -- -y`).
  - Then write `rust-toolchain.toml`. Pin the version that `rustc --version` shows.
  - Add the targets in the Global Constraints.
- [ ] **Step 2: Write the failing tests** in `cli_basics.rs`, with `assert_cmd`:
  - `version_prints_name`: `pqaudit --version` succeeds, and stdout starts with `pqaudit `.
  - `help_lists_stage1_commands`: `pqaudit --help` stdout contains `init`, `scan`, `merge`, `report`, `cbom`, `explain`, `rules`, and `profiles`.
  - `unknown_command_exits_1`: `pqaudit frobnicate` exits with 1.
    - Map clap usage errors to 1. Do not use the clap default of 2, because 2 means refusal.
- [ ] **Step 3:** Run `cargo test -p pqaudit-cli`. Expected result: FAIL (no binary).
- [ ] **Step 4:** Make the workspace, the clap derive CLI, the tracing-subscriber setup from `--log-format`/`--verbose`/`--quiet`, and the exit code map.
  - Write the flag doc comments in STE. Example: `/// Show the targets that the scan will connect to. Do not connect to the targets.`
- [ ] **Step 5:** Add `ci.yml` with these jobs: `fmt` (`cargo fmt --check`), `clippy` (`cargo clippy --workspace --all-targets --locked -- -D warnings`), and `test` on ubuntu, macos, and windows (`cargo test --workspace --locked`).
- [ ] **Step 6:** Run `cargo test --workspace`. Expected result: PASS. Run `cargo clippy --workspace --all-targets -- -D warnings`. Expected result: no warnings.
- [ ] **Step 7:** Commit: `Add the workspace and the CLI skeleton`.

### Task 2: STE tools

**Files:**
- Create: `docs/style/ste.md`, `.vale.ini`, `.github/vale/STE/{SentenceLength.yml,ProceduralLength.yml,ParagraphLength.yml,Passive.yml,Words.yml}`, `xtask/src/strings.rs`
- Change: `.github/workflows/ci.yml` (add the `ste` job)
- Test: `xtask/tests/strings.rs`, `.github/vale/fixtures/{good.md,bad.md}`

**Interfaces:**
- Consumes: `messages::ALL` of each crate. `pqaudit_cli::cli::Cli` (through `clap::CommandFactory`).
- Produces: `cargo xtask strings --out target/ste`. It writes these files:
  - `cli-help.md`: the long help of each command and subcommand.
  - `messages.md`: each text in each `messages::ALL`, one paragraph for each text.
  - `rules-text.md`: the title, description, and remediation of each rule, and the description of each milestone, in `rules/`.
    - Task 3 makes `rules/`. If it is not there, skip it and show no error.
  - `comments.md`: each `//` and `///` comment in `crates/**/*.rs` and `xtask/**/*.rs`.
    - Join the adjacent comment lines into one paragraph.
    - Put the file name and the line number as a heading above each paragraph.
    - Skip `// SAFETY:` labels and tool directives (for example `// rustfmt::skip`).
  - `commits.md`: the subject and body of each commit in the range that `--commits <range>` gives (default: `origin/main..HEAD`, or all commits if there is no `origin/main`).
  - Later tasks add text to these sources. The lint finds the new text automatically.

- [ ] **Step 1: Write the failing tests** in `xtask/tests/strings.rs`:
  - `strings_extracts_help_and_messages`: run `cargo xtask strings --out <tmp>`. `cli-help.md` contains the description of the `--engagement` flag. `messages.md` contains the text of `pqaudit_cli::messages::NOT_IMPLEMENTED`.
  - `strings_extracts_comments`: a temporary crate with the comments `/// Read the file.` and `// Stop here.` gives two paragraphs in `comments.md`, each with its file and line.
  - `strings_extracts_commits`: in a temporary git repository with one commit `Add the file`, `commits.md` contains `Add the file`.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write `strings.rs`.
- [ ] **Step 4:** Write the Vale rules:
  - `SentenceLength`: error if a sentence has more than 25 words.
  - `ProceduralLength`: error if a list item has more than 20 words.
  - `ParagraphLength`: error if a paragraph has more than 6 sentence ends (`occurrence`, `max: 6`).
  - `Passive`: error for a `be` verb followed by a past participle.
  - `Words`: substitutions from the project word list in `docs/style/ste.md`. Examples: `utilize→use`, `ensure→make sure`, `perform→do`, `in order to→to`.
  - Do not copy ASD dictionary content into the repository (spec section 19).
  - Write `docs/style/ste.md` in STE. It contains:
    - a summary of the rules,
    - the list of project technical names (algorithm names, file names, command names),
    - the commit message rule,
    - 5 examples (before and after).
- [ ] **Step 5:** Write the fixtures. `bad.md` contains one error for each rule. `good.md` contains no errors.
  - Run `vale .github/vale/fixtures/bad.md`. Expected result: exactly 5 alerts, one for each rule.
  - Run `vale .github/vale/fixtures/good.md`. Expected result: 0 alerts.
- [ ] **Step 6:** Add the CI `ste` job.
  - It installs a pinned Vale version.
  - It runs `cargo xtask strings --out target/ste --commits "${{ github.event.pull_request.base.sha || 'HEAD~1' }}..HEAD"`.
  - Then it runs `vale README.md docs/ target/ste/ crates/pqaudit-report/src/templates/ crates/pqaudit-cli/src/templates/ .github/release-notes-template.md`.
  - It skips paths that do not exist yet.
- [ ] **Step 7:** If Vale shows errors in the Task 1 comments, rewrite them.
  - Run the xtask tests. Expected result: PASS.
  - Run the `ste` job commands locally. Expected result: 0 errors.
- [ ] **Step 8:** Commit: `Add the STE style guide, the Vale rules, and the text extraction`.

### Task 3: Rules pack format, default pack, and the `profiles` command

**Files:**
- Create: `crates/pqaudit-rules/src/{pack.rs,embedded.rs}`, `rules/pack.toml`, `rules/algorithms.yaml`, `rules/rules/{certs,keys,tls,ssh}.yaml`, `rules/profiles/{us,uk,au}.yaml`, `crates/pqaudit-cli/src/commands/profiles.rs`
- Test: `crates/pqaudit-rules/tests/pack.rs`, `crates/pqaudit-cli/tests/profiles.rs`

**Interfaces:**
- Produces (in `pqaudit_rules::pack`):
  - `RulesPack { id: String, version: semver::Version, rules: Vec<RuleDef>, algorithms: Vec<AlgorithmFact>, profiles: Vec<DeadlineProfile>, content_hash: String /* sha256 hex over the sorted file list */ }`
  - `RuleDef { id: String, family: String, aliases: Vec<String>, title: String, description: String, remediation: String, threat_type: Option<ThreatType> /* None = the scanner sets it */, cwe: Vec<String>, attack: Vec<String>, change_type: ChangeType, size_impact: Vec<SizeImpact>, testing: Vec<TestType> }`
  - `AlgorithmFact { name: String, oid: Option<String>, primitive: Primitive /* Pke, Kem, Signature, KeyAgree, Hash, Cipher */, quantum_vulnerable: bool, nist_quantum_level: u8, weak_below_bits: Option<u32>, weak_always: bool }`
  - `DeadlineProfile { id: String, name: String, milestones: Vec<Milestone> }`, `Milestone { date: NaiveDate, kind: MilestoneKind /* Planning | Migration */, applies_to: AppliesTo { tier: Option<TierScope /* High | All */>, threat_types: Vec<ThreatType>, sector: Option<String> }, description: String, source_title: String, source_url: String, as_of: NaiveDate }`
  - `RulesPack::load_dir(path: &Path) -> Result<RulesPack, PackError>`, `RulesPack::rule(&self, id_or_alias: &str) -> Option<&RuleDef>`, `RulesPack::algorithm(&self, name: &str) -> Option<&AlgorithmFact>`
  - `pqaudit_rules::embedded::default_pack() -> &'static RulesPack` (with `include_dir!("$CARGO_MANIFEST_DIR/../../rules")`; parse one time with `OnceLock`)
  - Shared enums: `ThreatType { Hndl, ForgeryLongLived, ForgeryShortLived, ClassicalWeakNow }`, `ChangeType { Config, LibraryUpgrade, CodeChange, ProtocolPartner, Hardware, Vendor }`, `SizeImpact { CertChain, Mtu, StorageField }`, `TestType { Unit, Integration, Interop, Performance, Certification }`, `Tier { High, Standard }` (asset tier), `TierScope { High, All }` (milestone scope). These enums are in `pqaudit-rules`. `pqaudit-core` exports them again.
- Stage 1 rule IDs (exact): `cert.classical-key`, `cert.weak-key`, `cert.weak-sig-hash`, `key.classical`, `key.weak`, `tls.no-pq-kex`, `tls.legacy-version`, `ssh.no-pq-kex`, `ssh.weak-kex`, `ssh.classical-hostkey`.
- Change types: `cert.*` → `Config` (Task 15 changes CA certificates to `ProtocolPartner`), `key.*` → `Config`, `tls.no-pq-kex` → `LibraryUpgrade`, `tls.legacy-version` → `Config`, `ssh.no-pq-kex` → `LibraryUpgrade`, `ssh.weak-kex` → `Config`, `ssh.classical-hostkey` → `LibraryUpgrade`.
- CWE: `classical-key`, `no-pq-kex`, and `classical-hostkey` → `CWE-327`. `weak-key` → `CWE-326`. `weak-sig-hash` → `CWE-328`. `legacy-version` and `weak-kex` → `CWE-327`.
- ATT&CK: `tls.*` and `ssh.*-kex` → `T1040`, `T1557`. `key.*` → `T1552.004`.
- `profiles list` shows `id  name  milestones-count` for each profile.
- `profiles show <id>` shows each milestone: the date, the kind, `applies_to`, the description, the source title and URL, and the `as_of` date.
- An unknown ID → exit 1.

- [ ] **Step 1: Write the failing tests** in `pack.rs`:
  - `embedded_pack_loads`: `default_pack()` has the 10 rule IDs above and the profiles `us`, `uk`, and `au`.
  - `rule_lookup_by_alias`: in a test pack folder, `rule("old.id")` finds a rule with the alias `old.id`.
  - `uk_profile_milestones`: `uk` has planning `2028-12-31`, migration tier High `2031-12-31`, and migration tier All `2035-12-31`.
  - `au_profile_milestone`: `au` has migration tier All `2030-12-31`.
  - `us_profile_milestones`: migration tier All `2030-12-31` (NIST IR 8547, deprecated) and `2035-12-31` (disallowed).
  - `every_milestone_has_source_and_as_of`: each milestone has a `source_url` that starts with `https://`, and an `as_of` date.
  - `rsa_weak_below_2048`: `algorithm("RSA").weak_below_bits == Some(2048)`. `algorithm("SHA-1").weak_always` is true.
  - `bad_yaml_is_error_with_file_name`: a pack with incorrect YAML gives a `PackError`. The message contains the file name.
- [ ] **Step 2:** Run `cargo test -p pqaudit-rules`. Expected result: FAIL.
- [ ] **Step 3:** Write `pack.rs` and `embedded.rs`. Write the YAML files.
  - `algorithms.yaml` contains at least these algorithms:
    - RSA, DSA, DH, ECDSA, ECDH, Ed25519, Ed448, X25519, X448,
    - ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA (one family for all parameter sets),
    - X25519MLKEM768, SecP256r1MLKEM768, SHA-1, MD5, SHA-256/384/512, and 3DES.
  - Write all rule text in STE.
- [ ] **Step 4:** Check the profile data.
  - Open each `source_url`:
    - the NIST IR 8547 page,
    - the NCSC page "Timelines for migration to post-quantum cryptography",
    - the ASD page "Planning for post-quantum cryptography".
  - Make sure that each date and its words are correct.
  - In the description, record whether IR 8547 is a draft or final.
  - Set `as_of` to the date of your check.
  - If a source does not agree with the test values, stop. Tell the human before you change the tests.
- [ ] **Step 5:** Write the failing CLI tests `profiles_list_shows_three`, `profiles_show_uk`, and `profiles_show_unknown_exits_1`. Then write `commands/profiles.rs`.
- [ ] **Step 6:** Run `cargo test -p pqaudit-rules -p pqaudit-cli`. Expected result: PASS. Run `cargo xtask strings`, then `vale target/ste/rules-text.md`. Expected result: 0 errors.
- [ ] **Step 7:** Commit: `Add the rules pack format, the default pack, and the profiles command`.

### Task 4: Signatures, checks, key rotation, and installation for rules packs

**Files:**
- Create: `crates/pqaudit-rules/src/{verify.rs,install.rs}`, `rules/trust/keys.toml`, `xtask/src/{keygen.rs,sign.rs,pack_rules.rs}`, `crates/pqaudit-cli/src/commands/rules.rs`
- Test: `crates/pqaudit-rules/tests/verify.rs`, `crates/pqaudit-cli/tests/rules.rs`, `xtask/tests/openssl_interop.rs`

**Interfaces:**
- Signature file `<file>.sig.json`: `{"format":"pqaudit-hybrid-sig/1","key_id":"<hex>","ed25519":"<base64>","ml_dsa_65":"<base64>"}`.
  - `key_id` is the hex SHA-256 of (Ed25519 SPKI DER ‖ ML-DSA-65 SPKI DER).
  - The xtask also writes the raw files `<file>.ed25519.sig` and `<file>.mldsa65.sig` for OpenSSL.
- Pack archive: `rules-<version>.tar.zst`.
  - It contains the `rules/` layout, plus optional `rotations/NNN.json` and `rotations/NNN.json.sig.json` files.
  - A rotation statement: `{"format":"pqaudit-key-rotation/1","old_key_id":"<hex>","new_ed25519_spki":"<base64 DER>","new_ml_dsa_65_spki":"<base64 DER>","issued":"YYYY-MM-DD"}`.
  - The old key signs the bytes of the statement file (hybrid).
- `rules/trust/keys.toml`: `[[key]] id, ed25519_spki_pem, ml_dsa_65_spki_pem`, and `revoked = ["<key_id>", ...]`.
- Produces:
  - `HybridPublicKey { ed25519: VerifyingKey, ml_dsa_65: ml_dsa::VerifyingKey<MlDsa65> }`, `HybridPublicKey::key_id(&self) -> String`
  - `verify_hybrid(data: &[u8], sig: &SigFile, key: &HybridPublicKey) -> Result<(), VerifyError>`. Both signatures must be correct.
  - `verify_pack_archive(archive: &[u8], sig: &SigFile, trust: &TrustStore) -> Result<VerifiedPack, VerifyError>`. `VerifiedPack { pack: RulesPack, signed_by: String, rotation_chain: Vec<String> }`.
    - It follows the rotation statements in order, from a trusted key in the binary.
    - It fails if the chain contains a revoked key.
  - `install::install_pack(archive_path, sig_path) -> Result<PathBuf, InstallError>`.
    - It installs into `<dirs::data_dir()>/pqaudit/rules/<version>/`.
    - It keeps the archive and the signature, and checks them again when it loads the pack.
  - `install::active_pack(allow_unsigned: bool) -> Result<ActivePack, InstallError>`. `ActivePack { pack: Arc<RulesPack>, origin: PackOrigin /* Embedded | Installed { path, signed_by } | Unsigned { path } */ }`.
    - It selects the highest version from the default pack and the installed packs that pass the check.
  - xtask commands:
    - `keygen --out <dir>`: writes `ed25519.key.pem`, `ed25519.pub.pem`, `mldsa65.key.pem`, and `mldsa65.pub.pem` (PKCS#8 and SPKI).
    - `sign --keys <dir> <file>`.
    - `pack-rules --out <dir>`: makes a tar.zst of `rules/`.
      - The result must be the same each time: sorted entries, mtime 0, uid and gid 0.
  - CLI:
    - `rules list`: the active pack and the installed packs, with version, origin, and hash.
    - `rules verify <archive>`: exit 0 or 1. It shows the signer and the key chain.
    - `rules update --from <archive>`: the signature is at `<archive>.sig.json`, unless `--sig` gives a different path.
    - An unsigned pack or a bad pack → exit 1, unless the user gives `--allow-unsigned-rules`.
      - With this flag, the tool installs the pack and shows a warning.

- [ ] **Step 1: Write the failing tests** in `verify.rs`. Make the keys in the test.
  - `valid_hybrid_sig_verifies`
  - `ed25519_only_tampered_fails` and `mldsa_only_tampered_fails`: change one signature. The check must fail.
  - `modified_archive_fails`
  - `rotation_chain_accepts_new_key`: trust key A. Key B signs the pack, and the pack has the rotation A→B. Result: OK, and `rotation_chain == [A, B]`.
  - `rotation_from_revoked_key_fails`: key A is in the revoked list. Result: fail.
  - `rotation_not_signed_by_old_key_fails`.
  - `unknown_key_fails`.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write `verify.rs`, `install.rs`, and the xtask commands.
- [ ] **Step 4: Write the test** `openssl_interop.rs::openssl_verifies_both_signatures`.
  - If `openssl version` is less than 3.5, skip the test and show a note.
  - Make keys and sign a file with the xtask.
  - Then run `openssl pkeyutl -verify -pubin -inkey ed25519.pub.pem -rawin -in <file> -sigfile <file>.ed25519.sig`.
  - Run the same command with `mldsa65.pub.pem` and `.mldsa65.sig`.
  - Both commands must show `Signature Verified Successfully`.
  - Run the test. Expected result: PASS.
- [ ] **Step 5:** Write the CLI tests: `rules_verify_good_pack_exit_0`, `rules_update_bad_sig_exit_1`, `rules_update_unsigned_with_flag_installs_and_warns`, and `rules_list_shows_embedded`.
  - `install.rs` must use the environment variable `PQAUDIT_DATA_DIR` when it exists, so that each test has its own data folder.
  - Write `commands/rules.rs`.
- [ ] **Step 6:** Make a **development** key for packs with the xtask.
  - Put its public half in `rules/trust/keys.toml`, with the comment `# DEVELOPMENT KEY — replace before the first release`. (Task 20 replaces it.)
  - Do not commit private keys. Add `*.key.pem` to `.gitignore`.
- [ ] **Step 7:** Run `cargo test --workspace`. Expected result: PASS. Commit: `Add hybrid signatures, key rotation, and installation for rules packs`.

### Task 5: Finding model, results file, and fingerprints

**Files:**
- Create: `crates/pqaudit-core/src/{finding.rs,fingerprint.rs,results.rs}`, `schema/pqr.schema.json`
- Test: `crates/pqaudit-core/tests/{results.rs,fingerprint.rs}`

**Interfaces:**
- Produces (in `pqaudit_core`):
  - `Source { File, Net }` (Stage 2 adds `Code`, `Dependency`, `Config`), `Purpose { KeyExchange, Encryption, Signature, Hash, Unknown }`, `Agility { HardCoded, Config, LibraryDefault, Unknown }`, `FixOwner { InHouse, OpenSource, Vendor, Unknown }`.
  - `Algorithm { name: String, key_bits: Option<u32>, curve: Option<String> }`
  - `Location::File { path: String, line: Option<u32> }` | `Location::Endpoint { host: String, ip: IpAddr, port: u16, protocol: Protocol /* Tls | Ssh */ }`
  - `Occurrence { location: Location, evidence: String, run_id: Uuid }`
  - `CertInfo { sha256: String, subject: String, issuer: String, not_before: DateTime<Utc>, not_after: DateTime<Utc>, is_ca: bool, key_usage: Vec<String>, ext_key_usage: Vec<String>, public_key: Algorithm, signature_algorithm: String, chain_position: Option<u8> }`
  - `KeyInfo { fingerprint_sha256: String, kind: KeyKind /* X509Spki, OpenSsh, Pgp, Pkcs8Private, EncryptedPrivate */, algorithm: Option<Algorithm>, comment: Option<String> }`
  - `EndpointInfo { protocol: Protocol, tls: Option<TlsObservation>, ssh: Option<SshObservation> }`. `TlsObservation { pq_hybrid_supported: Option<bool>, negotiated_version: Option<String>, negotiated_group: Option<String>, cipher_suite: Option<String>, legacy_versions: Option<Vec<String>>, errors: Vec<String> }`. `SshObservation { banner: String, kex: Vec<String>, host_key_algorithms: Vec<String>, ciphers: Vec<String>, macs: Vec<String> }`
  - `Finding { id: String, fingerprint: Fingerprint, rule_id: String, source: Source, algorithm: Option<Algorithm>, purpose: Purpose, threat_type: ThreatType, agility: Agility, fix_owner: FixOwner, also: Vec<String> /* other rule IDs that matched the same subject */, occurrences: Vec<Occurrence>, cert: Option<CertInfo>, key: Option<KeyInfo>, endpoint: Option<EndpointInfo> }`
  - `InventoryItem { kind: InventoryKind /* Certificate, Key, Endpoint */, fingerprint: Fingerprint, pq_ready: bool, algorithm: Option<Algorithm>, cert: Option<CertInfo>, key: Option<KeyInfo>, endpoint: Option<EndpointInfo>, occurrences: Vec<Occurrence> }`. The inventory has each cryptography item that the scan found, also items that are not findings. The CBOM uses it.
  - `ScanError { location: String, reason: String }`
  - `Fingerprint(String)` with `Fingerprint::cert(sha256_hex: &str)`, `Fingerprint::key(spki_or_blob_sha256_hex: &str)`, and `Fingerprint::endpoint(host: &str, port: u16, rule_family: &str)`. Format: `"<kind>:" + hex(sha256(kind ‖ 0x00 ‖ fields joined by 0x00))[..32]`. The host is in lower case.
  - `ResultsHeader { schema_version: u32 /* 1 */, engagement: String, tool_version: String, rules_pack: PackRef { id, version, content_hash, origin }, scanner: ScannerKind /* Files, Net, Merged */, host: String, operator: String, started: DateTime<Utc>, finished: DateTime<Utc>, scope_hash: Option<String>, audit_log_hash: Option<String>, runs: Vec<RunInfo { run_id, scanner, host, started }>, redacted: bool }`
  - `ResultsFile { header, findings: Vec<Finding>, inventory: Vec<InventoryItem>, errors: Vec<ScanError> }`, with `ResultsFile::write(&self, path: &Path, compress: bool) -> io::Result<()>` and `ResultsFile::read(path: &Path) -> Result<ResultsFile, ResultsError>`.
    - `read` finds zstd by the magic bytes `28 B5 2F FD`.
    - If `schema_version` is higher than the supported version, `read` refuses the file with an STE message that gives the two versions.

- [ ] **Step 1: Write the failing tests:**
  - `roundtrip_plain_and_zstd`: for the two modes, write and read give the same value.
  - `newer_schema_rejected`: header `schema_version: 99` → `ResultsError::UnsupportedSchema { found: 99, supported: 1 }`.
  - `fingerprint_endpoint_case_insensitive_host`: `endpoint("Pay.Example", 443, "tls.no-pq-kex") == endpoint("pay.example", 443, "tls.no-pq-kex")`.
  - `fingerprint_distinct_kinds`: `cert(x) != key(x)`.
  - `fingerprint_stable_value`: `Fingerprint::cert("00".repeat(32))` is equal to a literal value.
    - Calculate the value one time and put it in the test.
    - This test finds an accidental change of the format.
  - `committed_schema_matches_generated`: `schemars::schema_for!(ResultsFile)`, serialized with pretty print, is equal to the content of `schema/pqr.schema.json`.
- [ ] **Step 2:** Run `cargo test -p pqaudit-core`. Expected result: FAIL.
- [ ] **Step 3:** Write the code. Make `schema/pqr.schema.json` with an `#[ignore]` test or an xtask helper, and commit it.
- [ ] **Step 4:** Run the tests. Expected result: PASS. Commit: `Add the finding model, the results file, and the fingerprints`.

### Task 6: Engagement files and `init`

**Files:**
- Create: `crates/pqaudit-core/src/engagement.rs`, `crates/pqaudit-cli/src/commands/init.rs`, `crates/pqaudit-cli/src/templates/{engagement,scope,assets,overrides,scoring}.toml`
- Test: `crates/pqaudit-core/tests/engagement.rs`, `crates/pqaudit-cli/tests/init.rs`

**Interfaces:**
- Produces (in `pqaudit_core::engagement`):
  - `EngagementConfig { client: String, assessor: String, assessment_date: Option<NaiveDate>, deadlines: DeadlineSelection { profiles: Vec<String>, sector: Option<String> }, assumptions: Assumptions { crqc_year: i32 }, passwords: Option<PasswordSource /* { env: String } | { file: PathBuf } */> }`
  - `AssetsFile { asset: Vec<Asset> }`, `Asset { name, business_unit: Option<String>, matcher: AssetMatch { hosts: Vec<String>, cidrs: Vec<IpNet>, paths: Vec<String> } /* TOML key "match" */, classification: Option<String>, data_lifespan_years: Option<u32>, exposure: Option<Exposure /* Internet, Partner, Internal, Isolated */>, owner: Option<String>, vendor: Option<bool>, priority_tier: Option<Tier>, hardware_constrained: Option<bool> }`
  - `OverridesFile { r#override: Vec<Override { fingerprint: String, priority: Band, reason: String, by: String, date: NaiveDate }> }`, `Band { Critical, High, Medium, Low }`
  - `ScoringConfig { weights: Weights { threat: f64, exposure: f64, sensitivity: f64, mosca: f64, deadline: f64, scale: f64 }, classification: BTreeMap<String, f64>, bands: Bands { critical: f64, high: f64, medium: f64 }, migration_years: BTreeMap<Size, f64> }`.
    - Its `Default` has the values of spec sections 10.2 and 10.3:
      - weights 0.25/0.20/0.20/0.15/0.10/0.10,
      - classification `public 0.1, internal 0.4, confidential 0.7, secret 1.0, restricted 1.0`,
      - bands 80/60/40,
      - migration years S 0.25, M 0.5, L 1, XL 2.
  - `Engagement { dir: PathBuf, config: EngagementConfig, assets: AssetsFile, overrides: OverridesFile, scoring: ScoringConfig }`, `Engagement::load(dir: &Path) -> Result<Engagement, EngagementError>`.
    - If `assets.toml`, `overrides.toml`, or `scoring.toml` is missing, use the empty value or the default.
    - If `engagement.toml` is missing, return an error.
    - Each error gives the file name and the TOML line.
- `init <name> [--dir <parent>]` makes `<parent>/<name>/` with the five templates, `results/`, and `reports/`.
  - If the folder exists and is not empty, `init` refuses and exits with 1.
  - The template comments use STE and explain each key.

- [ ] **Step 1: Write the failing tests:** `load_minimal_engagement`, `missing_optional_files_use_defaults`, `scoring_defaults_match_spec` (check each default value above), `bad_toml_error_names_file_and_line`, and `asset_match_key_parses` (`match = { hosts = [...], cidrs = ["10.0.0.0/24"], paths = ["repos/**"] }`). CLI tests: `init_creates_layout`, `init_refuses_non_empty_dir`, and `init_templates_load` (after `init`, set `client`, then `Engagement::load` succeeds).
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code.
- [ ] **Step 4:** Run the tests. Expected result: PASS. Run `vale crates/pqaudit-cli/src/templates/`. Expected result: 0 errors.
- [ ] **Step 5:** Commit: `Add the engagement files and the init command`.

### Task 7: `scan files` — file walk and X.509 certificates

**Files:**
- Create: `crates/pqaudit-scan-files/src/{lib.rs,walk.rs,cert.rs,messages.rs}`, `crates/pqaudit-core/src/classify.rs`, `crates/pqaudit-cli/src/commands/scan_files.rs`, `crates/pqaudit-scan-files/tests/fixtures/` + `generate.sh`, `xtask/src/check_offline.rs`
- Change: `.github/workflows/ci.yml` (add the `offline` job)
- Test: `crates/pqaudit-scan-files/tests/{certs.rs,robustness.rs}`, `crates/pqaudit-cli/tests/scan_files.rs`

**Interfaces:**
- Consumes: `ResultsFile`, `Finding`, `InventoryItem`, `Fingerprint::cert`, `RulesPack` (Tasks 3 and 5).
- Produces:
  - `pqaudit_scan_files::ScanOptions { max_file_size: u64 /* default 10_485_760 */, follow_symlinks: bool /* default false */, passwords: Vec<Zeroizing<String>> }`
  - `pqaudit_scan_files::scan(paths: &[PathBuf], opts: &ScanOptions, pack: &RulesPack, run_id: Uuid) -> ScanOutput { findings: Vec<Finding>, inventory: Vec<InventoryItem>, errors: Vec<ScanError> }`
  - `pqaudit_core::classify::classify_cert(cert: &CertInfo, pack: &RulesPack, today: NaiveDate) -> Option<(String /* primary rule id */, ThreatType, Vec<String> /* also */)>`.
    - Order of priority: `cert.weak-key` (the key is below `weak_below_bits`, or `weak_always`) > `cert.weak-sig-hash` (SHA-1 or MD5 signature) > `cert.classical-key` (quantum-vulnerable key).
    - Threat type: weak → `ClassicalWeakNow`. Else `ForgeryLongLived` if `is_ca`, or if the certificate has the code-signing EKU, or if `not_after - not_before > 3 years`. Else `ForgeryShortLived`.
    - A post-quantum key (ML-DSA, SLH-DSA) → `None` (inventory only, `pq_ready: true`).
  - Detection: by extension (`.pem .crt .cer .der`), and by content (`-----BEGIN CERTIFICATE-----` in the first 64 KiB).
    - If a file has many PEM blocks, each certificate gives one occurrence, and `chain_position` is the block index.
    - If many files contain the same certificate, the result is one finding with many occurrences.
  - `scan files <PATHS>... [--max-file-size <BYTES>] [--follow-symlinks] [--output <FILE>]`.
    - The default output is `<engagement>/results/files-<UTC yyyymmddTHHMMSS>.pqr`.
    - Exit 3 if `errors` is not empty and the tool scanned some files.
    - Exit 1 if the tool could read no files.
  - `xtask check-offline-deps`: runs `cargo tree -p pqaudit-scan-files -e normal --prefix none`. It fails if the output contains `tokio`, `rustls`, `hyper`, `reqwest`, `socket2`, `mio`, `ureq`, or `curl`.

- [ ] **Step 1:** Write `generate.sh`. It uses `openssl` (3.5 or later) to make these fixtures:
  - an RSA-2048 leaf (1 year),
  - an RSA-1024 leaf,
  - an ECDSA P-256 CA (10 years),
  - an RSA-2048 leaf with a SHA-1 signature,
  - an ML-DSA-65 self-signed certificate,
  - a PEM chain of 3 certificates,
  - a DER certificate.

  Commit the script and its output.
- [ ] **Step 2: Write the failing tests** in `certs.rs`: `rsa2048_leaf_is_classical_short_lived`, `rsa1024_is_weak_now_with_also_classical`, `ecdsa_ca_is_long_lived`, `sha1_sig_is_weak_sig_hash`, `mldsa_cert_is_inventory_pq_ready`, `chain_positions_recorded`, `der_cert_detected`, `same_cert_two_files_one_finding_two_occurrences`, and `finding_has_rule_cwe_from_pack` (the pack contains the `rule_id` of the finding).
- [ ] **Step 3: Write the failing tests** in `robustness.rs`:
  - `malformed_inputs_are_errors_not_panics`. The inputs:
    - a truncated DER file,
    - random bytes with the name `x.pem`,
    - a PEM file with 10 000 bad blocks,
    - a sparse 2 GB file (skipped, with the error `too large`).
    - Result: each file is in `errors` with a reason. The scan returns.
  - `unreadable_paths_give_partial_exit_3` (CLI test; the chmod and symlink parts are for Unix only). The inputs:
    - a file with `chmod 000`,
    - a symlink loop,
    - a file name that is not UTF-8,
    - one good certificate.
    - Result: exit 3, the finding for the good certificate, and three errors.
- [ ] **Step 4:** Run `cargo test -p pqaudit-scan-files`. Expected result: FAIL.
- [ ] **Step 5:** Write the code with `walkdir` (no ignore files, `follow_links(opts.follow_symlinks)`) and `x509-parser`.
  - Store a path that is not UTF-8 in lossy form, with an error note.
  - Connect `scan_files.rs`: it loads the `Engagement` and the `active_pack`, and it writes the results with `ScannerKind::Files`.
- [ ] **Step 6:** Add the CI `offline` job (ubuntu). It runs `cargo xtask check-offline-deps`. Then it runs `strace -f -e trace=socket,connect -o trace.txt target/debug/pqaudit scan files <fixtures>`. The job fails if `trace.txt` contains `socket(AF_INET`, `socket(AF_INET6`, or `connect(`.
- [ ] **Step 7:** Run all the tests. Expected result: PASS. Commit: `Add the file walk and the X.509 certificate scan`.

### Task 8: `scan files` — PKCS#12 and Java key stores

**Files:**
- Create: `crates/pqaudit-scan-files/src/{pkcs12.rs,jks.rs}`.
  - Fixtures: `generate.sh` makes the PKCS#12 fixtures.
  - Make the JKS and JCEKS fixtures one time with `keytool`, commit them, and put the `keytool` command in a comment.
- Test: `crates/pqaudit-scan-files/tests/keystores.rs`

**Interfaces:**
- Consumes: `ScanOptions.passwords`, `classify_cert`.
- Produces:
  - `pkcs12::scan_p12(bytes: &[u8], passwords: &[Zeroizing<String>]) -> Result<Vec<CertInfo>, StoreError>`.
  - `jks::scan_jks(bytes: &[u8]) -> Result<Vec<JksEntry>, StoreError>`, where `JksEntry::TrustedCert(CertInfo) | JksEntry::PrivateKeyChain(Vec<CertInfo>)`.
    - JKS magic: `FE ED FE ED`. JCEKS magic: `CE CE CE CE`.
    - Read the certificates without a password.
    - Skip the encrypted key bytes and do not decode them.
    - Ignore the integrity hash at the end.
  - PKCS#12: try each password that the user supplies, then the empty password.
    - If all passwords fail, record one `KeyInfo { kind: EncryptedPrivate, algorithm: None }` inventory item.
    - Also record a note "encrypted — not inspected" in `errors`.
    - Make no finding for it.
  - Detection by extension (`.p12 .pfx .jks .jceks .keystore`) and by magic bytes.

- [ ] **Step 1: Write the failing tests:** `p12_with_empty_password_reads_certs`, `p12_with_supplied_password_reads_certs`, `p12_wrong_password_is_not_inspected_note`, `jks_trusted_and_chain_certs_read`, `jceks_magic_detected`, `truncated_jks_is_error`, and `keystore_private_material_not_in_results`.
  - For the last test, serialize the full `ScanOutput` to JSON.
  - Make sure that no 16-byte window of these values is in the JSON, as hex or base64:
    - the decrypted key DER of the PKCS#12 key bag,
    - the encrypted key data of the JKS entry.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code with `p12-keystore` and a JKS reader that you write. Put all key bytes in `Zeroizing`.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Commit: `Add the PKCS#12 and Java key store scan`.

### Task 9: `scan files` — SSH keys, PEM private keys, and GPG keys

**Files:**
- Create: `crates/pqaudit-scan-files/src/{ssh.rs,privkey.rs,gpg.rs}`. Fixtures:
  - `ssh-keygen`: RSA-2048, ECDSA, Ed25519, an encrypted Ed25519 key, `authorized_keys`, and `known_hosts` with hashed entries.
  - OpenSSL: unencrypted PKCS#8 RSA and EC keys, encrypted PKCS#8 keys, and a PKCS#1 `RSA PRIVATE KEY`.
  - `gpg --export`: RSA-3072 and Ed25519.
- Test: `crates/pqaudit-scan-files/tests/keys.rs`

**Interfaces:**
- Produces:
  - Findings with `rule_id` `key.classical` or `key.weak`.
    - `key.classical`: the algorithm is quantum-vulnerable. `ThreatType::ForgeryShortLived` for signing keys. `Hndl` for keys that do only key agreement.
    - `key.weak`: `ClassicalWeakNow`.
  - `KeyInfo` with all its fields.
  - `Fingerprint::key(sha256 of the public key)`: the SPKI DER, the SSH public blob, or the OpenPGP v4 fingerprint.
  - Encrypted private keys → `KeyKind::EncryptedPrivate`, `algorithm: None`. Record them in the inventory, with a note.
  - `.kbx` key boxes → an `errors` entry "unsupported format". (The spec says that v1 supports exported keys and the old `pubring.gpg`.)
- Rule: a private key parser reads only the algorithm identifier, and the length of the public modulus or the curve.
  - Put the buffers in `Zeroizing`.
  - No error message contains bytes from the file.

- [ ] **Step 1: Write the failing tests:**
  - `ssh_rsa_ecdsa_ed25519_public_keys`
  - `authorized_keys_each_line_a_key`
  - `known_hosts_hashed_entries_supported`
  - `encrypted_openssh_private_key_public_part_only`: the OpenSSH format keeps the public key unencrypted. The algorithm is in the result.
  - `pkcs8_rsa_bits_read`, `pkcs1_rsa_detected`, `encrypted_pkcs8_not_inspected`
  - `gpg_rsa3072_and_ed25519`, `kbx_is_unsupported_error`
  - `same_key_in_authorized_keys_and_pub_file_one_finding`
  - `private_key_material_never_in_results`: for each private-key fixture, decode the private part.
    - Make sure that no 16-byte window of it (raw, hex, or base64) is in the serialized `ScanOutput` or in a `ScanError.reason`.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code with `ssh-key`, `pkcs8` + `pkcs1`, and `pgp`.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Commit: `Add the SSH, PEM private key, and GPG key scan`.

### Task 10: Scope file, target plan, enforcement, and dry-run

**Files:**
- Create: `crates/pqaudit-scan-net/src/{lib.rs,messages.rs,scope.rs}`, `crates/pqaudit-cli/src/commands/scan_net.rs` (the dry-run path only)
- Test: `crates/pqaudit-scan-net/tests/scope.rs`, `crates/pqaudit-cli/tests/scan_net_dry_run.rs`

**Interfaces:**
- `scope.toml`:
  ```toml
  require_ip_in_cidr = true           # default true when a CIDR is in targets or in allowed_cidrs
  allowed_cidrs = ["10.0.0.0/16"]     # addresses that names can resolve to; these are not targets
  allowed_hours = "09:00-17:00"       # optional, local time
  override_limits = false
  legacy_tls_check = false
  [limits]                            # all optional; the defaults are the values in the Global Constraints
  concurrency = 4
  [[target]]  host = "pay.acme.example"  ports = [443]  protocol = "tls"
  [[target]]  cidr = "10.0.1.0/28"       ports = [22]   protocol = "ssh"
  [[exclude]] cidr = "10.0.1.5/32"       # or host = "..."
  ```
- Produces (in `pqaudit_scan_net::scope`):
  - `ScopeFile` (serde). `Limits { concurrency: usize, per_host: usize, min_interval: Duration, tls_handshakes: u8, connect_timeout: Duration, read_timeout: Duration, retries: u8 }`. `Limits::effective(requested: &LimitsToml, override_limits: bool) -> Result<Limits, ScopeError>`: a value above the default, without `override_limits`, gives `ScopeError::LimitAboveDefault { name, requested, default }`.
  - `trait Resolver { fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>; }`, with `SystemResolver` (it uses `ToSocketAddrs`, one call for each host).
  - `build_plan(scope: &ScopeFile, resolver: &dyn Resolver) -> Result<TargetPlan, ScopeError>`. `TargetPlan { targets: Vec<PlannedTarget { host: Option<String> /* SNI */, ip: IpAddr, port: u16, protocol: Protocol, connections: u8 }>, refused: Vec<Refusal { target: String, reason: RefusalReason }>, limits: Limits }`.
    - A CIDR target with more than 256 addresses → refusal, unless `override_limits`.
    - Excludes have priority over includes.
    - The tool resolves each host exactly one time.
  - `TargetPlan::is_refused(&self) -> bool`. One refusal stops the full scan (exit 2).
  - `scope_hash(bytes: &[u8]) -> String` (sha256 hex), for `ResultsHeader.scope_hash`.
  - `scan net --dry-run` shows each planned target (host, IP, port, protocol, connections) and each refusal with its reason.
    - It exits with 0 if there are no refusals, else with 2.
    - It opens no sockets, except for DNS.

- [ ] **Step 1: Write the failing tests.** Use a `FakeResolver` that counts the calls.
  - `host_target_resolves_once`
  - `one_bad_resolved_ip_refuses_whole_scan`: a host resolves to `[10.0.0.5, 203.0.113.9]`, and `allowed_cidrs = ["10.0.0.0/16"]`. Result: the tool refuses the plan, and the reason contains `203.0.113.9`.
  - `exclude_beats_include`
  - `cidr_over_256_refused_without_override` and `cidr_over_256_allowed_with_override`
  - `limit_above_default_rejected`, `limit_below_default_accepted`
  - `tls_connections_count_is_2_or_3`: 2 without `legacy_tls_check`, 3 with it. SSH: 1.
  - `ip_target_has_no_sni`
  - CLI tests: `dry_run_lists_targets_exit_0` and `dry_run_with_refusal_exit_2`. (Use `localhost` and a CIDR scope, so that the resolution is local.)
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Commit: `Add the scope file, the target plan, and the dry-run`.

### Task 11: Network runtime, audit log, and TLS probes

**Files:**
- Create: `crates/pqaudit-scan-net/src/{runtime.rs,audit.rs,tls.rs,tls_legacy.rs}`
- Change: `crates/pqaudit-cli/src/commands/scan_net.rs` (the real scan)
- Test: `crates/pqaudit-scan-net/tests/{runtime.rs,tls.rs}`

**Interfaces:**
- Consumes: `TargetPlan`, `Limits`, `Finding`, `InventoryItem`, `Fingerprint::{endpoint,cert}`, `pqaudit_core::classify::classify_cert` (Task 7).
- Produces:
  - `audit::AuditLog::open(path: &Path) -> io::Result<AuditLog>` (append, JSON lines). `AuditLog::record(&self, e: &AuditEntry)`. `AuditEntry { ts: DateTime<Utc>, run_id: Uuid, src_ip: Option<IpAddr>, dst_host: Option<String>, dst_ip: IpAddr, port: u16, protocol: Protocol, probe: String /* "tls-hybrid" | "tls-classical" | "tls-legacy" | "ssh-kexinit" */, outcome: String, bytes_sent: u64, bytes_received: u64, duration_ms: u64 }`. `audit::CountingStream<S>`: an AsyncRead/AsyncWrite wrapper that counts bytes.
  - `runtime::run(plan: &TargetPlan, probes: &dyn Probes, audit: &AuditLog, run_id: Uuid) -> NetOutput { findings, inventory, errors }`.
  - `trait Probes { async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx) -> TlsObservationWithCerts; async fn ssh(&self, t: &PlannedTarget, ctx: &ProbeCtx) -> SshObservationResult; }`.
  - `run` applies these limits:
    - a global semaphore for concurrency,
    - 1 connection at a time for each host,
    - `min_interval` between two connections to the same IP address,
    - the timeouts,
    - no retries.
  - `ProbeCtx` contains the limits, the audit log, and the run ID.
  - Each connection attempt goes through one `connect()` helper. This helper records an `AuditEntry`, also when the connection fails.
  - `runtime::check_allowed_hours(spec: Option<&str>, now: NaiveTime) -> Result<(), ScopeError>`. Outside the window, the tool refuses (exit 2) before it makes a connection.
  - `tls::RealProbes` handshakes:
    1. Hybrid only: the rustls aws-lc-rs provider, TLS 1.3 only, and the key exchange group `X25519MLKEM768`.
       - Also use `SECP256R1MLKEM768` if the provider has it.
       - Success → `pq_hybrid_supported = Some(true)`.
       - A handshake error → `Some(false)`, with the error text.
    2. Classical: the groups X25519, secp256r1, and secp384r1; TLS 1.3 and 1.2.
       - Record the version, the group, the cipher suite, and the full peer chain.
       - Use a `ServerCertVerifier` that records the chain and accepts all chains.
       - (This is safe, because the probe sends no data.)
    3. Only if `legacy_tls_check` is true: `tls_legacy::probe` sends a ClientHello that you make by hand.
       - The ClientHello has `client_version = 0x0302` and the usual TLS 1.0 and 1.1 cipher suites.
       - The probe reads `server_version` from the ServerHello, then closes the connection.
    - Each handshake ends with close_notify (if there is a session) and closes the socket.
  - Findings:
    - `tls.no-pq-kex` (`Hndl`, one for each host:port) when `pq_hybrid_supported == Some(false)`.
    - `tls.legacy-version` (`ClassicalWeakNow`) when the server accepts TLS 1.0 or 1.1.
    - The certificates in the chain go through `classify_cert` and give `cert.*` findings, with an `Endpoint` occurrence.
    - Endpoints that support a hybrid group → inventory, `pq_ready: true`.
  - `scan net [--output <FILE>]` does these steps:
    - It makes the plan (a refusal → exit 2).
    - It checks the hours.
    - It opens `<engagement>/audit.log`.
    - It runs the probes.
    - It writes the `.pqr` file with `scope_hash` and `audit_log_hash` (the sha256 of the log after the run).
    - The default output is `<engagement>/results/net-<timestamp>.pqr`. Exit 3 if a target has an error.

- [ ] **Step 1: Write the failing tests** in `runtime.rs`. Use a fake `Probes` that records the time of each call.
  - `global_concurrency_respected`: with 20 targets, a maximum of 4 probes at the same time.
  - `same_host_min_interval_respected`: a minimum of 1000 ms between two calls to the same IP address. Use `tokio::time::pause`.
  - `every_connection_audited`: one entry for each connection, also for failures, with byte counts.
  - `outside_allowed_hours_refuses`
  - `no_retries_on_failure`
- [ ] **Step 2: Write the failing tests** in `tls.rs`. Use rustls servers in the same process on `127.0.0.1`, with rcgen certificates.
  - `hybrid_server_detected`: the server offers X25519MLKEM768.
  - `classical_only_server_gives_no_pq_finding`
  - `chain_certs_classified`: an RSA-2048 leaf gives `cert.classical-key` with an endpoint occurrence.
  - `legacy_probe_detects_tls10`: a minimal fake server answers with a ServerHello with version `0x0301`.
  - `legacy_probe_off_by_default_makes_2_connections`
  - `silent_server_times_out`: a TCP listener that never writes. Use a read timeout of 1 s in the test.
    - The probe stops in less than the read timeout + 1 s, and records an error.
- [ ] **Step 3:** Run the tests. Expected result: FAIL.
- [ ] **Step 4:** Write the code.
- [ ] **Step 5:** Run the tests. Expected result: PASS.
- [ ] **Step 6:** Commit: `Add the network runtime, the audit log, and the TLS probes`.

### Task 12: SSH KEXINIT probe

**Files:**
- Create: `crates/pqaudit-scan-net/src/ssh.rs`
- Test: `crates/pqaudit-scan-net/tests/ssh.rs`

**Interfaces:**
- Produces: `ssh::probe(stream, limits) -> Result<SshObservation, SshProbeError>`. The probe does these steps:
  1. Read lines until a line starts with `SSH-`. Maximum 64 lines and 255 bytes for each line. Else, the error is `banner too long`.
  2. Send `SSH-2.0-pqaudit_<version>\r\n`.
  3. Read one binary packet. If `packet_length` is more than 35 000, give an error.
  4. The message must be 20 (`SSH_MSG_KEXINIT`). Skip the 16-byte cookie.
  5. Parse the name-lists `kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms_server_to_client`, and `mac_algorithms_server_to_client`.
  6. Close the connection. Do not send KEXINIT.
- Findings:
  - `ssh.no-pq-kex` (`Hndl`): the server offers none of `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, and `sntrup761x25519-sha512@openssh.com`.
    - Keep this list of post-quantum KEX names in `algorithms.yaml`, so that a pack can add names.
  - `ssh.weak-kex` (`ClassicalWeakNow`): the server offers `diffie-hellman-group1-sha1`, `diffie-hellman-group14-sha1`, or `diffie-hellman-group-exchange-sha1`.
  - `ssh.classical-hostkey` (`ForgeryShortLived`): all the host key algorithms that the server offers are classical.
  - The server offers a post-quantum KEX → inventory, `pq_ready: true`.

- [ ] **Step 1: Write the failing tests.** Use a fake TCP server on `127.0.0.1` that sends recorded bytes.
  - `parses_openssh_kexinit`: a recorded KEXINIT from OpenSSH 9.9 that contains `mlkem768x25519-sha256`.
  - `no_pq_kex_finding`, `weak_kex_finding`
  - `pre_banner_lines_skipped`
  - `endless_banner_is_capped`: the server sends 1 000 lines.
  - `oversized_packet_is_rejected`: `packet_length = 0x7fffffff`.
  - `never_sends_kexinit`: the fake server makes sure that it received only the banner line.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code. Connect it to `RealProbes::ssh`.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Commit: `Add the SSH KEXINIT probe`.

### Task 13: Merge and redact

**Files:**
- Create: `crates/pqaudit-core/src/merge.rs`, `crates/pqaudit-cli/src/commands/merge.rs`
- Test: `crates/pqaudit-core/tests/merge.rs`, `crates/pqaudit-cli/tests/merge.rs`

**Interfaces:**
- Produces:
  - `merge(inputs: Vec<ResultsFile>) -> Result<ResultsFile, MergeError>`:
    - Remove duplicate findings by `fingerprint`. Join the occurrences, and remove duplicates by (location, run_id). Join the `also` lists.
    - Do the same for the inventory. Join the error lists.
    - Set `header.scanner = Merged`. `runs` contains all the runs of the inputs.
    - If the inputs have different rules packs, keep the highest version in the header.
      - Add a warning `ScanError { location: "merge", reason }` that gives the versions.
    - Different `engagement` names → `MergeError::EngagementMismatch`.
    - If `scan files` and `scan net` both find a certificate, the result is one finding.
      - The finding has the two types of occurrence (spec section 10.1).
  - `redact(file: &mut ResultsFile)`: replace these values with `"redacted:" + hex(sha256(value))[..12]`:
    - each host name, IP address, and path,
    - each certificate subject and issuer,
    - each SSH banner.
    - Do not change fingerprints. Set `header.redacted = true`. Redact `header.host` and `header.operator`.
  - `merge <INPUTS>... [--output <FILE>] [--redact]`. The default output is `<engagement>/results/merged.pqr`.

- [ ] **Step 1: Write the failing tests:**
  - `same_cert_from_files_and_net_merges`, `distinct_findings_kept`,
  - `occurrences_not_duplicated_on_remerge` (merge(merge(a,b), b) has the same findings as merge(a,b)),
  - `engagement_mismatch_errors`, `pack_version_mismatch_warns`,
  - `redact_keeps_fingerprints_and_removes_hosts` (the serialized redacted file contains none of the original host names or paths),
  - the CLI test `merge_writes_default_output`.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Commit: `Add merge and redaction of results files`.

### Task 14: Assessment — assets, deadlines, and overrides

**Files:**
- Create: `crates/pqaudit-core/src/{assets.rs,deadlines.rs,assess.rs}`
- Test: `crates/pqaudit-core/tests/{assets.rs,deadlines.rs,assess.rs}`

**Interfaces:**
- Consumes: `Engagement`, `ResultsFile`, `RulesPack`.
- Produces:
  - `assets::match_asset<'a>(assets: &'a [Asset], loc: &Location) -> Option<&'a Asset>`.
    - The first match in the file order wins.
    - Hosts: compare with `Location::Endpoint.host`, not case-sensitive.
    - IP addresses: compare with `cidrs`.
    - Paths: compare with `Location::File.path` through `globset`.
    - The asset of a finding is the match of its first occurrence that matches an asset.
  - `AssetContext { classification: Ctx<String>, data_lifespan_years: Ctx<u32>, exposure: Ctx<Exposure>, priority_tier: Ctx<Tier>, vendor: Ctx<bool>, hardware_constrained: Ctx<bool>, business_unit: Option<String>, owner: Option<String> }`, where `Ctx<T> = Assessed(T) | Unassessed`.
  - `deadlines::resolve(threat: ThreatType, tier: Ctx<Tier>, sector: Option<&str>, profiles: &[&DeadlineProfile]) -> Option<DeadlineRef { date: NaiveDate, profile_id: String, description: String, source_title: String, source_url: String }>`:
    - Use migration milestones only.
    - `applies_to.tier = High` matches when the tier is `High` or `Unassessed` (the cautious choice, spec section 7). `All` always matches.
    - If `threat_types` is not empty, it must contain the threat type of the finding.
    - `sector` must be the same as the sector of the engagement.
    - The earliest date wins. If two dates are the same, the first profile in the selection order wins.
  - `deadlines::planning(profiles) -> Vec<(String /* profile id */, Milestone)>`, for the engagement section of the report.
  - `assess::assess(results: &ResultsFile, eng: &Engagement, pack: &RulesPack, today: NaiveDate) -> Result<Assessment, AssessError>`. An unknown profile ID in `engagement.toml` → `AssessError::UnknownProfile`.
  - `Assessment { engagement: EngagementSummary, header: ResultsHeader, findings: Vec<AssessedFinding>, inventory: Vec<InventoryItem>, errors: Vec<ScanError>, planning_milestones: Vec<(String, Milestone)>, orphaned_overrides: Vec<Override>, unassessed_count: usize, assumptions: Assumptions, pack: PackRef }`.
  - `AssessedFinding { finding: Finding, rule: RuleDef, asset: Option<String>, context: AssetContext, deadline: Option<DeadlineRef>, score: ScoreBreakdown, band: Band, override_: Option<Override>, effective_band: Band, complexity: Complexity, testing: Vec<TestType> }`.
    - Task 15 fills the score and complexity fields.
    - In this task, call `scoring::score` and `complexity::assess_complexity` as stubs that return neutral values. Task 15 replaces the stubs.
  - `today` is `config.assessment_date`, or the local date if it is not set.

- [ ] **Step 1: Write the failing tests:**
  - assets: `host_match_case_insensitive`, `cidr_match`, `path_glob_match`, `first_match_wins`, `no_match_is_unassessed`.
  - deadlines: `uk_high_tier_gets_2031`, `uk_unassessed_tier_gets_2031`, `uk_standard_tier_gets_2035` (the asset `Tier` is `High | Standard`; the milestone `TierScope` is `High | All`), `au_and_uk_strictest_is_au_2030`, `planning_never_attached`, `threat_type_filter_respected` (a milestone with `threat_types = [ForgeryLongLived]` does not apply to `Hndl`), `sector_filter_respected`.
  - assess: `overrides_applied_by_fingerprint`, `orphaned_override_reported`, `unassessed_count_counts_findings_with_any_unassessed_field`, `unknown_profile_errors`.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Commit: `Add the assessment with assets, deadlines, and overrides`.

### Task 15: Scoring, complexity, necessary tests, and `explain`

**Files:**
- Create: `crates/pqaudit-core/src/{scoring.rs,complexity.rs}`, `crates/pqaudit-cli/src/commands/explain.rs`
- Test: `crates/pqaudit-core/tests/{scoring.rs,complexity.rs}`, `crates/pqaudit-cli/tests/explain.rs`

**Interfaces:**
- Produces:
  - `scoring::score(f: &Finding, ctx: &AssetContext, deadline: Option<&DeadlineRef>, complexity: &Complexity, cfg: &ScoringConfig, crqc_year: i32, today: NaiveDate) -> ScoreBreakdown`. `ScoreBreakdown { factors: Vec<FactorScore { name: &'static str, value: f64, weight: f64, contribution: f64, note: String }>, total: f64 /* 0–100 */ }`. `scoring::band(total, &cfg.bands) -> Band`.
  - Factor values (exact):
    - `threat`: Hndl 1.0, ForgeryLongLived 0.8, ClassicalWeakNow 1.0, ForgeryShortLived 0.3.
    - `exposure`: Internet 1.0, Partner 0.7, Internal 0.4, Isolated 0.2, Unassessed 1.0.
    - `sensitivity`: `cfg.classification[class]`. Unassessed or an unknown class → 1.0. An unknown class also adds a note.
    - `mosca`: `lifespan` is the data lifespan (Unassessed → 25). For ForgeryLongLived with a certificate, use `max(lifespan, years until not_after)`. `margin = lifespan + complexity.migration_years − (crqc_year − today.year)`. `value = 1.0 if margin ≥ 0, else max(0, 1 + margin / 10)`.
    - `deadline`: no deadline → 0.0. `years_left = (deadline − today).days / 365.25`. `value = 1.0 if years_left ≤ 0, else clamp(1 − years_left / 10, 0, 1)`.
    - `scale`: `n` is the number of occurrences. `value = min(1, log10(n + 1) / 2)`.
    - `total = 100 × Σ(weight × value) / Σ(weight)`.
  - `complexity::assess_complexity(f: &Finding, rule: &RuleDef, ctx: &AssetContext, cfg: &ScoringConfig) -> Complexity`. `Complexity { change_type: ChangeType, size: Size /* S, M, L, XL */, migration_years: f64, reasons: Vec<String> /* STE, from messages.rs */ }`.
    - Change type: start with `rule.change_type`.
      - Change it to `ProtocolPartner` for certificates with `is_ca`.
      - Change it to `Hardware` if `hardware_constrained = Assessed(true)`.
      - Change it to `Vendor` if `vendor = Assessed(true)`.
      - The highest value wins, in the order of spec section 10.3.
    - Size: Config S, LibraryUpgrade M, CodeChange M, ProtocolPartner L, Hardware XL, Vendor XL.
      - Add one size (maximum XL) if `exposure = Partner` or if `rule.size_impact.len() ≥ 2`.
    - `migration_years` comes from `cfg.migration_years[size]`.
  - `complexity::testing_scope(rule: &RuleDef, ctx: &AssetContext) -> Vec<TestType>` = `rule.testing`, plus these items:
    - Interop if the exposure is Partner,
    - Certification if `rule.testing` contains it or if the classification of the asset maps to 0.7 or more.
  - Replace the stubs from Task 14 with these functions.
  - `explain <FINDING-ID> [--results <FILE>]` (default `<engagement>/results/merged.pqr`). It shows:
    - the rule title and description,
    - the evidence of each occurrence,
    - the threat type,
    - the context (with unassessed fields marked),
    - the deadline and its source,
    - the CWE and ATT&CK IDs,
    - each score factor (value × weight = contribution, and the note),
    - the total and the band,
    - the override,
    - the complexity and its reasons,
    - the necessary tests,
    - the remediation.
  - An unknown ID → exit 1.

- [ ] **Step 1: Write the failing tests** in `scoring.rs`. Use `today = 2026-10-20`, `crqc_year = 2035`, and the default settings.
  - `all_max_scores_100`: Hndl, Internet, secret, lifespan 25, deadline 2026-01-01, and 99 occurrences → `total == 100.0`.
  - `worked_example`: Hndl, Internal, `confidential`, lifespan 5, complexity M (0.5), deadline `2030-12-31`, 1 occurrence.
    - The Mosca margin is 5 + 0.5 − 9 = −3.5 → 0.65.
    - The deadline `years_left` is about 4.2 → about 0.58.
    - The scale is log10(2)/2 ≈ 0.1505.
    - The total is `100 × (0.25×1 + 0.20×0.4 + 0.20×0.7 + 0.15×0.65 + 0.10×0.58 + 0.10×0.1505) ≈ 64.06`.
    - Check that the total is in the range ±0.2, and that the band is High.
  - `unassessed_is_conservative_and_noted`.
  - `bands_boundaries`: 80 → Critical, 79.99 → High, 60 → High, 40 → Medium, 39.99 → Low.
  - `custom_weights_used`.
- [ ] **Step 2: Write the failing tests** in `complexity.rs`: `tls_no_pq_kex_is_m`, `ca_cert_is_l_protocol_partner`, `vendor_asset_is_xl`, `partner_exposure_bumps_size_and_adds_interop`, `reasons_non_empty`.
- [ ] **Step 3:** Write the CLI tests `explain_shows_factor_breakdown` (stdout contains the name of each factor and the total) and `explain_unknown_id_exits_1`.
- [ ] **Step 4:** Run the tests. Expected result: FAIL.
- [ ] **Step 5:** Write the code.
- [ ] **Step 6:** Run the tests. Expected result: PASS. Run `cargo xtask strings`, then `vale target/ste/messages.md`. Expected result: 0 errors.
- [ ] **Step 7:** Commit: `Add scoring, complexity, necessary tests, and the explain command`.

### Task 16: Technical report

**Files:**
- Create: `crates/pqaudit-report/src/{lib.rs,technical.rs,messages.rs}`, `crates/pqaudit-report/src/templates/{technical.html,technical.md.j2}`, `crates/pqaudit-cli/src/commands/report.rs`
- Test: `crates/pqaudit-report/tests/technical.rs`, `crates/pqaudit-cli/tests/report.rs`

**Interfaces:**
- Consumes: `Assessment`.
- Produces: `technical::render(a: &Assessment, format: Format /* Html, Md, Json */) -> Result<String, ReportError>`.
  - Sections, in this order (spec section 12.2):
    1. title block (client, assessor, date, tool version and pack version),
    2. method,
    3. scope and coverage (runs, scope hash, audit log hash, number of errors),
    4. assumptions (CRQC year, profiles, planning milestones with their sources),
    5. summary: the number of findings in each effective band,
    6. findings, in order of effective band, then of total (highest first),
    7. "Fix now (not quantum)" (all `ClassicalWeakNow` findings),
    8. items that are already ready for post-quantum cryptography,
    9. questions for vendors (findings with `vendor = Assessed(true)`; one STE question for each finding, from the remediation of the rule),
    10. overrides log (original band, override, reason, person, date),
    11. orphaned overrides,
    12. risk register appendix: a table with these columns:
        - fingerprint, title,
        - likelihood factors (exposure, threat, classical weakness),
        - impact factors (classification, lifespan, scale),
        - suggested band, and effective band.
  - HTML is one file. It has inline CSS.
    - It has no `<script src>`, no `<link>`, and no external URLs, except source links as plain `<a>` text.
    - It includes a print stylesheet.
  - JSON is the `serde_json` serialization of `Assessment`.
  - `report --audience technical --format html|md|json [--results <FILE>] [--output <FILE>]`. The default output is `<engagement>/reports/technical.<ext>`. `--audience board` or `--format pdf` → exit 1 with `messages::LATER_RELEASE`.

- [ ] **Step 1: Write the failing tests.** Make an `Assessment` fixture in the test.
  - The fixture has 3 findings (one for each threat type, with one ClassicalWeakNow), one vendor asset, and one override.
  - It also has one orphaned override, and one endpoint that is ready for post-quantum cryptography.
  - `html_is_self_contained`: no `<script src`, `<link`, `@import`, or `url(http`.
  - `sections_in_order`: the positions of the headings increase, in the order above.
  - `fix_now_lists_classical_weak`, `vendor_questions_present`, `overrides_log_shows_reason`, `risk_register_has_row_per_finding`.
  - `unassessed_marked`: the report shows the word "Unassessed" for unassessed fields.
  - `md_and_json_render`.
  - CLI tests: `report_board_exits_1_later_release`, `report_pdf_exits_1_later_release`, `report_writes_default_path`.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code with `minijinja` (load the templates with `include_str!`). Write all fixed text in STE.
- [ ] **Step 4:** Run the tests. Expected result: PASS. Run `vale crates/pqaudit-report/src/templates/`. Expected result: 0 errors.
- [ ] **Step 5:** Commit: `Add the technical report in HTML, Markdown, and JSON`.

### Task 17: CycloneDX CBOM

**Files:**
- Create: `crates/pqaudit-report/src/cbom.rs`, `crates/pqaudit-cli/src/commands/cbom.rs`, `crates/pqaudit-report/tests/schema/` (copies of the CycloneDX 1.6 files `bom-1.6.schema.json`, `spdx.schema.json`, and `jsf-0.82.schema.json`, with their source URLs in a README)
- Test: `crates/pqaudit-report/tests/cbom.rs`

**Interfaces:**
- Consumes: `Assessment` (findings + inventory), `RulesPack::algorithm`.
- Produces: `cbom::render(a: &Assessment, pack: &RulesPack) -> serde_json::Value`.
  - Top level: `bomFormat: "CycloneDX"`, `specVersion: "1.6"`, `serialNumber: urn:uuid`, `metadata.tools` = pqaudit and its version, `metadata.component` = the engagement client.
  - Components:
    - One `cryptographic-asset` with `assetType: "algorithm"` for each different algorithm (remove duplicates by name + parameter set).
      - It has `oid`, `primitive` (`pke`, `kem`, `signature`, `key-agree`, `hash`, `block-cipher`), and `parameterSetIdentifier` (key bits or curve).
      - It has `nistQuantumSecurityLevel` (from the pack; 0 for classical algorithms).
    - One `assetType: "certificate"` for each certificate: `subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `subjectPublicKeyRef`, `certificateFormat: "X.509"`. The `bom-ref` is the fingerprint.
    - One `assetType: "related-crypto-material"` for each key: `type: "public-key"` or `"private-key"`, `algorithmRef`, `size`. Never include key bytes.
    - One `assetType: "protocol"` for each endpoint: `type: "tls"` or `"ssh"`, `version`, and `cipherSuites` with `algorithms` references.
  - Services: one for each endpoint. `name` = host:port. `endpoints` = [`https://host:port`] or [`ssh://host:port`].
  - `dependencies`: each service → its protocol and certificates. Each certificate → its algorithms. Each file location is a `properties` entry `pqaudit:location`.
  - `cbom [--results <FILE>] [-o <FILE>]`. The default output is `<engagement>/reports/cbom.cdx.json`.

- [ ] **Step 1: Write the failing tests:**
  - `cbom_validates_against_cyclonedx_1_6` (jsonschema with the copied schema files)
  - `algorithm_components_deduped`
  - `cert_component_refs_algorithms`
  - `endpoint_service_depends_on_protocol_and_cert`
  - `pq_algorithm_has_level_3` (ML-DSA-65 → `nistQuantumSecurityLevel: 3`)
  - `no_key_bytes_in_cbom`: use the private-key fixtures from Task 9.
    - Do scan → merge → assess → cbom.
    - No 16-byte window of a private key is in the result.
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write the code.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Commit: `Add the CycloneDX 1.6 CBOM`.

### Task 18: End-to-end engagement test

**Files:**
- Test: `crates/pqaudit-cli/tests/e2e.rs`

**Interfaces:**
- Consumes: all commands.

- [ ] **Step 1: Write the test** `full_stage1_engagement`. It does these steps:
  1. `init`.
  2. Set `engagement.toml` (profiles `["au","uk"]`, `crqc_year = 2035`, `assessment_date = 2026-10-20`) and `assets.toml` (one asset that matches `127.0.0.1` and the fixtures path).
  3. Start a TLS server (classical only) and a fake SSH server in the same process, on `127.0.0.1`.
  4. Write a `scope.toml` that targets them, with `allowed_cidrs = ["127.0.0.0/8"]`, and test limits below the defaults.
  5. Run `scan net --dry-run` (exit 0), `scan net`, `scan files` on the fixtures, `merge`, `report --format html`, `report --format json`, `cbom`, and `explain <first id>`.
  - Check these results:
    - Each command exits with 0. (Exit 3 is correct only where the fixtures include errors on purpose.)
    - The audit log has one line for each connection.
    - The findings in the JSON report include `tls.no-pq-kex`, with the deadline `2030-12-31` from the profile `au`.
    - The CBOM is valid.
    - The HTML report contains all its content.
- [ ] **Step 2:** Run `cargo test -p pqaudit-cli --test e2e`. Expected result: PASS.
  - If an integration problem occurs, repair it in the crate that owns the code.
  - Add a regression test in that crate.
- [ ] **Step 3:** Commit: `Add the end-to-end test for Stage 1`.

### Task 19: Documents

**Files:**
- Create: `README.md`, `docs/user-guide.md`, `docs/verifying.md`, `.github/release-notes-template.md`
- Test: the CI `ste` job

**Interfaces:**
- Consumes: the final CLI (Tasks 1–17), and the release pipeline design (Task 20).
  - Write `verifying.md` with the commands that Task 20 lists.
  - Task 20 Step 6 checks them again.

Content (all in STE):

- `README.md`:
  - what pqaudit does (2 paragraphs),
  - installation (download, and a link to the verification steps),
  - quick start (the workflow in spec section 5, with Stage 1 commands only),
  - **"Trusting pqaudit in your environment"**:
    - the scope model, the gentle defaults, the audit log,
    - offline modes that open no sockets,
    - private keys that the tool never copies,
    - signed releases, the SBOM, the CBOM,
    - a link to `docs/verifying.md`,
  - a summary of the safety model (spec section 8, items 1 to 8),
  - the limits of Stage 1 (no code scan, no board report, no PDF yet),
  - the licence.
- `docs/user-guide.md`:
  - the engagement folder,
  - each key of each TOML file,
  - each command and flag (the same text as the CLI help),
  - exit codes,
  - how to read the technical report,
  - how the tool calculates the score:
    - the table and formula in spec section 10.2,
    - the worked example from Task 15,
  - how the tool selects deadlines (the rule in spec section 13),
  - overrides, redaction, and rules packs (`rules list/verify/update`, and the warning for unsigned packs).
- `docs/verifying.md` — "Verifying this release":
  - `gh attestation verify <file> --repo <org>/pqaudit`,
  - `cosign verify-blob <file> --bundle <file>.sigstore.json --certificate-identity-regexp '^https://github.com/<org>/pqaudit/.github/workflows/release.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com`,
  - steps without a network connection:
    - copy the bundle and `trusted_root.json`,
    - get a current `trusted_root.json` from Sigstore TUF before you go offline,
    - use the pinned cosign version,
    - use the `--trusted-root` flag,
  - the check of the hybrid post-quantum signature: the two `openssl pkeyutl -verify` commands on `SHA256SUMS`, then `sha256sum -c`,
  - Windows: `Get-AuthenticodeSignature`,
  - macOS: `codesign --verify --deep --strict` and `spctl --assess`,
  - the SBOM location, and how to compare it with the `cargo auditable` data (`rust-audit-info <binary>`),
  - the location of the CBOM of the tool,
  - the check of a rules pack,
  - an appendix for maintainers: the manual signing steps of Task 20.
- `.github/release-notes-template.md`: sections Changes, Rules pack version, Verifying this release (short form and a link), and Known limits.

- [ ] **Step 1:** Write the four files.
- [ ] **Step 2:** Make sure that the user guide has each command. Run `cargo xtask strings`.
  - Add the test `docs_mention_every_flag` to `xtask/tests/strings.rs`: each long flag in `cli-help.md` is in `docs/user-guide.md`.
  - Run the test. Expected result: PASS.
- [ ] **Step 3:** Run `vale README.md docs/ .github/release-notes-template.md`. Expected result: 0 errors.
- [ ] **Step 4:** Commit: `Add the README, the user guide, and the release verification guide`.

### Task 20: Release pipeline, CBOM of the tool, and production keys

**Files:**
- Create: `.github/workflows/release.yml`, `docs/self-crypto.toml`, `xtask/src/{self_cbom.rs,sign_release.rs}`
- Change: `rules/trust/keys.toml` (the production key for packs), `rules/algorithms.yaml` (add `crypto_crates`), `Cargo.toml` (`[profile.release]` with `lto = true`, `codegen-units = 1`, `strip = true`)
- Test: `xtask/tests/self_cbom.rs`

**Interfaces:**
- `docs/self-crypto.toml`:
  - `[[use]] purpose = "tls-probe" algorithms = ["X25519MLKEM768", "X25519", "P-256", "P-384", "RSA", "ECDSA", "Ed25519"] crates = ["aws-lc-rs"]`
  - `[[use]] purpose = "rules-pack-verify" algorithms = ["Ed25519", "ML-DSA-65"] crates = ["ed25519-dalek", "ml-dsa"]`
  - `[[use]] purpose = "fingerprints" algorithms = ["SHA-256"] crates = ["sha2"]`
- `cargo xtask self-cbom --sbom <sbom.json> --out <cbom.json>`:
  - It fails if a crate in the SBOM is in the `crypto_crates` list in `algorithms.yaml` but not in `self-crypto.toml`.
    - The list:
      - aws-lc-rs, aws-lc-sys, ring, rustls,
      - ed25519-dalek, ml-dsa, sha2, sha1, md-5,
      - rsa, p256, p384, x25519-dalek, ml-kem.
  - It fails if `self-crypto.toml` declares a crate that is not in the SBOM.
  - Else it writes a CycloneDX 1.6 CBOM with the `pqaudit_report::cbom` helpers. The CBOM lists the declared algorithms for each purpose.
- `cargo xtask sign-release --keys <dir> --dir <downloaded-release-dir>`:
  - It checks the Sigstore bundle of each file with `cosign verify-blob`. It fails if a bundle is missing.
  - It writes `SHA256SUMS` and `SHA3-256SUMS` if they are not there.
  - It hybrid-signs the two checksum files (`.sig.json`, `.ed25519.sig`, `.mldsa65.sig`).
- `release.yml`, on tags `v*`, with `permissions: { contents: write, id-token: write, attestations: write }`:
  1. Build matrix: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (cargo-zigbuild), `x86_64-apple-darwin` and `aarch64-apple-darwin` (then `lipo` → universal), `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc`.
     - If aws-lc-rs does not build for Windows arm64, remove that target and add a comment.
     - All builds use `cargo auditable build --release --locked`.
  2. macOS: `codesign --options runtime --timestamp` with Developer ID, then `xcrun notarytool submit --wait`.
     - Windows: `signtool sign /fd SHA256 /tr <timestamp> /td SHA256`.
     - Each step runs only if its secrets exist. If not, the job writes a warning and continues.
  3. SBOM: `cargo cyclonedx --format json --spec-version 1.6` for `pqaudit-cli`.
  4. CBOM of the tool: `cargo xtask self-cbom`.
  5. `actions/attest-build-provenance` for each binary. `actions/attest-sbom` with the SBOM for each binary.
  6. `cosign sign-blob --yes --bundle <file>.sigstore.json <file>` for each binary, the SBOM, the CBOM, and the rules pack archive.
  7. `cargo xtask pack-rules`. Attach the archive without a hybrid signature. The maintainers sign it offline (item 9).
  8. Make a **draft** release from `.github/release-notes-template.md`, with all the files.
  9. Manual step (the maintainer appendix in `docs/verifying.md` describes it):
     - A maintainer downloads the draft and runs `cargo xtask sign-release`.
     - The maintainer runs `cargo xtask sign` on the rules archive with the offline keys.
     - Then the maintainer uploads the signature files and publishes the release.

- [ ] **Step 1: Write the failing tests** in `self_cbom.rs`: `undeclared_crypto_crate_fails`, `declared_but_absent_crate_fails`, and `valid_declaration_writes_cbom` (validate it against the CycloneDX 1.6 schema from Task 17).
- [ ] **Step 2:** Run the tests. Expected result: FAIL.
- [ ] **Step 3:** Write `self_cbom.rs`, `sign_release.rs`, and `release.yml`.
- [ ] **Step 4:** Run the tests. Expected result: PASS.
- [ ] **Step 5:** Ask the human two questions:
  - Who keeps the production offline keys?
  - Do the Apple and Windows signing secrets exist?
  - Make the production keys for packs with `cargo xtask keygen` on the computer of the key keeper.
  - Replace the development key in `rules/trust/keys.toml`. Run `cargo test --workspace` again.
- [ ] **Step 6:** Check the pipeline.
  - Push the tag `v0.1.0-rc.1` to the repository (or to a fork). All release jobs must pass.
  - Download one Linux binary. Run each command in `docs/verifying.md` on it:
    - `gh attestation verify`,
    - `cosign verify-blob` with and without a network connection,
    - the two `openssl pkeyutl -verify` commands (after item 9),
    - `sha256sum -c SHA256SUMS`.
  - If a command fails, repair the document or the workflow.
- [ ] **Step 7:** Commit: `Add the signed release pipeline, the SBOM, the provenance, and the CBOM of the tool`.
