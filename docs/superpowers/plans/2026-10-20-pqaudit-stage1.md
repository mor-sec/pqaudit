# pqaudit Stage 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship pqaudit Stage 1 — a signed, single-binary CLI that scans certificates/keys on disk and TLS/SSH endpoints within a strict scope, scores findings, and emits a technical report and a CycloneDX CBOM.

**Architecture:** Cargo workspace. Scanners write portable `.pqr` results files; `merge` combines them; an assessment step joins results with customer context (assets, deadlines, overrides, scoring weights) and feeds the report and CBOM renderers. Detection facts, rule text, and deadline profiles live in a hybrid-signed rules pack; a default pack is embedded in the binary.

**Tech Stack:** Rust (stable, pinned), clap 4, serde/serde_json/toml/serde_yaml, schemars, chrono, tracing, tokio + tokio-rustls + rustls (aws-lc-rs provider), x509-parser, p12-keystore, ssh-key, pgp (rPGP), pkcs8/pkcs1, zeroize, ipnet, globset, walkdir, zstd, tar, ed25519-dalek, ml-dsa (RustCrypto), minijinja, include_dir, jsonschema (tests), assert_cmd + predicates (tests), Vale (docs lint).

**Spec:** `docs/superpowers/specs/2026-10-20-pqaudit-design.md` — Stage 1 is defined in §18. Read the spec sections cited in each task.

## Global Constraints

- Platforms: Linux x86_64 + aarch64 (static musl), macOS universal (x86_64 + arm64), Windows x86_64 (+ arm64 if the toolchain allows).
- Rust toolchain pinned in `rust-toolchain.toml` to the stable version current when Task 1 runs; `Cargo.lock` committed; CI builds with `--locked`.
- Licence: `Apache-2.0 OR MIT`.
- **All user-facing text is ASD-STE100 Simplified Technical English (spec §19):** CLI help and every flag description, messages, `init` template comments, report fixed text, rules-pack text, README and docs. Procedural sentences ≤ 20 words, descriptive ≤ 25, paragraphs ≤ 6 sentences, active voice, one instruction per sentence. Technical names (algorithm, file, command and flag names) are allowed.
- User-facing strings live in one `messages.rs` per crate, registered in a `pub const ALL: &[(&str, &str)]` (id, text) so the STE lint can extract them. clap help comes from doc comments and is extracted by rendering help.
- Exit codes: `0` success, `1` error, `2` scope/safety refusal, `3` partial results.
- Offline scanner crates (`pqaudit-scan-files`) must not depend on tokio, rustls, hyper, reqwest, socket2, or any networking crate, and must open no sockets.
- Private key material is never written to results, logs, reports, or error messages.
- Network defaults (spec §8) are maximums unless `override_limits = true` in `scope.toml`: global concurrency 4, per-host 1, min 1000 ms between connections to the same host, ≤ 3 TLS handshakes per port, 1 connection per SSH port, connect timeout 5000 ms, read timeout 10000 ms, 0 retries.
- Hybrid signatures: Ed25519 (pure) + ML-DSA-65 (pure ML-DSA, FIPS 204, empty context string), both over the raw file bytes; both must verify. Keys are PKCS#8 / SPKI PEM so OpenSSL 3.5+ can verify.
- Dates written as "by YEAR" in a source are stored as `YEAR-12-31`.
- Stage 1 deadline profiles: `us`, `uk`, `au` only.
- `report --audience board` and PDF output are Stage 3: they must exit `1` with an STE message that says the feature is in a later release.

## Review Focus

1. **Hostile or malformed files** (truncated DER, garbage named `.pem`, a 2 GB file, a PEM with 10 000 blocks) → the file is recorded as a scan error with a reason, the scan continues, no panic, bounded memory. Test: Task 7 `malformed_inputs_are_errors_not_panics`.
2. **Hostile network peers** (server that sends banner lines forever, a giant SSH packet length, a server that accepts TCP and never speaks) → probe ends at the read timeout or size cap, records an error, no OOM. Tests: Task 11 `silent_server_times_out`, Task 12 `endless_banner_is_capped`, `oversized_packet_is_rejected`.
3. **A hostname that resolves to an address outside the allowed CIDRs, or to several addresses where one is outside** → the whole scan refuses before any connection, exit 2, and dry-run shows the reason. Test: Task 10 `one_bad_resolved_ip_refuses_whole_scan`.
4. **Private keys inside containers** (unencrypted PKCS#8, PKCS#12 key bags, JKS private-key entries, OpenSSH private keys, and parse errors on key files) → nothing from the private key appears in the `.pqr`, logs, or error text. Tests: Task 8 `keystore_private_material_not_in_results`, Task 9 `private_key_material_never_in_results`.
5. **Unreadable paths** (permission denied, symlink loop, non-UTF-8 file name, path that disappears mid-scan) → recorded as a scan error, exit 3, other files still scanned. Test: Task 7 `unreadable_paths_give_partial_exit_3`.

---

## File Structure

```
Cargo.toml                      workspace
rust-toolchain.toml
LICENSE-APACHE, LICENSE-MIT
README.md                       STE; includes "Trusting pqaudit in your environment"
docs/user-guide.md              STE
docs/verifying.md               STE; "Verifying this release"
docs/style/ste.md               contributor STE guide
docs/self-crypto.toml           declaration of algorithms the binary uses (self-CBOM)
schema/pqr.schema.json          generated, committed
.vale.ini, .github/vale/STE/*.yml
.github/workflows/ci.yml, release.yml
.github/release-notes-template.md   STE
rules/                          default rules pack (embedded)
  pack.toml
  algorithms.yaml
  rules/certs.yaml, keys.yaml, tls.yaml, ssh.yaml
  profiles/us.yaml, uk.yaml, au.yaml
  trust/keys.toml               trusted pack-signing public keys + revoked IDs
crates/pqaudit-core/src/
  lib.rs, messages.rs
  finding.rs        Finding, enums, Occurrence, Location, CertInfo, KeyInfo, EndpointInfo
  fingerprint.rs    Fingerprint + constructors
  results.rs        ResultsFile (.pqr), header, read/write, zstd
  engagement.rs     EngagementConfig, AssetsFile, OverridesFile, ScoringConfig parsing
  assets.rs         asset matching
  deadlines.rs      milestone resolution
  assess.rs         Assessment pipeline
  scoring.rs        score + bands
  complexity.rs     change type → size, testing scope
  merge.rs          merge + redact
  classify.rs       certificate classification (shared by both scanners)
crates/pqaudit-rules/src/
  lib.rs, messages.rs
  pack.rs           RulesPack, RuleDef, AlgorithmFact, DeadlineProfile, Milestone
  embedded.rs       embedded default pack
  verify.rs         hybrid signature, rotation chain, revocation
  install.rs        user data dir install + active pack selection
crates/pqaudit-scan-files/src/
  lib.rs, messages.rs, walk.rs, cert.rs, pkcs12.rs, jks.rs, ssh.rs, privkey.rs, gpg.rs
crates/pqaudit-scan-net/src/
  lib.rs, messages.rs
  scope.rs          ScopeFile parse, plan building, enforcement
  runtime.rs        limiter, allowed_hours, orchestration
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

### Task 1: Workspace scaffold and CLI skeleton

**Files:**
- Create: `Cargo.toml`, `rust-toolchain.toml`, `LICENSE-APACHE`, `LICENSE-MIT`, `.gitignore`, all crate `Cargo.toml` + `lib.rs`/`main.rs` stubs, `crates/pqaudit-cli/src/{main.rs,cli.rs,exit.rs,messages.rs}`, `xtask/`, `.github/workflows/ci.yml`
- Test: `crates/pqaudit-cli/tests/cli_basics.rs`

**Interfaces:**
- Produces: `pqaudit_cli::exit::ExitCode { Success = 0, Error = 1, Refused = 2, Partial = 3 }`; `cli::Cli` with global flags `--engagement <DIR>` (default `.`), `--quiet`, `--verbose`, `--log-format text|json`, `--no-color`, `--allow-unsigned-rules`; subcommand enum with stubs for `init, scan files, scan net, merge, report, cbom, explain, rules, profiles` that each return `ExitCode::Error` with message `messages::NOT_IMPLEMENTED` until their task lands. Every crate has `messages.rs` exporting `pub const ALL: &[(&str, &str)]`.

- [ ] **Step 1:** If `cargo` is missing, install rustup (`curl https://sh.rustup.rs -sSf | sh -s -- -y`), then write `rust-toolchain.toml` pinning the version from `rustc --version` plus targets listed in Global Constraints.
- [ ] **Step 2: Write failing tests** in `cli_basics.rs` with `assert_cmd`:
  - `version_prints_name`: `pqaudit --version` succeeds, stdout starts with `pqaudit `.
  - `help_lists_stage1_commands`: `pqaudit --help` stdout contains each of `init`, `scan`, `merge`, `report`, `cbom`, `explain`, `rules`, `profiles`.
  - `unknown_command_exits_1`: `pqaudit frobnicate` exit code 1 (map clap usage errors to 1, not clap's default 2, because 2 means refusal).
- [ ] **Step 3:** Run `cargo test -p pqaudit-cli` → FAIL (no binary).
- [ ] **Step 4:** Implement workspace, clap derive CLI, tracing-subscriber init from `--log-format`/`--verbose`/`--quiet`, exit-code mapping. Flag doc comments in STE (example: `/// Show the targets that the scan will connect to. Do not connect to the targets.`).
- [ ] **Step 5:** Add `ci.yml`: jobs `fmt` (`cargo fmt --check`), `clippy` (`cargo clippy --workspace --all-targets --locked -- -D warnings`), `test` on ubuntu/macos/windows (`cargo test --workspace --locked`).
- [ ] **Step 6:** Run `cargo test --workspace` → PASS; `cargo clippy --workspace --all-targets -- -D warnings` → clean.
- [ ] **Step 7:** Commit `chore: scaffold workspace and CLI skeleton`.

### Task 2: STE tooling

**Files:**
- Create: `docs/style/ste.md`, `.vale.ini`, `.github/vale/STE/{SentenceLength.yml,ProceduralLength.yml,ParagraphLength.yml,Passive.yml,Words.yml}`, `xtask/src/strings.rs`
- Modify: `.github/workflows/ci.yml` (add `ste` job)
- Test: `xtask/tests/strings.rs`, `.github/vale/fixtures/{good.md,bad.md}`

**Interfaces:**
- Consumes: every crate's `messages::ALL`; `pqaudit_cli::cli::Cli` (via `clap::CommandFactory`).
- Produces: `cargo xtask strings --out target/ste` writes `target/ste/cli-help.md` (long help of every command and subcommand), `target/ste/messages.md` (all `messages::ALL` texts, one paragraph each), `target/ste/rules-text.md` (title/description/remediation of every rule and milestone description in `rules/`, once Task 3 exists — skip silently if absent). Later tasks add their text to these sources; the lint picks it up automatically.

- [ ] **Step 1: Write failing test** `strings_extracts_help_and_messages`: run `cargo xtask strings --out <tmp>`; assert `cli-help.md` contains the `--engagement` flag description and `messages.md` contains the text of `pqaudit_cli::messages::NOT_IMPLEMENTED`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `strings.rs`.
- [ ] **Step 4:** Write Vale rules: `SentenceLength` (error, > 25 words, scope sentence), `ProceduralLength` (error, > 20 words, scope list items), `ParagraphLength` (error, `occurrence` max 6 sentence ends per paragraph), `Passive` (error, `be`-verb + past participle pattern), `Words` (substitution, project word list from `docs/style/ste.md`, e.g. `utilize→use`, `ensure→make sure`, `perform→do`, `in order to→to`). Do not copy ASD dictionary content into the repo (spec §19). `docs/style/ste.md` in STE: rules summary, project technical-names list (algorithm names, file names, command names), and 5 before/after examples.
- [ ] **Step 5:** Fixtures: `bad.md` with one violation per rule; `good.md` clean. Verify: `vale .github/vale/fixtures/bad.md` reports exactly 5 alerts, one per rule; `vale .github/vale/fixtures/good.md` reports 0.
- [ ] **Step 6:** CI `ste` job: install pinned Vale, run `cargo xtask strings --out target/ste`, then `vale README.md docs/ target/ste/ crates/pqaudit-report/src/templates/ crates/pqaudit-cli/src/templates/ .github/release-notes-template.md` (skip missing paths).
- [ ] **Step 7:** Run xtask test → PASS. Commit `chore: add STE style guide, Vale rules and string extraction`.

### Task 3: Rules pack format, embedded default pack, profiles command

**Files:**
- Create: `crates/pqaudit-rules/src/{pack.rs,embedded.rs}`, `rules/pack.toml`, `rules/algorithms.yaml`, `rules/rules/{certs,keys,tls,ssh}.yaml`, `rules/profiles/{us,uk,au}.yaml`, `crates/pqaudit-cli/src/commands/profiles.rs`
- Test: `crates/pqaudit-rules/tests/pack.rs`, `crates/pqaudit-cli/tests/profiles.rs`

**Interfaces:**
- Produces (in `pqaudit_rules::pack`):
  - `RulesPack { id: String, version: semver::Version, rules: Vec<RuleDef>, algorithms: Vec<AlgorithmFact>, profiles: Vec<DeadlineProfile>, content_hash: String /* sha256 hex over canonical file list */ }`
  - `RuleDef { id: String, family: String, aliases: Vec<String>, title: String, description: String, remediation: String, threat_type: Option<ThreatType> /* None = derived by scanner */, cwe: Vec<String>, attack: Vec<String>, change_type: ChangeType, size_impact: Vec<SizeImpact>, testing: Vec<TestType> }`
  - `AlgorithmFact { name: String, oid: Option<String>, primitive: Primitive /* Pke, Kem, Signature, KeyAgree, Hash, Cipher */, quantum_vulnerable: bool, nist_quantum_level: u8, weak_below_bits: Option<u32>, weak_always: bool }`
  - `DeadlineProfile { id: String, name: String, milestones: Vec<Milestone> }`, `Milestone { date: NaiveDate, kind: MilestoneKind /* Planning | Migration */, applies_to: AppliesTo { tier: Option<TierScope /* High | All */>, threat_types: Vec<ThreatType>, sector: Option<String> }, description: String, source_title: String, source_url: String, as_of: NaiveDate }`
  - `RulesPack::load_dir(path: &Path) -> Result<RulesPack, PackError>`, `RulesPack::rule(&self, id_or_alias: &str) -> Option<&RuleDef>`, `RulesPack::algorithm(&self, name: &str) -> Option<&AlgorithmFact>`
  - `pqaudit_rules::embedded::default_pack() -> &'static RulesPack` (via `include_dir!("$CARGO_MANIFEST_DIR/../../rules")`, parsed once with `OnceLock`)
  - Shared enums `ThreatType { Hndl, ForgeryLongLived, ForgeryShortLived, ClassicalWeakNow }`, `ChangeType { Config, LibraryUpgrade, CodeChange, ProtocolPartner, Hardware, Vendor }`, `SizeImpact { CertChain, Mtu, StorageField }`, `TestType { Unit, Integration, Interop, Performance, Certification }`, `Tier { High, Standard }` (asset tier), `TierScope { High, All }` (milestone scope) live in `pqaudit-rules` and are re-exported by `pqaudit-core`.
- Stage 1 rule IDs (exact): `cert.classical-key`, `cert.weak-key`, `cert.weak-sig-hash`, `key.classical`, `key.weak`, `tls.no-pq-kex`, `tls.legacy-version`, `ssh.no-pq-kex`, `ssh.weak-kex`, `ssh.classical-hostkey`. Change types: `cert.*` → `Config` (scanner raises CA certs to `ProtocolPartner`, Task 15), `key.*` → `Config`, `tls.no-pq-kex` → `LibraryUpgrade`, `tls.legacy-version` → `Config`, `ssh.no-pq-kex` → `LibraryUpgrade`, `ssh.weak-kex` → `Config`, `ssh.classical-hostkey` → `LibraryUpgrade`. CWE: classical-key/no-pq-kex/classical-hostkey → `CWE-327`; weak-key → `CWE-326`; weak-sig-hash → `CWE-328`; legacy-version/weak-kex → `CWE-327`. ATT&CK: `tls.*`/`ssh.*-kex` → `T1040`, `T1557`; `key.*` → `T1552.004`.
- `profiles list` prints `id  name  milestones-count`; `profiles show <id>` prints each milestone: date, kind, applies_to, description, source title + URL, as-of. Unknown id → exit 1.

- [ ] **Step 1: Write failing tests** in `pack.rs`:
  - `embedded_pack_loads`: `default_pack()` has the 10 rule IDs above and profiles `us`, `uk`, `au`.
  - `rule_lookup_by_alias`: a test pack dir with a rule aliased `old.id` resolves via `rule("old.id")`.
  - `uk_profile_milestones`: `uk` has planning `2028-12-31`, migration tier High `2031-12-31`, migration tier All `2035-12-31`.
  - `au_profile_milestone`: `au` has migration tier All `2030-12-31`.
  - `us_profile_milestones`: migration tier All `2030-12-31` (NIST IR 8547 deprecation) and `2035-12-31` (disallowed).
  - `every_milestone_has_source_and_as_of`: all milestones have non-empty `source_url` starting `https://` and `as_of`.
  - `rsa_weak_below_2048`: `algorithm("RSA").weak_below_bits == Some(2048)`; `algorithm("SHA-1").weak_always`.
  - `bad_yaml_is_error_with_file_name`: a pack with invalid YAML → `PackError` whose message names the file.
- [ ] **Step 2:** Run `cargo test -p pqaudit-rules` → FAIL.
- [ ] **Step 3:** Implement `pack.rs`, `embedded.rs`, author YAML. `algorithms.yaml` covers at least: RSA, DSA, DH, ECDSA, ECDH, Ed25519, Ed448, X25519, X448, ML-KEM-512/768/1024, ML-DSA-44/65/87, SLH-DSA (all param sets as one fact family), X25519MLKEM768, SecP256r1MLKEM768, SHA-1, MD5, SHA-256/384/512, 3DES. All rule text in STE.
- [ ] **Step 4:** Verify profile data: open each `source_url` (NIST IR 8547 page, NCSC "Timelines for migration to post-quantum cryptography", ASD "Planning for post-quantum cryptography"), confirm each date and wording, record whether IR 8547 is draft or final in the description, set `as_of` to the date you checked. If a source disagrees with the test values, stop and report to the human before changing tests.
- [ ] **Step 5:** Write failing CLI tests `profiles_list_shows_three`, `profiles_show_uk`, `profiles_show_unknown_exits_1`; implement `commands/profiles.rs`.
- [ ] **Step 6:** Run `cargo test -p pqaudit-rules -p pqaudit-cli` → PASS; `cargo xtask strings` now emits `rules-text.md`; `vale target/ste/rules-text.md` → 0 errors.
- [ ] **Step 7:** Commit `feat(rules): rules pack format, embedded default pack, profiles command`.

### Task 4: Rules pack signing, verification, rotation, install

**Files:**
- Create: `crates/pqaudit-rules/src/{verify.rs,install.rs}`, `rules/trust/keys.toml`, `xtask/src/{keygen.rs,sign.rs,pack_rules.rs}`, `crates/pqaudit-cli/src/commands/rules.rs`
- Test: `crates/pqaudit-rules/tests/verify.rs`, `crates/pqaudit-cli/tests/rules.rs`, `xtask/tests/openssl_interop.rs`

**Interfaces:**
- Signature file `<file>.sig.json`: `{"format":"pqaudit-hybrid-sig/1","key_id":"<hex>","ed25519":"<base64>","ml_dsa_65":"<base64>"}`. `key_id` = hex SHA-256 of (Ed25519 SPKI DER ‖ ML-DSA-65 SPKI DER). xtask also writes raw `<file>.ed25519.sig` and `<file>.mldsa65.sig` for OpenSSL.
- Pack archive: `rules-<version>.tar.zst` containing the `rules/` layout plus optional `rotations/NNN.json` + `rotations/NNN.json.sig.json`. Rotation statement: `{"format":"pqaudit-key-rotation/1","old_key_id":"<hex>","new_ed25519_spki":"<base64 DER>","new_ml_dsa_65_spki":"<base64 DER>","issued":"YYYY-MM-DD"}`, signed (hybrid) by the old key over the statement file bytes.
- `rules/trust/keys.toml`: `[[key]] id, ed25519_spki_pem, ml_dsa_65_spki_pem` and `revoked = ["<key_id>", ...]`.
- Produces:
  - `HybridPublicKey { ed25519: VerifyingKey, ml_dsa_65: ml_dsa::VerifyingKey<MlDsa65> }`, `HybridPublicKey::key_id(&self) -> String`
  - `verify_hybrid(data: &[u8], sig: &SigFile, key: &HybridPublicKey) -> Result<(), VerifyError>` — both must pass.
  - `verify_pack_archive(archive: &[u8], sig: &SigFile, trust: &TrustStore) -> Result<VerifiedPack, VerifyError>`; `VerifiedPack { pack: RulesPack, signed_by: String, rotation_chain: Vec<String> }`. Walks rotation statements in order from an embedded trusted key; fails if any key in the chain is revoked.
  - `install::install_pack(archive_path, sig_path) -> Result<PathBuf, InstallError>` into `<dirs::data_dir()>/pqaudit/rules/<version>/` (keeps the archive + sig; verifies again at load).
  - `install::active_pack(allow_unsigned: bool) -> Result<ActivePack, InstallError>`; `ActivePack { pack: Arc<RulesPack>, origin: PackOrigin /* Embedded | Installed { path, signed_by } | Unsigned { path } */ }`. Selects highest version among embedded and verified installed packs.
  - xtask: `keygen --out <dir>` (writes `ed25519.key.pem`, `ed25519.pub.pem`, `mldsa65.key.pem`, `mldsa65.pub.pem`, PKCS#8/SPKI), `sign --keys <dir> <file>`, `pack-rules --out <dir>` (tar.zst of `rules/`, deterministic: sorted entries, mtime 0, uid/gid 0).
  - CLI: `rules list` (active + installed packs, version, origin, hash), `rules verify <archive>` (exit 0/1, prints signer and chain), `rules update --from <archive>` (sig at `<archive>.sig.json` unless `--sig`). Unsigned or bad pack → exit 1 unless `--allow-unsigned-rules`, which installs with a warning.

- [ ] **Step 1: Write failing tests** in `verify.rs` (generate keys in-test):
  - `valid_hybrid_sig_verifies`
  - `ed25519_only_tampered_fails` and `mldsa_only_tampered_fails` (corrupt one signature; must fail).
  - `modified_archive_fails`
  - `rotation_chain_accepts_new_key`: trust A; pack signed by B with rotation A→B → OK, `rotation_chain == [A, B]`.
  - `rotation_from_revoked_key_fails`: A revoked → fail.
  - `rotation_not_signed_by_old_key_fails`.
  - `unknown_key_fails`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implement `verify.rs`, `install.rs`, xtask commands.
- [ ] **Step 4: Write test** `openssl_interop.rs::openssl_verifies_both_signatures` (skip with a printed note if `openssl version` < 3.5): xtask keygen + sign a file, then `openssl pkeyutl -verify -pubin -inkey ed25519.pub.pem -rawin -in <file> -sigfile <file>.ed25519.sig` and the same for `mldsa65.pub.pem` / `.mldsa65.sig` both print `Signature Verified Successfully`. Run → PASS.
- [ ] **Step 5:** CLI tests: `rules_verify_good_pack_exit_0`, `rules_update_bad_sig_exit_1`, `rules_update_unsigned_with_flag_installs_and_warns`, `rules_list_shows_embedded`. Use an env var `PQAUDIT_DATA_DIR` (honoured by `install.rs`) to isolate the data dir in tests. Implement `commands/rules.rs`.
- [ ] **Step 6:** Generate a **development** pack-signing key with xtask, put its public half in `rules/trust/keys.toml` marked `# DEVELOPMENT KEY — replace before first release` (Task 20 replaces it). Do not commit private keys; add `*.key.pem` to `.gitignore`.
- [ ] **Step 7:** Run `cargo test --workspace` → PASS. Commit `feat(rules): hybrid-signed rules packs with rotation and install`.

### Task 5: Core finding model, results file, fingerprints

**Files:**
- Create: `crates/pqaudit-core/src/{finding.rs,fingerprint.rs,results.rs}`, `schema/pqr.schema.json`
- Test: `crates/pqaudit-core/tests/{results.rs,fingerprint.rs}`

**Interfaces:**
- Produces (in `pqaudit_core`):
  - `Source { File, Net }` (Stage 2 adds `Code, Dependency, Config`), `Purpose { KeyExchange, Encryption, Signature, Hash, Unknown }`, `Agility { HardCoded, Config, LibraryDefault, Unknown }`, `FixOwner { InHouse, OpenSource, Vendor, Unknown }`.
  - `Algorithm { name: String, key_bits: Option<u32>, curve: Option<String> }`
  - `Location::File { path: String, line: Option<u32> }` | `Location::Endpoint { host: String, ip: IpAddr, port: u16, protocol: Protocol /* Tls | Ssh */ }`
  - `Occurrence { location: Location, evidence: String, run_id: Uuid }`
  - `CertInfo { sha256: String, subject: String, issuer: String, not_before: DateTime<Utc>, not_after: DateTime<Utc>, is_ca: bool, key_usage: Vec<String>, ext_key_usage: Vec<String>, public_key: Algorithm, signature_algorithm: String, chain_position: Option<u8> }`
  - `KeyInfo { fingerprint_sha256: String, kind: KeyKind /* X509Spki, OpenSsh, Pgp, Pkcs8Private, EncryptedPrivate */, algorithm: Option<Algorithm>, comment: Option<String> }`
  - `EndpointInfo { protocol: Protocol, tls: Option<TlsObservation>, ssh: Option<SshObservation> }`, `TlsObservation { pq_hybrid_supported: Option<bool>, negotiated_version: Option<String>, negotiated_group: Option<String>, cipher_suite: Option<String>, legacy_versions: Option<Vec<String>>, errors: Vec<String> }`, `SshObservation { banner: String, kex: Vec<String>, host_key_algorithms: Vec<String>, ciphers: Vec<String>, macs: Vec<String> }`
  - `Finding { id: String, fingerprint: Fingerprint, rule_id: String, source: Source, algorithm: Option<Algorithm>, purpose: Purpose, threat_type: ThreatType, agility: Agility, fix_owner: FixOwner, also: Vec<String> /* other rule IDs that matched the same subject */, occurrences: Vec<Occurrence>, cert: Option<CertInfo>, key: Option<KeyInfo>, endpoint: Option<EndpointInfo> }`
  - `InventoryItem { kind: InventoryKind /* Certificate, Key, Endpoint */, fingerprint: Fingerprint, pq_ready: bool, algorithm: Option<Algorithm>, cert: Option<CertInfo>, key: Option<KeyInfo>, endpoint: Option<EndpointInfo>, occurrences: Vec<Occurrence> }` — every observed crypto asset, findings or not (CBOM uses this).
  - `ScanError { location: String, reason: String }`
  - `Fingerprint(String)` with `Fingerprint::cert(sha256_hex: &str)`, `Fingerprint::key(spki_or_blob_sha256_hex: &str)`, `Fingerprint::endpoint(host: &str, port: u16, rule_family: &str)`. Format: `"<kind>:" + hex(sha256(kind ‖ 0x00 ‖ fields joined by 0x00))[..32]`. Host is lower-cased.
  - `ResultsHeader { schema_version: u32 /* 1 */, engagement: String, tool_version: String, rules_pack: PackRef { id, version, content_hash, origin }, scanner: ScannerKind /* Files, Net, Merged */, host: String, operator: String, started: DateTime<Utc>, finished: DateTime<Utc>, scope_hash: Option<String>, audit_log_hash: Option<String>, runs: Vec<RunInfo { run_id, scanner, host, started }>, redacted: bool }`
  - `ResultsFile { header, findings: Vec<Finding>, inventory: Vec<InventoryItem>, errors: Vec<ScanError> }` with `ResultsFile::write(&self, path: &Path, compress: bool) -> io::Result<()>` and `ResultsFile::read(path: &Path) -> Result<ResultsFile, ResultsError>` (detects zstd by magic `28 B5 2F FD`; rejects `schema_version` greater than supported with an STE message naming both versions).

- [ ] **Step 1: Write failing tests:**
  - `roundtrip_plain_and_zstd`: write + read equal for both modes.
  - `newer_schema_rejected`: header `schema_version: 99` → `ResultsError::UnsupportedSchema { found: 99, supported: 1 }`.
  - `fingerprint_endpoint_case_insensitive_host`: `endpoint("Pay.Example", 443, "tls.no-pq-kex") == endpoint("pay.example", 443, "tls.no-pq-kex")`.
  - `fingerprint_distinct_kinds`: `cert(x) != key(x)`.
  - `fingerprint_stable_value`: `Fingerprint::cert("00".repeat(32))` equals a literal you compute once and paste in (guards accidental format change).
  - `committed_schema_matches_generated`: `schemars::schema_for!(ResultsFile)` serialized pretty == contents of `schema/pqr.schema.json`.
- [ ] **Step 2:** Run `cargo test -p pqaudit-core` → FAIL.
- [ ] **Step 3:** Implement. Generate `schema/pqr.schema.json` with a `#[ignore]`d test or xtask helper and commit it.
- [ ] **Step 4:** Run → PASS. Commit `feat(core): finding model, .pqr results file and fingerprints`.

### Task 6: Engagement files and `init`

**Files:**
- Create: `crates/pqaudit-core/src/engagement.rs`, `crates/pqaudit-cli/src/commands/init.rs`, `crates/pqaudit-cli/src/templates/{engagement,scope,assets,overrides,scoring}.toml`
- Test: `crates/pqaudit-core/tests/engagement.rs`, `crates/pqaudit-cli/tests/init.rs`

**Interfaces:**
- Produces (in `pqaudit_core::engagement`):
  - `EngagementConfig { client: String, assessor: String, assessment_date: Option<NaiveDate>, deadlines: DeadlineSelection { profiles: Vec<String>, sector: Option<String> }, assumptions: Assumptions { crqc_year: i32 }, passwords: Option<PasswordSource /* { env: String } | { file: PathBuf } */> }`
  - `AssetsFile { asset: Vec<Asset> }`, `Asset { name, business_unit: Option<String>, matcher: AssetMatch { hosts: Vec<String>, cidrs: Vec<IpNet>, paths: Vec<String> } /* toml key "match" */, classification: Option<String>, data_lifespan_years: Option<u32>, exposure: Option<Exposure /* Internet, Partner, Internal, Isolated */>, owner: Option<String>, vendor: Option<bool>, priority_tier: Option<Tier>, hardware_constrained: Option<bool> }`
  - `OverridesFile { r#override: Vec<Override { fingerprint: String, priority: Band, reason: String, by: String, date: NaiveDate }> }`, `Band { Critical, High, Medium, Low }`
  - `ScoringConfig { weights: Weights { threat: f64, exposure: f64, sensitivity: f64, mosca: f64, deadline: f64, scale: f64 }, classification: BTreeMap<String, f64>, bands: Bands { critical: f64, high: f64, medium: f64 }, migration_years: BTreeMap<Size, f64> }` with `Default` = spec §10.2 / §10.3 values: weights 0.25/0.20/0.20/0.15/0.10/0.10; classification `public 0.1, internal 0.4, confidential 0.7, secret 1.0, restricted 1.0`; bands 80/60/40; migration years S 0.25, M 0.5, L 1, XL 2.
  - `Engagement { dir: PathBuf, config: EngagementConfig, assets: AssetsFile, overrides: OverridesFile, scoring: ScoringConfig }`, `Engagement::load(dir: &Path) -> Result<Engagement, EngagementError>` — missing `assets.toml`/`overrides.toml`/`scoring.toml` → empty/default; missing `engagement.toml` → error. Errors name the file and the TOML line.
  - Note: `hardware_constrained` is an asset field added by this plan to carry spec §10.1's hardware flag.
- `init <name> [--dir <parent>]` creates `<parent>/<name>/` with the five templates, `results/`, `reports/`. Refuses (exit 1) if the folder exists and is non-empty. Template comments in STE explain every key.

- [ ] **Step 1: Write failing tests:** `load_minimal_engagement`, `missing_optional_files_use_defaults`, `scoring_defaults_match_spec` (assert every default value above), `bad_toml_error_names_file_and_line`, `asset_match_key_parses` (`match = { hosts = [...], cidrs = ["10.0.0.0/24"], paths = ["repos/**"] }`); CLI `init_creates_layout`, `init_refuses_non_empty_dir`, `init_templates_load` (`Engagement::load` succeeds on a fresh init after filling `client`).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS; `vale crates/pqaudit-cli/src/templates/` → 0 errors.
- [ ] **Step 5:** Commit `feat: engagement files and init command`.

### Task 7: `scan files` — walker and X.509 certificates

**Files:**
- Create: `crates/pqaudit-scan-files/src/{lib.rs,walk.rs,cert.rs,messages.rs}`, `crates/pqaudit-core/src/classify.rs`, `crates/pqaudit-cli/src/commands/scan_files.rs`, `crates/pqaudit-scan-files/tests/fixtures/` + `generate.sh`, `xtask/src/check_offline.rs`
- Modify: `.github/workflows/ci.yml` (add `offline` job)
- Test: `crates/pqaudit-scan-files/tests/{certs.rs,robustness.rs}`, `crates/pqaudit-cli/tests/scan_files.rs`

**Interfaces:**
- Consumes: `ResultsFile`, `Finding`, `InventoryItem`, `Fingerprint::cert`, `RulesPack` (Tasks 3, 5).
- Produces:
  - `pqaudit_scan_files::ScanOptions { max_file_size: u64 /* default 10_485_760 */, follow_symlinks: bool /* default false */, passwords: Vec<Zeroizing<String>> }`
  - `pqaudit_scan_files::scan(paths: &[PathBuf], opts: &ScanOptions, pack: &RulesPack, run_id: Uuid) -> ScanOutput { findings: Vec<Finding>, inventory: Vec<InventoryItem>, errors: Vec<ScanError> }`
  - `pqaudit_core::classify::classify_cert(cert: &CertInfo, pack: &RulesPack, today: NaiveDate) -> Option<(String /* primary rule id */, ThreatType, Vec<String> /* also */)>` — precedence: `cert.weak-key` (key below `weak_below_bits` or `weak_always`) > `cert.weak-sig-hash` (SHA-1/MD5 signature) > `cert.classical-key` (quantum-vulnerable key). Threat type: weak → `ClassicalWeakNow`; else `ForgeryLongLived` if `is_ca` or code-signing EKU or `not_after - not_before > 3 years`; else `ForgeryShortLived`. PQ key (ML-DSA, SLH-DSA) → `None` (inventory only, `pq_ready: true`).
  - Detection: by extension (`.pem .crt .cer .der`) and by content (`-----BEGIN CERTIFICATE-----` anywhere in the first 64 KiB). Multiple PEM blocks per file → one occurrence per cert, `chain_position` = block index. Same cert seen in several files → one finding, several occurrences.
  - `scan files <PATHS>... [--max-file-size <BYTES>] [--follow-symlinks] [--output <FILE>]`; default output `<engagement>/results/files-<UTC yyyymmddTHHMMSS>.pqr`. Exit 3 when `errors` is non-empty and some files were scanned; exit 1 when nothing was readable.
  - `xtask check-offline-deps`: runs `cargo tree -p pqaudit-scan-files -e normal --prefix none` and fails if any of `tokio, rustls, hyper, reqwest, socket2, mio, ureq, curl` appear.

- [ ] **Step 1:** Write `generate.sh` using `openssl` (≥ 3.5) to create fixtures: RSA-2048 leaf (1 year), RSA-1024 leaf, ECDSA P-256 CA (10 years), SHA-1-signed RSA-2048 leaf, ML-DSA-65 self-signed, a 3-cert PEM chain, a DER cert. Commit the script and its output.
- [ ] **Step 2: Write failing tests** in `certs.rs`: `rsa2048_leaf_is_classical_short_lived`, `rsa1024_is_weak_now_with_also_classical`, `ecdsa_ca_is_long_lived`, `sha1_sig_is_weak_sig_hash`, `mldsa_cert_is_inventory_pq_ready`, `chain_positions_recorded`, `der_cert_detected`, `same_cert_two_files_one_finding_two_occurrences`, `finding_has_rule_cwe_from_pack` (finding `rule_id` resolvable in pack).
- [ ] **Step 3: Write failing tests** in `robustness.rs`:
  - `malformed_inputs_are_errors_not_panics`: truncated DER, random bytes named `x.pem`, a PEM with 10 000 invalid blocks, a sparse file of 2 GB (skipped with error `too large`) → each appears in `errors` with a reason; scan returns.
  - `unreadable_paths_give_partial_exit_3` (CLI test, Unix-only for chmod/symlink parts): a `chmod 000` file, a symlink loop, a non-UTF-8 file name, plus one valid cert → exit 3, valid cert finding present, three errors.
- [ ] **Step 4:** Run `cargo test -p pqaudit-scan-files` → FAIL.
- [ ] **Step 5:** Implement with `walkdir` (no ignore files, `follow_links(opts.follow_symlinks)`), `x509-parser`. Non-UTF-8 paths are stored lossily with an error note. Wire `scan_files.rs` (loads `Engagement`, `active_pack`, writes results with `ScannerKind::Files`).
- [ ] **Step 6:** CI `offline` job (ubuntu): `cargo xtask check-offline-deps`; then `strace -f -e trace=socket,connect -o trace.txt target/debug/pqaudit scan files <fixtures>` and fail if `trace.txt` contains `socket(AF_INET` or `socket(AF_INET6` or `connect(`.
- [ ] **Step 7:** Run all tests → PASS. Commit `feat(scan-files): walker and X.509 certificate scanning`.

### Task 8: `scan files` — PKCS#12 and Java key stores

**Files:**
- Create: `crates/pqaudit-scan-files/src/{pkcs12.rs,jks.rs}`, fixtures (generated by `generate.sh`; JKS/JCEKS fixtures generated once with `keytool` and committed with the command in a comment)
- Test: `crates/pqaudit-scan-files/tests/keystores.rs`

**Interfaces:**
- Consumes: `ScanOptions.passwords`, `classify_cert`.
- Produces: `pkcs12::scan_p12(bytes: &[u8], passwords: &[Zeroizing<String>]) -> Result<Vec<CertInfo>, StoreError>`; `jks::scan_jks(bytes: &[u8]) -> Result<Vec<JksEntry>, StoreError>` where `JksEntry::TrustedCert(CertInfo) | JksEntry::PrivateKeyChain(Vec<CertInfo>)` (JKS magic `FE ED FE ED`, JCEKS `CE CE CE CE`; read certificates without a password; skip encrypted key bytes without decoding them; ignore the trailing integrity hash). PKCS#12 tries each supplied password, then the empty password; all fail → one `KeyInfo { kind: EncryptedPrivate, algorithm: None }` inventory item and a finding-free note "encrypted — not inspected" in `errors`. Detection by extension `.p12 .pfx .jks .jceks .keystore` and by magic.

- [ ] **Step 1: Write failing tests:** `p12_with_empty_password_reads_certs`, `p12_with_supplied_password_reads_certs`, `p12_wrong_password_is_not_inspected_note`, `jks_trusted_and_chain_certs_read`, `jceks_magic_detected`, `truncated_jks_is_error`, and `keystore_private_material_not_in_results` (serialize the full `ScanOutput` to JSON; assert no 16-byte window of the PKCS#12 key bag's decrypted key DER, nor of the JKS encrypted key blob, appears in it hex- or base64-encoded).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement with `p12-keystore` and a hand-written JKS reader. Wrap any key bytes in `Zeroizing`. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(scan-files): PKCS#12 and Java key stores`.

### Task 9: `scan files` — SSH keys, PEM private keys, GPG keys

**Files:**
- Create: `crates/pqaudit-scan-files/src/{ssh.rs,privkey.rs,gpg.rs}`, fixtures (`ssh-keygen` RSA-2048, ECDSA, Ed25519, an encrypted Ed25519, `authorized_keys`, `known_hosts` incl. hashed entries; OpenSSL PKCS#8 RSA/EC unencrypted + encrypted, PKCS#1 `RSA PRIVATE KEY`; `gpg --export` RSA-3072 + Ed25519)
- Test: `crates/pqaudit-scan-files/tests/keys.rs`

**Interfaces:**
- Produces: findings with `rule_id` `key.classical` (quantum-vulnerable algorithm, `ThreatType::ForgeryShortLived` for signing keys / `Hndl` for keys whose algorithm is key agreement only) or `key.weak` (`ClassicalWeakNow`), `KeyInfo` populated, `Fingerprint::key(sha256 of public key: SPKI DER / SSH public blob / OpenPGP v4 fingerprint)`. Encrypted private keys → `KeyKind::EncryptedPrivate`, `algorithm: None`, recorded in inventory with note. `.kbx` key boxes → `errors` entry "unsupported format" (spec: v1 supports exported keys and legacy `pubring.gpg`).
- Rule: private-key parsing takes only the algorithm identifier and the public modulus length / curve; buffers are `Zeroizing`; no error message includes file bytes.

- [ ] **Step 1: Write failing tests:** `ssh_rsa_ecdsa_ed25519_public_keys`, `authorized_keys_each_line_a_key`, `known_hosts_hashed_entries_supported`, `encrypted_openssh_private_key_public_part_only` (OpenSSH format exposes the public key unencrypted — algorithm present), `pkcs8_rsa_bits_read`, `pkcs1_rsa_detected`, `encrypted_pkcs8_not_inspected`, `gpg_rsa3072_and_ed25519`, `kbx_is_unsupported_error`, `same_key_in_authorized_keys_and_pub_file_one_finding`, and `private_key_material_never_in_results`: for every private-key fixture, decode its private body and assert no 16-byte window (raw, hex, or base64) appears in the serialized `ScanOutput` or in any `ScanError.reason`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement with `ssh-key`, `pkcs8` + `pkcs1`, `pgp`. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(scan-files): SSH, PEM private key and GPG key scanning`.

### Task 10: Scope file, target plan, enforcement, dry-run

**Files:**
- Create: `crates/pqaudit-scan-net/src/{lib.rs,messages.rs,scope.rs}`, `crates/pqaudit-cli/src/commands/scan_net.rs` (dry-run path only)
- Test: `crates/pqaudit-scan-net/tests/scope.rs`, `crates/pqaudit-cli/tests/scan_net_dry_run.rs`

**Interfaces:**
- `scope.toml`:
  ```toml
  require_ip_in_cidr = true           # default true when any CIDR appears in targets or allowed_cidrs
  allowed_cidrs = ["10.0.0.0/16"]     # addresses names may resolve to; not themselves targets
  allowed_hours = "09:00-17:00"       # optional, local time
  override_limits = false
  legacy_tls_check = false
  [limits]                            # all optional; defaults are the Global Constraints values
  concurrency = 4
  [[target]]  host = "pay.acme.example"  ports = [443]  protocol = "tls"
  [[target]]  cidr = "10.0.1.0/28"       ports = [22]   protocol = "ssh"
  [[exclude]] cidr = "10.0.1.5/32"       # or host = "..."
  ```
- Produces (in `pqaudit_scan_net::scope`):
  - `ScopeFile` (serde), `Limits { concurrency: usize, per_host: usize, min_interval: Duration, tls_handshakes: u8, connect_timeout: Duration, read_timeout: Duration, retries: u8 }`, `Limits::effective(requested: &LimitsToml, override_limits: bool) -> Result<Limits, ScopeError>` — values above defaults without `override_limits` → `ScopeError::LimitAboveDefault { name, requested, default }`.
  - `trait Resolver { fn resolve(&self, host: &str) -> io::Result<Vec<IpAddr>>; }` with `SystemResolver` (uses `ToSocketAddrs`, called once per host).
  - `build_plan(scope: &ScopeFile, resolver: &dyn Resolver) -> Result<TargetPlan, ScopeError>`; `TargetPlan { targets: Vec<PlannedTarget { host: Option<String> /* SNI */, ip: IpAddr, port: u16, protocol: Protocol, connections: u8 }>, refused: Vec<Refusal { target: String, reason: RefusalReason }>, limits: Limits }`. CIDR targets larger than 256 addresses → refusal unless `override_limits`. Excludes win over includes. Each host resolved exactly once.
  - `TargetPlan::is_refused(&self) -> bool` — any refusal aborts the scan (exit 2).
  - `scope_hash(bytes: &[u8]) -> String` (sha256 hex) for `ResultsHeader.scope_hash`.
  - `scan net --dry-run` prints every planned target (host, ip, port, protocol, connections) and every refusal with reason; exit 0 if no refusals, else 2. Opens no sockets except DNS.

- [ ] **Step 1: Write failing tests** with a `FakeResolver` that counts calls:
  - `host_target_resolves_once`
  - `one_bad_resolved_ip_refuses_whole_scan`: host resolves to `[10.0.0.5, 203.0.113.9]`, `allowed_cidrs = ["10.0.0.0/16"]` → plan refused, reason names `203.0.113.9`.
  - `exclude_beats_include`
  - `cidr_over_256_refused_without_override` and `..._allowed_with_override`
  - `limit_above_default_rejected`, `limit_below_default_accepted`
  - `tls_connections_count_is_2_or_3`: 2 without `legacy_tls_check`, 3 with it; ssh 1.
  - `ip_target_has_no_sni`
  - CLI: `dry_run_lists_targets_exit_0`, `dry_run_with_refusal_exit_2` (use `localhost` and a CIDR scope so resolution is local).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(scan-net): scope file, target plan and dry-run`.

### Task 11: Network runtime, audit log, TLS probes

**Files:**
- Create: `crates/pqaudit-scan-net/src/{runtime.rs,audit.rs,tls.rs,tls_legacy.rs}`
- Modify: `crates/pqaudit-cli/src/commands/scan_net.rs` (real scan)
- Test: `crates/pqaudit-scan-net/tests/{runtime.rs,tls.rs}`

**Interfaces:**
- Consumes: `TargetPlan`, `Limits`, `Finding`, `InventoryItem`, `Fingerprint::{endpoint,cert}`, `pqaudit_core::classify::classify_cert` (Task 7).
- Produces:
  - `audit::AuditLog::open(path: &Path) -> io::Result<AuditLog>` (append, JSON lines), `AuditLog::record(&self, e: &AuditEntry)`; `AuditEntry { ts: DateTime<Utc>, run_id: Uuid, src_ip: Option<IpAddr>, dst_host: Option<String>, dst_ip: IpAddr, port: u16, protocol: Protocol, probe: String /* "tls-hybrid" | "tls-classical" | "tls-legacy" | "ssh-kexinit" */, outcome: String, bytes_sent: u64, bytes_received: u64, duration_ms: u64 }`; `audit::CountingStream<S>` (AsyncRead/AsyncWrite wrapper counting bytes).
  - `runtime::run(plan: &TargetPlan, probes: &dyn Probes, audit: &AuditLog, run_id: Uuid) -> NetOutput { findings, inventory, errors }`; `trait Probes { async fn tls(&self, t: &PlannedTarget, ctx: &ProbeCtx) -> TlsObservationWithCerts; async fn ssh(&self, t: &PlannedTarget, ctx: &ProbeCtx) -> SshObservationResult; }` — enforces global concurrency semaphore, per-host concurrency 1, `min_interval` between connections to the same IP, timeouts, no retries. `ProbeCtx` carries limits, audit log, run id. Every connection attempt goes through one `connect()` helper that records an `AuditEntry` (also on failure).
  - `runtime::check_allowed_hours(spec: Option<&str>, now: NaiveTime) -> Result<(), ScopeError>` — outside window → refuse (exit 2) before any connection.
  - `tls::RealProbes` handshakes: (1) hybrid only: rustls aws-lc-rs provider, kx groups `X25519MLKEM768` (+ `SECP256R1MLKEM768` if the provider offers it), TLS 1.3 only; success → `pq_hybrid_supported = Some(true)`, handshake error → `Some(false)` with error text. (2) classical: groups X25519, secp256r1, secp384r1; TLS 1.3 + 1.2; records version, group, suite, and the full peer chain via a recording `ServerCertVerifier` that accepts any chain (it never sends data, so acceptance is safe). (3) only if `legacy_tls_check`: `tls_legacy::probe` sends a hand-built ClientHello with `client_version = 0x0302` and common TLS 1.0/1.1 suites, reads the ServerHello `server_version`, closes. Each handshake ends with close_notify (where a session exists) and socket close.
  - Findings: `tls.no-pq-kex` (`Hndl`, one per host:port) when `pq_hybrid_supported == Some(false)`; `tls.legacy-version` (`ClassicalWeakNow`) when TLS 1.0/1.1 accepted; chain certs go through `classify_cert` → `cert.*` findings with an `Endpoint` occurrence. Endpoints with hybrid support → inventory `pq_ready: true`.
  - `scan net [--output <FILE>]`: builds plan (refusal → exit 2), checks hours, opens `<engagement>/audit.log`, runs, writes `.pqr` with `scope_hash` and `audit_log_hash` (sha256 of the log after the run). Default output `<engagement>/results/net-<timestamp>.pqr`. Exit 3 if any target errored.

- [ ] **Step 1: Write failing tests** in `runtime.rs` with a fake `Probes` that records call times: `global_concurrency_respected` (max in-flight ≤ 4 with 20 targets), `same_host_min_interval_respected` (≥ 1000 ms between calls to one IP — use `tokio::time::pause`), `every_connection_audited` (entries == connections incl. failures, with byte counts), `outside_allowed_hours_refuses`, `no_retries_on_failure`.
- [ ] **Step 2: Write failing tests** in `tls.rs` against in-process rustls servers on `127.0.0.1` with rcgen certs: `hybrid_server_detected` (server offers X25519MLKEM768), `classical_only_server_gives_no_pq_finding`, `chain_certs_classified` (RSA-2048 leaf → `cert.classical-key` with endpoint occurrence), `legacy_probe_detects_tls10` (a minimal fake server that answers a ServerHello with version `0x0301`), `legacy_probe_off_by_default_makes_2_connections`, and `silent_server_times_out` (TCP listener that never writes; probe ends within `read_timeout` + 1 s, error recorded; use a 1 s read timeout in test).
- [ ] **Step 3:** Run → FAIL. **Step 4:** Implement. **Step 5:** Run → PASS.
- [ ] **Step 6:** Commit `feat(scan-net): runtime, audit log and TLS probes`.

### Task 12: SSH KEXINIT probe

**Files:**
- Create: `crates/pqaudit-scan-net/src/ssh.rs`
- Test: `crates/pqaudit-scan-net/tests/ssh.rs`

**Interfaces:**
- Produces: `ssh::probe(stream, limits) -> Result<SshObservation, SshProbeError>` — read lines until one starts with `SSH-` (max 64 lines, max 255 bytes per line, else error `banner too long`), send `SSH-2.0-pqaudit_<version>\r\n`, read one binary packet (`packet_length` ≤ 35 000 else error), require message 20 (`SSH_MSG_KEXINIT`), skip 16-byte cookie, parse name-lists `kex_algorithms`, `server_host_key_algorithms`, `encryption_algorithms_server_to_client`, `mac_algorithms_server_to_client`, then close without sending KEXINIT.
- Findings: `ssh.no-pq-kex` (`Hndl`) if neither `mlkem768x25519-sha256` nor `sntrup761x25519-sha512` (nor `sntrup761x25519-sha512@openssh.com`) is offered — the PQ KEX names list lives in `algorithms.yaml` so packs can extend it; `ssh.weak-kex` (`ClassicalWeakNow`) if `diffie-hellman-group1-sha1` or `diffie-hellman-group14-sha1` or `diffie-hellman-group-exchange-sha1` is offered; `ssh.classical-hostkey` (`ForgeryShortLived`) when all offered host key algorithms are classical. PQ KEX offered → inventory `pq_ready: true`.

- [ ] **Step 1: Write failing tests** with a fake TCP server on `127.0.0.1` replaying canned bytes: `parses_openssh_kexinit` (canned KEXINIT from OpenSSH 9.9 containing `mlkem768x25519-sha256`), `no_pq_kex_finding`, `weak_kex_finding`, `pre_banner_lines_skipped`, `endless_banner_is_capped` (server sends 1 000 lines), `oversized_packet_is_rejected` (`packet_length = 0x7fffffff`), `never_sends_kexinit` (fake server asserts it received only the banner line).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement and wire into `RealProbes::ssh`. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(scan-net): SSH KEXINIT probe`.

### Task 13: Merge and redact

**Files:**
- Create: `crates/pqaudit-core/src/merge.rs`, `crates/pqaudit-cli/src/commands/merge.rs`
- Test: `crates/pqaudit-core/tests/merge.rs`, `crates/pqaudit-cli/tests/merge.rs`

**Interfaces:**
- Produces:
  - `merge(inputs: Vec<ResultsFile>) -> Result<ResultsFile, MergeError>` — findings deduped by `fingerprint` (occurrences unioned, deduped by (location, run_id); `also` unioned); same for inventory; errors concatenated; `header.scanner = Merged`, `runs` = all input runs; rules packs of inputs differing → keep the highest version in header and add a `ScanError { location: "merge", reason }` warning naming the versions. Different `engagement` names → `MergeError::EngagementMismatch`. A cert seen by files and net → one finding with both occurrence types (spec §10.1).
  - `redact(file: &mut ResultsFile)` — replace every host name, IP, path, certificate subject/issuer and SSH banner with `"redacted:" + hex(sha256(value))[..12]`; fingerprints unchanged; `header.redacted = true`; `header.host`/`operator` redacted.
  - `merge <INPUTS>... [--output <FILE>] [--redact]`; default output `<engagement>/results/merged.pqr`.

- [ ] **Step 1: Write failing tests:** `same_cert_from_files_and_net_merges`, `distinct_findings_kept`, `occurrences_not_duplicated_on_remerge` (merge(merge(a,b), b) == merge(a,b) findings), `engagement_mismatch_errors`, `pack_version_mismatch_warns`, `redact_keeps_fingerprints_and_removes_hosts` (serialized redacted file contains none of the original hostnames/paths), CLI `merge_writes_default_output`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat: merge and redact results files`.

### Task 14: Assessment — assets, deadlines, overrides

**Files:**
- Create: `crates/pqaudit-core/src/{assets.rs,deadlines.rs,assess.rs}`
- Test: `crates/pqaudit-core/tests/{assets.rs,deadlines.rs,assess.rs}`

**Interfaces:**
- Consumes: `Engagement`, `ResultsFile`, `RulesPack`.
- Produces:
  - `assets::match_asset<'a>(assets: &'a [Asset], loc: &Location) -> Option<&'a Asset>` — first match in file order; hosts compare case-insensitively against `Location::Endpoint.host`; IPs against `cidrs`; paths with `globset` against `Location::File.path`. A finding's asset = the match of its first occurrence that matches anything.
  - `AssetContext { classification: Ctx<String>, data_lifespan_years: Ctx<u32>, exposure: Ctx<Exposure>, priority_tier: Ctx<Tier>, vendor: Ctx<bool>, hardware_constrained: Ctx<bool>, business_unit: Option<String>, owner: Option<String> }` where `Ctx<T> = Assessed(T) | Unassessed`.
  - `deadlines::resolve(threat: ThreatType, tier: Ctx<Tier>, sector: Option<&str>, profiles: &[&DeadlineProfile]) -> Option<DeadlineRef { date: NaiveDate, profile_id: String, description: String, source_title: String, source_url: String }>` — migration milestones only; `applies_to.tier = High` matches when tier is `High` or `Unassessed` (conservative, spec §7); `All` always; non-empty `threat_types` must contain the finding's; `sector` must equal the engagement sector; earliest date wins; tie → first profile in selection order.
  - `deadlines::planning(profiles) -> Vec<(String /* profile id */, Milestone)>` for engagement-level display.
  - `assess::assess(results: &ResultsFile, eng: &Engagement, pack: &RulesPack, today: NaiveDate) -> Result<Assessment, AssessError>`; unknown profile id in `engagement.toml` → `AssessError::UnknownProfile`.
  - `Assessment { engagement: EngagementSummary, header: ResultsHeader, findings: Vec<AssessedFinding>, inventory: Vec<InventoryItem>, errors: Vec<ScanError>, planning_milestones: Vec<(String, Milestone)>, orphaned_overrides: Vec<Override>, unassessed_count: usize, assumptions: Assumptions, pack: PackRef }`; `AssessedFinding { finding: Finding, rule: RuleDef, asset: Option<String>, context: AssetContext, deadline: Option<DeadlineRef>, score: ScoreBreakdown, band: Band, override_: Option<Override>, effective_band: Band, complexity: Complexity, testing: Vec<TestType> }` (score/complexity fields filled by Task 15 functions; this task calls them through `scoring::score` and `complexity::assess_complexity` stubs returning neutral values, replaced in Task 15).
  - `today` = `config.assessment_date` or the local date.

- [ ] **Step 1: Write failing tests:**
  - assets: `host_match_case_insensitive`, `cidr_match`, `path_glob_match`, `first_match_wins`, `no_match_is_unassessed`.
  - deadlines: `uk_high_tier_gets_2031`, `uk_unassessed_tier_gets_2031`, `uk_standard_tier_gets_2035` (asset `Tier` is `High | Standard`; milestone `TierScope` is `High | All`), `au_and_uk_strictest_is_au_2030`, `planning_never_attached`, `threat_type_filter_respected` (milestone with `threat_types = [ForgeryLongLived]` not applied to `Hndl`), `sector_filter_respected`.
  - assess: `overrides_applied_by_fingerprint`, `orphaned_override_reported`, `unassessed_count_counts_findings_with_any_unassessed_field`, `unknown_profile_errors`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(core): assessment with assets, deadlines and overrides`.

### Task 15: Scoring, complexity, testing scope, `explain`

**Files:**
- Create: `crates/pqaudit-core/src/{scoring.rs,complexity.rs}`, `crates/pqaudit-cli/src/commands/explain.rs`
- Test: `crates/pqaudit-core/tests/{scoring.rs,complexity.rs}`, `crates/pqaudit-cli/tests/explain.rs`

**Interfaces:**
- Produces:
  - `scoring::score(f: &Finding, ctx: &AssetContext, deadline: Option<&DeadlineRef>, complexity: &Complexity, cfg: &ScoringConfig, crqc_year: i32, today: NaiveDate) -> ScoreBreakdown`; `ScoreBreakdown { factors: Vec<FactorScore { name: &'static str, value: f64, weight: f64, contribution: f64, note: String }>, total: f64 /* 0–100 */ }`; `scoring::band(total, &cfg.bands) -> Band`.
  - Factor values (exact):
    - `threat`: Hndl 1.0, ForgeryLongLived 0.8, ClassicalWeakNow 1.0, ForgeryShortLived 0.3.
    - `exposure`: Internet 1.0, Partner 0.7, Internal 0.4, Isolated 0.2, Unassessed 1.0.
    - `sensitivity`: `cfg.classification[class]`; Unassessed or unknown class → 1.0 (unknown class also adds a note).
    - `mosca`: `lifespan` = data lifespan (Unassessed → 25); for ForgeryLongLived with a cert, `max(lifespan, years until not_after)`. `margin = lifespan + complexity.migration_years − (crqc_year − today.year)`. `value = 1.0 if margin ≥ 0 else max(0, 1 + margin / 10)`.
    - `deadline`: none → 0.0; `years_left = (deadline − today).days / 365.25`; `value = 1.0 if years_left ≤ 0 else clamp(1 − years_left / 10, 0, 1)`.
    - `scale`: `n` = occurrences; `value = min(1, log10(n + 1) / 2)`.
    - `total = 100 × Σ(weight × value) / Σ(weight)`.
  - `complexity::assess_complexity(f: &Finding, rule: &RuleDef, ctx: &AssetContext, cfg: &ScoringConfig) -> Complexity`; `Complexity { change_type: ChangeType, size: Size /* S, M, L, XL */, migration_years: f64, reasons: Vec<String> /* STE, from messages.rs */ }`. Change type: `rule.change_type`, raised to `ProtocolPartner` for certs with `is_ca`, to `Hardware` if `hardware_constrained = Assessed(true)`, to `Vendor` if `vendor = Assessed(true)` (highest wins in the order of spec §10.3). Size: Config S, LibraryUpgrade M, CodeChange M, ProtocolPartner L, Hardware XL, Vendor XL; +1 size (cap XL) if `exposure = Partner` or `rule.size_impact.len() ≥ 2`. `migration_years` from `cfg.migration_years[size]`.
  - `complexity::testing_scope(rule: &RuleDef, ctx: &AssetContext) -> Vec<TestType>` = `rule.testing` ∪ {Interop if exposure is Partner} ∪ {Certification if the rule's testing already contains it or the asset classification maps ≥ 0.7}.
  - Replace the Task 14 stubs with these.
  - `explain <FINDING-ID> [--results <FILE>]` (default `<engagement>/results/merged.pqr`): prints rule title, description, evidence of each occurrence, threat type, context (marking unassessed), deadline + source, CWE/ATT&CK, every score factor (value × weight = contribution, note), total and band, override, complexity + reasons, testing scope, remediation. Unknown id → exit 1.

- [ ] **Step 1: Write failing tests** in `scoring.rs` with fixed `today = 2026-10-20`, `crqc_year = 2035`, defaults:
  - `all_max_scores_100`: Hndl, Internet, secret, lifespan 25, deadline 2026-01-01, 99 occurrences → `total == 100.0`.
  - `worked_example`: Hndl, Internal, `confidential`, lifespan 5, complexity M (0.5), deadline `2030-12-31`, 1 occurrence → mosca margin = 5 + 0.5 − 9 = −3.5 → 0.65; deadline years_left ≈ 4.2 → ≈ 0.58; scale = log10(2)/2 ≈ 0.1505; total = 100 × (0.25×1 + 0.20×0.4 + 0.20×0.7 + 0.15×0.65 + 0.10×0.58 + 0.10×0.1505) ≈ 64.06 → assert within ±0.2, band High.
  - `unassessed_is_conservative_and_noted`.
  - `bands_boundaries` (80 → Critical, 79.99 → High, 60 → High, 40 → Medium, 39.99 → Low).
  - `custom_weights_used`.
- [ ] **Step 2: Write failing tests** in `complexity.rs`: `tls_no_pq_kex_is_m`, `ca_cert_is_l_protocol_partner`, `vendor_asset_is_xl`, `partner_exposure_bumps_size_and_adds_interop`, `reasons_non_empty`.
- [ ] **Step 3:** CLI test `explain_shows_factor_breakdown` (stdout contains each factor name and the total) and `explain_unknown_id_exits_1`.
- [ ] **Step 4:** Run → FAIL. **Step 5:** Implement. **Step 6:** Run → PASS; `vale target/ste/messages.md` → 0 errors after `cargo xtask strings`.
- [ ] **Step 7:** Commit `feat(core): scoring, complexity, testing scope and explain`.

### Task 16: Technical report

**Files:**
- Create: `crates/pqaudit-report/src/{lib.rs,technical.rs,messages.rs}`, `crates/pqaudit-report/src/templates/{technical.html,technical.md.j2}`, `crates/pqaudit-cli/src/commands/report.rs`
- Test: `crates/pqaudit-report/tests/technical.rs`, `crates/pqaudit-cli/tests/report.rs`

**Interfaces:**
- Consumes: `Assessment`.
- Produces: `technical::render(a: &Assessment, format: Format /* Html, Md, Json */) -> Result<String, ReportError>`. Sections in order (spec §12.2): title block (client, assessor, date, tool + pack version), methodology, scope and coverage (runs, scope hash, audit log hash, error count), assumptions (CRQC year, profiles, planning milestones with sources), summary counts by effective band, ranked findings (effective band, then total desc), "Fix now (not quantum)" (all `ClassicalWeakNow`), already-PQ-ready inventory, vendor questions (findings with `vendor = Assessed(true)`: one STE question per finding from the rule's remediation), overrides log (original band, override, reason, by, date), orphaned overrides, risk-register appendix table (fingerprint, title, likelihood factors: exposure / threat / classical-weak; impact factors: classification / lifespan / scale; suggested band; effective band). HTML is one file: inline CSS, no `<script src>`, no `<link>`, no external URLs except source links as plain `<a>` text; print stylesheet included. JSON = `serde_json` of `Assessment`.
  - `report --audience technical --format html|md|json [--results <FILE>] [--output <FILE>]`; default output `<engagement>/reports/technical.<ext>`. `--audience board` or `--format pdf` → exit 1 with `messages::LATER_RELEASE`.

- [ ] **Step 1: Write failing tests** using a fixture `Assessment` built in-test (3 findings: one per threat type incl. one ClassicalWeakNow, one vendor asset, one override, one orphaned override, one PQ-ready endpoint):
  - `html_is_self_contained` (no `<script src`, `<link`, `@import`, `url(http`).
  - `sections_in_order` (heading positions increase in the order listed).
  - `fix_now_lists_classical_weak`, `vendor_questions_present`, `overrides_log_shows_reason`, `risk_register_has_row_per_finding`, `unassessed_marked` (literal "Unassessed" appears for unassessed fields).
  - `md_and_json_render`.
  - CLI: `report_board_exits_1_later_release`, `report_pdf_exits_1_later_release`, `report_writes_default_path`.
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement with `minijinja` (templates via `include_str!`). All fixed text in STE. **Step 4:** Run → PASS; `vale crates/pqaudit-report/src/templates/` → 0 errors.
- [ ] **Step 5:** Commit `feat(report): technical report in HTML, Markdown and JSON`.

### Task 17: CycloneDX CBOM

**Files:**
- Create: `crates/pqaudit-report/src/cbom.rs`, `crates/pqaudit-cli/src/commands/cbom.rs`, `crates/pqaudit-report/tests/schema/` (vendored CycloneDX 1.6 `bom-1.6.schema.json`, `spdx.schema.json`, `jsf-0.82.schema.json` with source URLs in a README)
- Test: `crates/pqaudit-report/tests/cbom.rs`

**Interfaces:**
- Consumes: `Assessment` (findings + inventory), `RulesPack::algorithm`.
- Produces: `cbom::render(a: &Assessment, pack: &RulesPack) -> serde_json::Value` — `bomFormat: "CycloneDX"`, `specVersion: "1.6"`, `serialNumber: urn:uuid`, `metadata.tools` = pqaudit + version, `metadata.component` = engagement client. Components:
  - one `cryptographic-asset` / `assetType: "algorithm"` per distinct algorithm (dedup by name + parameter set), with `oid`, `primitive` (`pke`, `kem`, `signature`, `key-agree`, `hash`, `block-cipher`), `parameterSetIdentifier` (key bits or curve), `nistQuantumSecurityLevel` (from pack; 0 for classical);
  - one `assetType: "certificate"` per cert (`subjectName`, `issuerName`, `notValidBefore`, `notValidAfter`, `signatureAlgorithmRef`, `subjectPublicKeyRef`, `certificateFormat: "X.509"`), `bom-ref` = fingerprint;
  - one `assetType: "related-crypto-material"` per key (`type: "public-key"` or `"private-key"`, `algorithmRef`, `size`) — never key bytes;
  - one `assetType: "protocol"` per endpoint (`type: "tls"` / `"ssh"`, `version`, `cipherSuites` with `algorithms` refs).
  Services: one per endpoint (`name` = host:port, `endpoints` = [`https://host:port`-style or `ssh://host:port`]). `dependencies`: each service → its protocol + certificates; each certificate → its algorithms; each file location appears as a `properties` entry `pqaudit:location`.
  - `cbom [--results <FILE>] [-o <FILE>]`; default `<engagement>/reports/cbom.cdx.json`.

- [ ] **Step 1: Write failing tests:** `cbom_validates_against_cyclonedx_1_6` (jsonschema with the vendored files), `algorithm_components_deduped`, `cert_component_refs_algorithms`, `endpoint_service_depends_on_protocol_and_cert`, `pq_algorithm_has_level_3` (ML-DSA-65 → `nistQuantumSecurityLevel: 3`), `no_key_bytes_in_cbom` (re-use Task 9 private-key fixtures through scan → merge → assess → cbom; no 16-byte window present).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement. **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `feat(report): CycloneDX 1.6 CBOM`.

### Task 18: End-to-end engagement test

**Files:**
- Test: `crates/pqaudit-cli/tests/e2e.rs`

**Interfaces:**
- Consumes: all commands.

- [ ] **Step 1: Write test** `full_stage1_engagement`: `init` → fill `engagement.toml` (profiles `["au","uk"]`, `crqc_year = 2035`, `assessment_date = 2026-10-20`) and `assets.toml` (one asset matching `127.0.0.1` and the fixtures path) → start an in-process TLS server (classical only) and fake SSH server on `127.0.0.1` → `scope.toml` targeting them with `allowed_cidrs = ["127.0.0.0/8"]` and test-only limits below defaults → `scan net --dry-run` (exit 0) → `scan net` → `scan files` on fixtures → `merge` → `report --format html` → `report --format json` → `cbom` → `explain <first id>`. Assert: every command exit 0 (or 3 only where fixtures include deliberate errors), audit log has one line per connection, JSON report findings include `tls.no-pq-kex` with deadline `2030-12-31` from profile `au`, CBOM validates, HTML self-contained.
- [ ] **Step 2:** Run `cargo test -p pqaudit-cli --test e2e` → PASS (fix integration defects in the owning crate, with a regression test there).
- [ ] **Step 3:** Commit `test: end-to-end Stage 1 engagement`.

### Task 19: Documentation in STE

**Files:**
- Create: `README.md`, `docs/user-guide.md`, `docs/verifying.md`, `.github/release-notes-template.md`
- Test: CI `ste` job

**Interfaces:**
- Consumes: final CLI (Tasks 1–17), release pipeline design (Task 20 — write `verifying.md` against the commands listed there; Task 20 Step 7 re-checks them).

Content (all STE):
- `README.md`: what pqaudit does (2 paragraphs), install (download + verify link), quick start (the §5 workflow, Stage 1 commands only), **"Trusting pqaudit in your environment"** (scope model, gentle defaults, audit log, offline modes open no sockets, private keys never copied, signed releases + SBOM + CBOM, link to `docs/verifying.md`), safety model summary (spec §8 points 1–8), Stage 1 limits (no code scanning, no board report, no PDF yet), licence.
- `docs/user-guide.md`: engagement folder; every key of each TOML file; every command and flag (same text as CLI help); exit codes; reading the technical report; how the score is calculated (the §10.2 table and formula, a worked example — use the Task 15 worked example); how deadlines are chosen (§13 rule); overrides; redaction; rules packs (`rules list/verify/update`, unsigned warning).
- `docs/verifying.md` — "Verifying this release": `gh attestation verify <file> --repo <org>/pqaudit`; `cosign verify-blob <file> --bundle <file>.sigstore.json --certificate-identity-regexp '^https://github.com/<org>/pqaudit/.github/workflows/release.yml@refs/tags/v' --certificate-oidc-issuer https://token.actions.githubusercontent.com`; air-gapped steps (copy bundle + `trusted_root.json`, how to refresh it from Sigstore TUF before going offline, pinned cosign version, `--trusted-root` flag); hybrid PQ signature check with the two `openssl pkeyutl -verify` commands on `SHA256SUMS` then `sha256sum -c`; Windows `Get-AuthenticodeSignature`; macOS `codesign --verify --deep --strict` + `spctl --assess`; SBOM location + compare with `cargo auditable` data (`rust-audit-info <binary>`); self-CBOM location; rules pack verification.
- `.github/release-notes-template.md`: sections Changes, Rules pack version, Verifying this release (short form + link), Known limits.

- [ ] **Step 1:** Write the four files.
- [ ] **Step 2:** Verify every command in `user-guide.md` exists: `cargo xtask strings` then a test `docs_mention_every_flag` (in `xtask/tests/strings.rs`) asserting every long flag in `cli-help.md` appears in `docs/user-guide.md`. Run → PASS.
- [ ] **Step 3:** Run `vale README.md docs/ .github/release-notes-template.md` → 0 errors.
- [ ] **Step 4:** Commit `docs: README, user guide and release verification in STE`.

### Task 20: Release pipeline, self-CBOM, production keys

**Files:**
- Create: `.github/workflows/release.yml`, `docs/self-crypto.toml`, `xtask/src/{self_cbom.rs,sign_release.rs}`
- Modify: `rules/trust/keys.toml` (production pack key), `Cargo.toml` (`[profile.release]` `lto = true`, `codegen-units = 1`, `strip = true`)
- Test: `xtask/tests/self_cbom.rs`

**Interfaces:**
- `docs/self-crypto.toml`: `[[use]] purpose = "tls-probe" algorithms = ["X25519MLKEM768", "X25519", "P-256", "P-384", "RSA", "ECDSA", "Ed25519"] crate = "aws-lc-rs"`, `[[use]] purpose = "rules-pack-verify" algorithms = ["Ed25519", "ML-DSA-65"] crates = ["ed25519-dalek", "ml-dsa"]`, `[[use]] purpose = "fingerprints" algorithms = ["SHA-256"] crate = "sha2"`.
- `cargo xtask self-cbom --sbom <sbom.json> --out <cbom.json>`: fails if a crate in the SBOM appears in the `crypto_crates` list in `algorithms.yaml` (add this list in this task: aws-lc-rs, aws-lc-sys, ring, rustls, ed25519-dalek, ml-dsa, sha2, sha1, md-5, rsa, p256, p384, x25519-dalek, ml-kem) but is not declared in `self-crypto.toml`, or a declared crate is absent from the SBOM; otherwise writes a CycloneDX 1.6 CBOM via `pqaudit_report::cbom` helpers listing the declared algorithms per purpose.
- `cargo xtask sign-release --keys <dir> --dir <downloaded-release-dir>`: verifies each artifact's Sigstore bundle with `cosign verify-blob` (fails if missing), writes `SHA256SUMS` and `SHA3-256SUMS` if absent, hybrid-signs both sums files (`.sig.json`, `.ed25519.sig`, `.mldsa65.sig`).
- `release.yml` on tag `v*`, `permissions: { contents: write, id-token: write, attestations: write }`:
  1. Build matrix: `x86_64-unknown-linux-musl`, `aarch64-unknown-linux-musl` (cargo-zigbuild), `x86_64-apple-darwin` + `aarch64-apple-darwin` (then `lipo` → universal), `x86_64-pc-windows-msvc`, `aarch64-pc-windows-msvc` (drop from matrix with a comment if aws-lc-rs fails to build). All with `cargo auditable build --release --locked`.
  2. macOS: `codesign --options runtime --timestamp` with Developer ID + `xcrun notarytool submit --wait`; Windows: `signtool sign /fd SHA256 /tr <timestamp> /td SHA256`. Both steps run only when their secrets exist; otherwise the job logs a warning and continues.
  3. SBOM: `cargo cyclonedx --format json --spec-version 1.6` for `pqaudit-cli`.
  4. Self-CBOM: `cargo xtask self-cbom`.
  5. `actions/attest-build-provenance` for every binary; `actions/attest-sbom` with the SBOM for every binary.
  6. `cosign sign-blob --yes --bundle <file>.sigstore.json <file>` for every binary, SBOM, CBOM, and the rules pack archive.
  7. `cargo xtask pack-rules`; the archive is attached unsigned — maintainers hybrid-sign it offline (step 9).
  8. Create a **draft** release from `.github/release-notes-template.md` with all artifacts.
  9. (Manual, documented in `docs/verifying.md` maintainer appendix) maintainer downloads the draft, runs `cargo xtask sign-release` and `cargo xtask sign` on the rules archive with offline keys, uploads the signature files, publishes.

- [ ] **Step 1: Write failing tests** in `self_cbom.rs`: `undeclared_crypto_crate_fails`, `declared_but_absent_crate_fails`, `valid_declaration_writes_cbom` (validates against CycloneDX 1.6 schema from Task 17).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implement `self_cbom.rs`, `sign_release.rs`, `release.yml`. **Step 4:** Run → PASS.
- [ ] **Step 5:** Ask the human for: who holds the production offline keys, and whether Apple/Windows signing secrets exist. Generate production pack-signing keys on the key holder's machine with `cargo xtask keygen`; replace the development key in `rules/trust/keys.toml`; re-run `cargo test --workspace`.
- [ ] **Step 6:** Verify the pipeline: push tag `v0.1.0-rc.1` to the repo (or a fork); all release jobs green; download one Linux binary and run every command in `docs/verifying.md` against it — `gh attestation verify`, online and offline `cosign verify-blob`, both `openssl pkeyutl -verify` commands after step 9, `sha256sum -c SHA256SUMS`. Fix the doc or the workflow where a command fails.
- [ ] **Step 7:** Commit `ci: signed release pipeline, SBOM, provenance and self-CBOM`.
