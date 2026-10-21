# Maintaining pqaudit

This procedure is for the persons who change, build, and release pqaudit. It uses ASD-STE100 Simplified Technical English. The style guide is `docs/style/ste.md`.

## 1. Get the tools

Install these tools on your computer:

- Git.
- `rustup`. The file `rust-toolchain.toml` selects the Rust version. Cargo installs that version when you build.
- OpenSSL 3.5 or later. The signature tests use it.
- `ssh-keygen` and `gpg`. Only the fixture scripts use them.

Install the pinned Vale version for the STE lint. The CI file `.github/workflows/ci.yml` gives the version and the SHA-256 value. Put the `vale` program in `.tools/vale`. Git ignores the `.tools/` folder.

## 2. Get the code

Do these steps one time:

1. Clone the repository: `git clone https://github.com/mor-sec/pqaudit.git`.
2. Go into the folder: `cd pqaudit`.
3. Build the code: `cargo build --locked`.
4. Run the tests: `cargo test --workspace --locked`.

If step 4 fails on a clean clone, stop. Tell the maintainers before you change the code.

## 3. Make a branch

Do not change `main` directly. Make a branch for each change:

1. Get the latest `main`: `git switch main` and then `git pull --ff-only`.
2. Make the branch: `git switch -c <short-name>`. Use a short name that tells the change, for example `fix-ssh-banner`.

## 4. Change the code

Obey these rules for each change:

- Write a failing test first. Then write the code that makes it pass.
- Put user-facing text in the `messages.rs` file of the crate. Add each text to the `ALL` list.
- Write all text in STE: code comments, CLI help, messages, documents, and commit messages.
- Do not add a network crate to `pqaudit-scan-files`. The file scan must not open sockets.
- Never write private key bytes to results, logs, reports, or error messages.

If you change the `ResultsFile` types, make the JSON Schema again. Run `PQAUDIT_UPDATE_SCHEMA=1 cargo test -p pqaudit-core --test results`. Commit the changed `schema/pqr.schema.json`.

If you change a fixture script, all fixture keys change. The scripts are `crates/pqaudit-scan-files/tests/generate.sh` and `generate-keys.sh`. Run the full test suite after you run a script.

## 5. Check the change

Run these checks before each commit. CI runs the same checks.

1. Format: `cargo fmt --check`.
2. Lint: `cargo clippy --workspace --all-targets --locked -- -D warnings`.
3. Tests: `cargo test --workspace --locked`.
4. Offline rule: `cargo --locked xtask check-offline-deps`.
5. Make the STE text files: `cargo --locked xtask strings --out target/ste --commits main..HEAD`.
6. STE lint: `VALE=.tools/vale .github/scripts/ste-lint.sh`.

Each check must show no errors. Do not commit code that fails a check.

## 6. Commit the change

Make small commits. Each commit holds one change that you can explain in one sentence.

1. Look at the change: `git status` and `git diff`.
2. Add only the files of this change: `git add <files>`. Do not use `git add -A` without a check of the file list.
3. Commit with a signature: `git commit -S`.

Write the commit message in STE:

- Write the first line in the imperative form, for example `Add the SSH probe`.
- Do not put a type prefix such as `feat:` in the first line.
- Keep the first line short. Use 60 characters or fewer.
- In the body, use 6 sentences or fewer in each paragraph. The lint joins the body lines into one paragraph.

Do not commit secrets, private keys, or `redact.key` files. Test keys go only in `tests/fixtures/`.

## 7. Push and merge

1. Push the branch: `git push -u origin <short-name>`.
2. Open a pull request to `main`.
3. Wait until all CI jobs pass: `fmt`, `clippy`, `test` on three systems, `ste`, and `offline`.
4. Get a review from a second maintainer.
5. Merge the pull request. Keep the history linear.
6. Delete the branch after the merge.

## 8. Change a dependency

1. Update one crate at a time: `cargo update -p <crate>`.
2. Look at the change in `Cargo.lock`. Find out why each new crate is there.
3. Run all the checks in section 5.
4. If you add, remove, or change a cryptography crate, update `docs/self-crypto.toml`.

The release workflow runs `cargo --locked xtask self-cbom`. That command fails if `docs/self-crypto.toml` does not agree with the SBOM.

## 9. Change the rules pack

The rules pack is in the `rules/` folder. The binary contains it.

- Each change to a file in `rules/` changes the content hash of the pack.
- A report needs the same pack as the scan that made the results. Scan again after a pack change.
- For a deadline milestone, give `source_url` and an `as_of` date. Check the date on the primary source page.
- Increase `version` in `rules/pack.toml` for each pack release.

To send a pack to users without a new binary, do these steps on the computer that holds the pack key:

1. Make the archive: `cargo --locked xtask pack-rules --out <dir>`.
2. Sign it: `cargo --locked xtask sign --keys <pack-key-dir> <archive>`.
3. Give users the archive and its `.sig.json` file.

## 10. Version numbers

pqaudit uses semantic versions, `MAJOR.MINOR.PATCH`.

- Increase PATCH for a fix that does not change behaviour that users rely on.
- Increase MINOR for a new feature.
- Increase MAJOR for a change that breaks a command, a file format, or an output that users rely on.

The tool version is `version` in the workspace `Cargo.toml`. The pack version is in `rules/pack.toml`. These two versions are separate. Change `schema_version` in the results file only for a change that old readers cannot read.

## 11. Make a release

Before the first tag, replace the development key. The file `rules/trust/keys.toml` starts with the text `DEVELOPMENT KEY`. Make the real pack key with `cargo --locked xtask keygen --out <dir>` on the offline computer. Put its public key in `rules/trust/keys.toml` and remove the development key. The release workflow stops if the file still has the text `DEVELOPMENT KEY`.

Before the first release, make two environments in the GitHub settings of the repository:

- `release-signing`: add the reviewers that must approve a run. Add the signing secrets that `release.yml` names.
- Only the jobs `sign-macos` and `sign-windows` use `release-signing`.
- `release`: add the reviewers that must approve a run.
- For `release`, set the deployment rule to selected branches and tags. Add only the tag pattern `v*`.
- Only the job `release` uses `release`. This job can write to the repository and get an OIDC token.

Also protect the tags `v*` with a ruleset. Then only the maintainers can make or move a release tag. The job `release` also stops if the commit of the tag is not on `main`.

Do the release steps in this order:

1. Make sure that `main` passes all CI jobs.
2. Change `version` in the workspace `Cargo.toml`. Run `cargo build --locked` to update `Cargo.lock`.
3. Write the release notes from `.github/release-notes-template.md`.
4. Commit and merge these changes through a pull request.
5. Make a signed tag on `main`: `git tag -s v<version>`. Write the release key fingerprints in the tag message.
6. Push the tag: `git push origin v<version>`.
7. Wait for the release workflow.
8. Approve the `release-signing` environment in GitHub. Then approve the `release` environment. That job makes a draft release.
9. Download the draft release files to the computer that holds the release key.
10. Sign the checksums with `xtask sign-release`. Give the commit of the tag with `--commit`.
11. Sign the rules archive: `cargo --locked xtask sign --keys <pack-key-dir> <rules-archive>`.
12. Upload all the new signature files to the draft release.
13. Do all the checks in `docs/verifying.md` on the downloaded files.
14. Publish the release.

For step 5, get the SHA-256 fingerprint of each release public key:

```text
openssl pkey -pubin -in release-keys/release-ed25519.pub.pem -outform DER | sha256sum
openssl pkey -pubin -in release-keys/release-mldsa65.pub.pem -outform DER | sha256sum
```

Also put the fingerprints on the project site. Customers compare them with the keys in the repository.

For step 10, run this command:

```text
cargo --locked xtask sign-release --keys <release-key-dir> --dir <download-dir> --repo mor-sec/pqaudit --tag v<version> --commit <commit>
```

Get `<commit>` with `git rev-parse 'v<version>^{commit}'`. The task accepts only bundles from the workflow run of that tag on that commit.

If a check in step 13 fails, do not publish. Delete the draft and the tag. Fix the problem and start again with a new version number.

For a test release, use a tag such as `v0.1.0-rc.1`. Delete the test release after the checks.

## 12. Keep the signing keys safe

The maintainers keep two key pairs offline: the pack key and the release key. Each pair has an Ed25519 part and an ML-DSA-65 part.

- Keep the private key files and a backup on a computer that is not on the network.
- Never put a private key in the repository, in CI, or in a GitHub secret.
- To make a new key pair, run `cargo --locked xtask keygen --out <dir>`.

If you lose a key or if a person steals it, do these steps:

1. Make a new key pair.
2. Put the new public key in `rules/trust/keys.toml`.
3. Put the ID of the old key in the `revoked` list in the same file.
4. Make a new release of the binary.

To change the pack key without a new binary, add a rotation statement to the next pack. The old key signs the statement. The binary then trusts the new key.
