# Verifying this release

> Status: the project has no first release yet. Until then, these items are not confirmed: the file names of the release, the text that `cosign` prints, the TUF cache path, and the macOS checks. The release process checks each command again.

This document tells how to check a pqaudit release before you use it. Each check is separate. Do all of them if you can. Most checks do not need pqaudit. Only section 8 uses it.

In the commands below, `<file>` is the release file that you check. Use the name of the file as it appears in the release. The GitHub repository is `mor-sec/pqaudit`.

## What a release contains

- The binaries for each platform.
- A Sigstore bundle for each file, with the name `<file>.sigstore.json`.
- `SHA256SUMS` and `SHA3-256SUMS`.
- The hybrid post-quantum signatures of the checksum files: `SHA256SUMS.ed25519.sig` and `SHA256SUMS.mldsa65.sig`, and the same two for `SHA3-256SUMS`.
- The files `SHA256SUMS.sig.json` and `SHA3-256SUMS.sig.json`.
- The SBOM in CycloneDX 1.5 format, with the name `pqaudit-<tag>.sbom.cdx.json`.
- The CBOM of the tool in CycloneDX 1.6 format, with the name `pqaudit-<tag>.cbom.cdx.json`.
- The rules pack archive and its signature file.

The workflow `.github/workflows/release.yml` in the repository `mor-sec/pqaudit` builds the release. The workflow runs only for tags that start with `v`.

## 1. Check the build provenance

This check needs a network connection and the `gh` tool.

```text
gh attestation verify <file> --repo mor-sec/pqaudit
```

The command checks that the GitHub Actions workflow of this repository built the file. If the command fails, do not use the file.

## 2. Check the Sigstore bundle with cosign

This check also needs a network connection. It uses the bundle `<file>.sigstore.json`.

```text
cosign verify-blob <file> \
  --bundle <file>.sigstore.json \
  --certificate-identity-regexp '^https://github.com/mor-sec/pqaudit/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The certificate identity must be the path of the release workflow. The issuer must be the GitHub Actions issuer. The command prints `Verified OK` when the check passes.

## 3. Check without a network connection

You can check a file in a network that has no internet access. Do these steps before you go offline.

1. Get a current `trusted_root.json` from Sigstore TUF. Run `cosign initialize` while you are online.
2. Copy `trusted_root.json` from the TUF cache of cosign, for example `~/.sigstore/root/targets/`.
3. Get the file again before each check. It changes without a warning.
4. Download the release file and its bundle `<file>.sigstore.json`.
5. Use the pinned version of cosign that the release notes name. The offline flags change between versions.
6. Copy the file, the bundle, `trusted_root.json`, and the cosign binary to the offline computer.

Then run the check on the offline computer:

```text
cosign verify-blob <file> \
  --bundle <file>.sigstore.json \
  --trusted-root trusted_root.json \
  --certificate-identity-regexp '^https://github.com/mor-sec/pqaudit/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

If the check fails and the file is correct, the `trusted_root.json` can be too old. Get a new copy and try again.

## 4. Check the hybrid post-quantum signature

The maintainers sign the checksum files with two keys: Ed25519 and ML-DSA-65. They keep the keys offline. Both signatures must be correct. You need OpenSSL 3.5 or later. Run `openssl version` to see your version.

First get the public keys. They are in the folder `release-keys/` of the repository, on the website of the project, and in the release notes. Compare the three copies before you trust a key. Name the files `release-ed25519.pub.pem` and `release-mldsa65.pub.pem`.

Then run both commands:

```text
openssl pkeyutl -verify -pubin -inkey release-ed25519.pub.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.ed25519.sig
openssl pkeyutl -verify -pubin -inkey release-mldsa65.pub.pem -rawin -in SHA256SUMS -sigfile SHA256SUMS.mldsa65.sig
```

Each command must print `Signature Verified Successfully`. If one command fails, do not use the release.

Last, check the files against the checksums:

```text
sha256sum --ignore-missing -c SHA256SUMS
```

On macOS, use `shasum -a 256 -c SHA256SUMS`. For `SHA3-256SUMS`, use `openssl dgst -sha3-256 <file>` and compare the hash by eye. Use the signature files of that checksum file.

## 5. Check the operating system signature

The maintainers sign the Windows and macOS binaries with the native signature of the platform. A release can come without this signature if the maintainers had no certificate. The release notes say so.

On Windows, use PowerShell:

```text
Get-AuthenticodeSignature .\pqaudit.exe
```

The `Status` must be `Valid`. Check the name of the signer.

On macOS:

```text
codesign --verify --deep --strict --verbose=2 ./pqaudit
```

The command `codesign` must pass. Check the notarization with `xcrun stapler validate ./pqaudit` or with the `xcrun notarytool` history of the maintainers. The command `spctl --assess --type execute` is not confirmed for a bare command-line binary. It can report that the file does not seem to be an app.

## 6. Find the SBOM and compare it with the binary

The release has an SBOM in CycloneDX format. It is a release file, and it has its own Sigstore bundle. The workflow also attaches it to each binary as an attestation.

The binary holds its own list of dependencies, from `cargo auditable`. To read it, use `rust-audit-info`:

```text
rust-audit-info ./pqaudit
```

Compare the list with the SBOM. The crate names and versions must be the same. A difference is a reason to ask the maintainers.

## 7. Find the CBOM of the tool

The release has a CBOM of pqaudit itself. It is a CycloneDX 1.6 file with the cryptographic assets of the tool. It lists the algorithms for each purpose, such as TLS probes and signature checks. It has its own Sigstore bundle. You can read it as JSON.

## 8. Check a rules pack

The rules pack is a separate archive, for example `rules-1.0.0.tar.zst`. It has a signature file with the name `rules-1.0.0.tar.zst.sig.json`.

pqaudit checks the signature with trust keys that the build puts into the binary. The check does not need a network connection:

```text
pqaudit rules verify rules-1.0.0.tar.zst
```

The command exits with code 0 and prints the signing key when both signatures are correct. The release also has a Sigstore bundle for the archive. You can check it with the cosign commands in sections 2 and 3. The binary does not use that bundle.

To install the pack, run `pqaudit rules update --from rules-1.0.0.tar.zst`. The release notes name the version of the default pack in the binary.

## Appendix for maintainers: sign a release by hand

The CI builds the release and makes a draft. The maintainers sign the release offline, so that the signing keys never go into CI. The keys are the hybrid key pair of the release and the hybrid key pair for rules packs. Keep them on an offline computer.

1. Download all the files of the draft release into one empty folder.
2. Install the pinned version of cosign.
3. Run the signing task. It checks each Sigstore bundle with `cosign verify-blob`. It stops if a bundle is missing.

   ```text
   cargo xtask sign-release --keys <keys-dir> --dir <release-dir> --repo mor-sec/pqaudit
   ```

   The task computes `SHA256SUMS` and `SHA3-256SUMS` from the checked files. It writes them if they are not there. If one is there and is different, the task stops and signs nothing. Then it signs both files.

4. Sign the rules pack archive with the key pair for packs:

   ```text
   cargo xtask sign --keys <pack-keys-dir> <release-dir>/rules-<version>.tar.zst
   ```

   The task writes `.sig.json`, `.ed25519.sig`, and `.mldsa65.sig` files next to the archive.
5. Run the commands in sections 2 and 4 on the result.
6. Upload the signature files to the draft release. Publish the release.

To make a new key pair, run `cargo xtask keygen --out <dir>` on the offline computer. The task never overwrites a file. Put the private keys in safe offline storage. Add the public keys to the repository, the website, and the release notes. For a pack key, add the public keys to `rules/trust/keys.toml` and build a new binary.
