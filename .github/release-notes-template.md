# pqaudit <version>

## Changes

- Write the changes of this release here. Use one short sentence for each change.

## Rules pack version

The default rules pack in this release has the version <pack-version>. The pack archive and its signature file are in the release files.

## Verifying this release

Check each file before you use it. The short form is below. The commit of the tag is <commit>. Compare it with the output of `git rev-parse '<tag>^{commit}'` after `git tag -v <tag>`.

```text
gh attestation verify <file> --repo mor-sec/pqaudit --signer-workflow mor-sec/pqaudit/.github/workflows/release.yml --source-ref refs/tags/<tag> --source-digest <commit>
cosign verify-blob <file> --bundle <file>.sigstore.json --certificate-identity 'https://github.com/mor-sec/pqaudit/.github/workflows/release.yml@refs/tags/<tag>' --certificate-oidc-issuer https://token.actions.githubusercontent.com --certificate-github-workflow-sha <commit>
```

Use the pinned version of cosign: <cosign-version>. Check the hybrid post-quantum signature of `SHA256SUMS` with OpenSSL 3.5 or later. Then run `sha256sum -c SHA256SUMS`. The full steps are in the file `docs/verifying.md` of the repository, at the tag of this release.

The public keys for the hybrid signature are below. Compare their fingerprints with the fingerprints on the project site and in the signed tag.

- Ed25519: <ed25519-public-key-pem>
- ML-DSA-65: <mldsa65-public-key-pem>

## Known limits

- This release has no code scan, no board report, and no PDF output.
- The deadline profiles are `us`, `uk`, and `au` only.
- The file scan stops at the first private-key entry in a JCEKS key store.
- The file scan does not read `.kbx` GPG key stores.
- Add the known limits of this release here.
