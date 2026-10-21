# pqaudit

```text
         _________                .~~~~~~~~~~~~~~~~~~~~~~~~~~~.
        /  _____  \               |  RSA-2048 ....... [ !! ]  |
       |  |     |  |              |  ECDSA P-256 .... [ !! ]  |
       |  |     |  |              |  X25519MLKEM768 . [ OK ]  |
   ____|__|_____|__|____          |  ML-DSA-65 ...... [ OK ]  |
  |  o---o---o---o---o  |         '~~~~~~~~~~~~~~~~~~~~~~~~~~~'
  |  | \ | / | \ | / |  |
  |  o---o-[0x50]-o--o  |                              _ _ _
  |  | / | \ | / | \ |  |    _ __   __ _  __ _ _   _  __| (_) |_
  |  o---o-[0x51]-o--o  |   | '_ \ / _` |/ _` | | | |/ _` | | __|
  |  | \ | / | \ | / |  |   | |_) | (_| | (_| | |_| | (_| | | |_
  |  o---o---o---o---o  |   | .__/ \__, |\__,_|\__,_|\__,_|_|\__|
  |_____________________|   |_|       |_|
       lattice locked         find it. score it. fix it.
```

`pqaudit` is a command-line tool for post-quantum readiness audits. It finds the cryptography that a system uses. It shows which parts a quantum computer can break. It also shows what to fix first.

Security consultants and security teams use it in an engagement. A scan finds certificates, keys, and TLS and SSH endpoints. The tool then adds the context of the client: how important the data is, and how far an attacker can reach the system. The result is a technical report with a suggested priority and a deadline for each finding. You can see how the tool calculates each score. You can change each priority with an override.

## Installation

1. Download the file for your system from the releases page of the project.
2. Check the file. The steps are in [docs/verifying.md](docs/verifying.md).
3. Put the `pqaudit` file in a directory in your path.

The release files are for Linux (x86_64 and aarch64), macOS (universal), and Windows (x86_64 and arm64). The tool is one file. It does not need an installer or a service.

## Quick start

This example uses only the commands of Stage 1. The tool makes a folder for the engagement. All the files of the engagement stay in that folder.

```text
pqaudit init acme-2026q4
# Edit engagement.toml, scope.toml, and assets.toml in the new folder.

pqaudit --engagement acme-2026q4 scan net --dry-run
pqaudit --engagement acme-2026q4 scan net
pqaudit --engagement acme-2026q4 scan files /etc /opt/app
pqaudit --engagement acme-2026q4 merge acme-2026q4/results/net-*.pqr acme-2026q4/results/files-*.pqr
pqaudit --engagement acme-2026q4 report --format html
pqaudit --engagement acme-2026q4 cbom
pqaudit --engagement acme-2026q4 explain F-1a2b3c4d
```

You can do each step on a different computer. A person with network access runs `scan net`. A person on the target hosts runs `scan files`. The client can read the raw results before they leave the client network. Then one person merges the results files and makes the reports.

The [user guide](docs/user-guide.md) describes each file, each command, and each flag.

## Trusting pqaudit in your environment

This section is for the security team of a client. It tells what the tool does and what it does not do. Each statement below is a property of the tool. You can check each one.

### The scope model

- The file `scope.toml` is the only source of network targets.
- The command `scan net` connects only to the `host:port` pairs in that file.
- The tool refuses all other targets. The tool cannot connect to a host that the scope file does not list.
- The tool resolves each host name one time, at the start.
- If `require_ip_in_cidr` is `true`, an address outside `allowed_cidrs` makes the tool refuse the full scan. It exits with code 2.
- The default of `require_ip_in_cidr` is `true` only if `allowed_cidrs` or a CIDR target exists.
- A scope with host names needs `allowed_cidrs` or a CIDR target. Otherwise the tool stops with exit code 1.
- To accept all addresses for host names, set `require_ip_in_cidr = false`.
- A host name must not resolve to a loopback, link-local, multicast, or unspecified address.
- Only an IP or CIDR target can name such an address.
- The tool rejects IP addresses that are not canonical, such as `10.1` or `0x0a.0.0.1`.
- A host name with one label must end with a dot.
- An `exclude` entry has priority over a target.
- The tool does not follow redirects, SRV records, or MX records.
- The file `scope.toml` that `init` makes has no targets. The command `scan net` does nothing until you add a target.

The command `scan net --dry-run` shows each target, port, protocol, and number of connections. Then it stops. It makes no connection to a target. It does ask the DNS to resolve the host names.

### The gentle defaults

Most network limits are maximum values. You can lower them. You can raise them only if `scope.toml` has `override_limits = true`. The minimum interval is the reverse.

- 4 connections at the same time in total, and 1 for each host.
- At least 1000 ms between two connections to the same host. A lower value needs `override_limits`.
- At most 3 TLS handshakes for each IP address and port, for all host names together.
- 1 connection for each SSH port.
- A connect timeout of 5000 ms and a read timeout of 10000 ms.
- No retries.

You can also set `allowed_hours`. The tool does not start outside these hours.

### The audit log

The tool adds lines to the file `audit.log` in the engagement folder. Each line is JSON. Each connection has a "started" line and a final line.

A line shows the time, the source address, the destination, the port, the protocol, the probe, the result, and the bytes sent and received. The results file holds the hash of the log. You can give the log to the client as proof of each connection. If the tool cannot write to the log, it makes no more connections.

### Offline modes that open no sockets

The command `scan files` does not use the network. It does not do DNS or HTTP. The code that scans files does not depend on any network library. A check in the build of the project makes sure of this.

The commands `merge`, `report`, `cbom`, `explain`, `profiles`, and `rules` also make no network connection. The command `rules update` reads a local file. The tool never gets a rules pack from the network.

### Private keys

The file scan reads the type of a key, its size or curve, and its public parts. It never writes private key bytes to results, logs, reports, or error messages. The tool reads key files into buffers that it wipes after use.

There are two limits. The PKCS#12 library decrypts key bags into memory that the tool cannot wipe, and the tool drops them early. A call to a library can leave a short copy on the stack.

If a key store has encryption and you give no password, the tool records "encrypted - not inspected". The tool does not read a password from the command line. A password in an environment variable stays in the process environment. Libraries get copies of passwords.

### Redacted results

The command `merge --redact` replaces host names, addresses, paths, names, banners, and key comments with keyed hashes. Keep the key file `redact.key` private.

Fingerprints, certificate hashes, and key hashes also become keyed hashes. Finding IDs come from the keyed fingerprints. Without the key, a person cannot compare them with a known certificate, key, or IP address. Overrides still apply to a redacted file when the engagement folder holds `redact.key`. Do not treat a redacted file as anonymous. The algorithms, dates, and counts stay.

### Signed releases, the SBOM, and the CBOM

Each release has these items:

- build provenance from GitHub Actions, with a Sigstore bundle for each file,
- an SBOM in CycloneDX format, and the list of dependencies inside each binary,
- a CBOM of the tool itself,
- a hybrid post-quantum signature (Ed25519 and ML-DSA-65) on the file `SHA256SUMS`,
- the native signature for Windows and macOS, when the maintainers have the certificates for it.

The file [docs/verifying.md](docs/verifying.md) gives the commands to check each item. Most checks work without a network connection. The command `gh attestation verify` needs a network.

## Summary of the safety model

1. The scope is explicit. The tool refuses all other targets.
2. Exclusions have priority over targets.
3. The default limits are gentle. A higher limit needs an explicit flag in `scope.toml`.
4. The option `--dry-run` shows the plan and then stops.
5. The audit log has a record of each connection attempt.
6. The offline modes never open sockets.
7. The tool never writes private key bytes to its output. Refer to the section "Private keys" for the limits.
8. The tool does not change the systems that it scans. Scans write in the engagement folder. `--output`, `rules update`, and `init --dir` can write elsewhere.

## Limits of Stage 1

This release is Stage 1. These features are not in it:

- There is no code scan. The command `scan code` does not exist yet.
- There is no board report. The command `report --audience board` exits with code 1.
- There is no PDF output. The command `report --format pdf` exits with code 1.
- There is no `export` command.
- The deadline profiles are `us`, `uk`, and `au` only.

The [user guide](docs/user-guide.md) lists more known limits of the file scan and the network scan.

## Test keys

The private keys in `crates/pqaudit-scan-files/tests/fixtures/` are test data. The scripts in `crates/pqaudit-scan-files/tests/` make them. No system uses them.

## Licence

You can use this project under the Apache License, Version 2.0, or under the MIT licence. You choose one. The files `LICENSE-APACHE` and `LICENSE-MIT` have the full text.
