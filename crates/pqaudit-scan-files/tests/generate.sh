#!/usr/bin/env bash
# Make the test certificates in the directory "fixtures".
# This script needs OpenSSL 3.5 or later. It needs 3.5 for ML-DSA.
# All keys are for tests only. The script deletes each key after it signs.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/fixtures"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
rm -rf "$out"
mkdir -p "$out"

# Make a self-signed certificate. Arguments: name, subject, days, key option, extra options.
# OpenSSL makes a CA by default. Each leaf adds "CA:FALSE".
selfsigned() {
  local name="$1" subject="$2" days="$3" keyopt="$4"
  shift 4
  openssl req -x509 -newkey "$keyopt" -nodes -keyout "$work/$name.key" \
    -out "$out/$name.pem" -subj "$subject" -days "$days" "$@" 2>/dev/null
}

selfsigned rsa2048-leaf "/CN=rsa2048.test" 365 rsa:2048 -sha256 -addext "basicConstraints=CA:FALSE"
selfsigned rsa1024-leaf "/CN=rsa1024.test" 365 rsa:1024 -sha256 -addext "basicConstraints=CA:FALSE"
selfsigned ecdsa-p256-ca "/CN=ecdsa-ca.test" 3650 ec -pkeyopt ec_paramgen_curve:P-256 \
  -sha256 -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=keyCertSign,cRLSign"
selfsigned rsa2048-sha1 "/CN=sha1.test" 365 rsa:2048 -sha1 -addext "basicConstraints=CA:FALSE"
selfsigned mldsa65 "/CN=mldsa65.test" 365 ML-DSA-65 -addext "basicConstraints=CA:FALSE"

# A chain of 3 certificates in one PEM file: a root, an intermediate, and a leaf.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/root.key" \
  -out "$work/root.pem" -subj "/CN=chain-root.test" -days 3650 -sha256 \
  -addext "basicConstraints=critical,CA:TRUE" 2>/dev/null
for level in intermediate leaf; do
  parent=root
  [ "$level" = leaf ] && parent=intermediate
  ext="basicConstraints=critical,CA:TRUE"
  [ "$level" = leaf ] && ext="basicConstraints=CA:FALSE"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$work/$level.key" \
    -out "$work/$level.csr" -subj "/CN=chain-$level.test" 2>/dev/null
  printf '%s\n' "$ext" >"$work/$level.ext"
  openssl x509 -req -in "$work/$level.csr" -CA "$work/$parent.pem" -CAkey "$work/$parent.key" \
    -CAcreateserial -out "$work/$level.pem" -days 365 -sha256 -extfile "$work/$level.ext" 2>/dev/null
done
cat "$work/leaf.pem" "$work/intermediate.pem" "$work/root.pem" >"$out/chain3.pem"

# A DER certificate.
openssl x509 -in "$out/rsa2048-leaf.pem" -outform DER -out "$out/rsa2048-leaf.der"

echo "Made the fixtures in $out"
