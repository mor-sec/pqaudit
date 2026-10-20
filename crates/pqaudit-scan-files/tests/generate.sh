#!/usr/bin/env bash
# Make the test certificates in the directory "fixtures".
# This script needs OpenSSL 3.5 or later. It needs 3.5 for ML-DSA.
# All keys are for tests only. The script deletes each key after it signs.
# The PKCS#12 files are the exception: the tests keep their key DER files.
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

# An RSA-PSS key in the certificate.
openssl req -x509 -newkey rsa-pss -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha256 \
  -nodes -keyout "$work/pss.key" -out "$out/rsa-pss.pem" -subj "/CN=rsa-pss.test" -days 365 \
  -addext "basicConstraints=CA:FALSE" 2>/dev/null

# The OpenSSL trusted form of a certificate. It has trust data after the certificate.
openssl x509 -in "$out/rsa2048-leaf.pem" -trustout -addtrust serverAuth -out "$out/trusted.pem"

# A PEM file with no certificate. This block has an unknown label.
printf -- '-----BEGIN TEST DATA-----\nAAAA\n-----END TEST DATA-----\n' >"$out/other-block.pem"

# A DER certificate.
openssl x509 -in "$out/rsa2048-leaf.pem" -outform DER -out "$out/rsa2048-leaf.der"

# PKCS#12 files. Each file has a test key and a certificate.
# The tests need the key DER bytes. They check that no key bytes reach the results.
# One file has the empty password. The other has the password "pqaudit-test".
for variant in empty pw; do
  pass=""
  [ "$variant" = pw ] && pass="pqaudit-test"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$work/p12-$variant.key" \
    -out "$work/p12-$variant.pem" -subj "/CN=p12-$variant.test" -days 365 -sha256 \
    -addext "basicConstraints=CA:FALSE" 2>/dev/null
  openssl pkcs12 -export -inkey "$work/p12-$variant.key" -in "$work/p12-$variant.pem" \
    -name "p12-$variant" -passout "pass:$pass" -out "$out/store-$variant.p12" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$work/p12-$variant.key" -outform DER \
    -out "$out/store-$variant.key.der"
  chmod 644 "$out/store-$variant.p12" "$out/store-$variant.key.der"
done

echo "Made the fixtures in $out"
