#!/usr/bin/env bash
# Make the test keys in the directory "fixtures/keys".
# This script needs OpenSSL 3.5 or later, ssh-keygen, and gpg.
# All keys are for tests only. They protect nothing.
# The password of each encrypted key is "pqaudit-test".
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/fixtures/keys"
work="$(mktemp -d)"
trap 'gpgconf --homedir "$work/gnupg" --kill all 2>/dev/null || true; rm -rf "$work"' EXIT
rm -rf "$out"
mkdir -p "$out"
pass="pqaudit-test"

# SSH keys. The comment of each key shows the key name.
for spec in "rsa -b 2048" "rsa1024 -b 1024" "ecdsa -b 256" "ed25519"; do
  set -- $spec
  name="$1"
  type="${name%1024}"
  ssh-keygen -q -t "$type" "${@:2}" -N "" -C "ssh-$name@ssh.example.test" -f "$out/id_$name"
done
ssh-keygen -q -t ed25519 -N "$pass" -C "ssh-ed25519-enc@ssh.example.test" -f "$out/id_ed25519_enc"

# An authorized_keys file. One line has options. One line is a comment.
{
  echo "# Test keys"
  cat "$out/id_rsa.pub"
  echo "command=\"/bin/true\",no-pty $(cat "$out/id_ecdsa.pub")"
  cat "$out/id_ed25519.pub"
  cat "$out/id_rsa.pub"
} >"$out/authorized_keys"

# A known_hosts file. The first 2 lines have plain host names. The last 2 lines have hashed names.
{
  echo "plain.pqaudit.test,192.0.2.10 $(cut -d' ' -f1,2 "$out/id_ed25519.pub")"
  echo "other.pqaudit.test $(cut -d' ' -f1,2 "$out/id_rsa.pub")"
  echo "hashed1.pqaudit.test $(cut -d' ' -f1,2 "$out/id_ecdsa.pub")"
  echo "hashed2.pqaudit.test $(cut -d' ' -f1,2 "$out/id_ed25519.pub")"
} >"$work/known_hosts"
ssh-keygen -q -H -f "$work/known_hosts" 2>/dev/null
# Keep the plain lines and the hashed lines in one file.
{
  head -n 2 "$work/known_hosts.old"
  tail -n 2 "$work/known_hosts"
} >"$out/known_hosts"

# PEM keys from OpenSSL.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$out/pkcs8-rsa.pem"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$out/pkcs8-ec.pem"
openssl genpkey -algorithm ED25519 -out "$out/pkcs8-ed25519.pem"
openssl pkcs8 -topk8 -in "$out/pkcs8-rsa.pem" -v2 aes-256-cbc -passout "pass:$pass" \
  -out "$out/pkcs8-rsa-enc.pem"
openssl rsa -in "$out/pkcs8-rsa.pem" -traditional -out "$out/pkcs1-rsa.pem" 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out "$out/sec1-ec.pem"
openssl pkey -in "$out/pkcs8-rsa.pem" -pubout -out "$out/spki-rsa.pem"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out "$out/pkcs8-rsa1024.pem"

# Post-quantum keys. A certificate for the ML-KEM key is signed with an ML-DSA key.
openssl genpkey -algorithm ML-KEM-768 -out "$out/pkcs8-mlkem768.pem"
openssl pkey -in "$out/pkcs8-mlkem768.pem" -pubout -out "$out/spki-mlkem768.pem"
openssl genpkey -algorithm ML-DSA-65 -out "$work/mldsa.key"
openssl x509 -new -force_pubkey "$out/spki-mlkem768.pem" -key "$work/mldsa.key" \
  -subj "/CN=mlkem768.test" -days 365 -out "$out/cert-mlkem768.pem"

# GnuPG keys. The home directory is a temporary directory.
export GNUPGHOME="$work/gnupg"
mkdir -m 700 "$GNUPGHOME"
gpg --batch --quiet --passphrase "" --quick-gen-key "Test RSA <rsa@pqaudit.test>" rsa3072 default never
gpg --batch --quiet --passphrase "" --quick-gen-key "Test Ed25519 <ed@pqaudit.test>" ed25519 default never
rsa_fpr="$(gpg --list-keys --with-colons rsa@pqaudit.test | awk -F: '$1=="fpr" {print $10; exit}')"
ed_fpr="$(gpg --list-keys --with-colons ed@pqaudit.test | awk -F: '$1=="fpr" {print $10; exit}')"
gpg --batch --quiet --passphrase "" --quick-add-key "$rsa_fpr" rsa3072 encr never
gpg --batch --quiet --passphrase "" --quick-add-key "$ed_fpr" cv25519 encr never
gpg --export rsa@pqaudit.test >"$out/gpg-rsa3072.pub.gpg"
gpg --armor --export ed@pqaudit.test >"$out/gpg-ed25519.pub.asc"
gpg --batch --pinentry-mode loopback --passphrase "" --export-secret-keys rsa@pqaudit.test \
  >"$out/gpg-rsa3072.sec.gpg"
gpg --batch --pinentry-mode loopback --passphrase "" --armor --export-secret-keys ed@pqaudit.test \
  >"$out/gpg-ed25519.sec.asc"
# The fingerprints (version 4, lower case hex) of all keys. The tests use them as the oracle.
gpg --with-colons --fingerprint --list-keys | awk -F: '$1=="fpr" {print tolower($10)}' \
  >"$out/gpg-fingerprints.txt"
# The key box of GnuPG 2.1 and later.
gpgconf --kill all 2>/dev/null || true
cp "$GNUPGHOME/pubring.kbx" "$out/pubring.kbx"

chmod 644 "$out"/*
echo "Made the fixtures in $out"
