#!/usr/bin/env bash
# root-sign.sh — sign an NTM delegation document with ONE root key.
#
# RUN BY THE PROJECT OWNER ONLY, in their own terminal (never in an agent
# session, never with a `!` prefix). docs/signing-trust-model.md §8.
#
# Usage (from the repo root, on the Mac):
#   scripts/trust/root-sign.sh r1 signing/delegation.txt   # seed read from Keychain
#   scripts/trust/root-sign.sh r2 signing/delegation.txt   # seed typed from the card
#
# Output: signing/delegation.txt.<rN>.sig  (public; commit it or post it)
#
# The seed is never echoed and never written to disk: the private key exists
# only inside a pipe for the duration of one openssl call. The script refuses
# to write a signature unless it verifies against signing/roots/<rN>.pub.der,
# so a mistyped card fails here instead of producing a useless signature.
#
# Portable to macOS /bin/bash 3.2 and zsh-launched shells. ASCII only.

set -eu

die() { echo "ERROR [root-sign]: $*" >&2; exit 1; }

[ $# -eq 2 ] || die "usage: $0 <r1|r2|r3> <delegation-file>"
ROOT="$1"; DOC="$2"
case "$ROOT" in r1|r2|r3) ;; *) die "root must be r1, r2 or r3" ;; esac
[ -f "$DOC" ] || die "no such file: $DOC"
PUB="signing/roots/${ROOT}.pub.der"
[ -f "$PUB" ] || die "run from the repo root ($PUB not found)"
OUT="${DOC}.${ROOT}.sig"
[ ! -e "$OUT" ] || die "$OUT already exists; delete it first if you mean to re-sign"

# Homebrew OpenSSL >= 3.5 (macOS /usr/bin/openssl is LibreSSL: no ML-DSA).
if command -v brew >/dev/null 2>&1; then
    PATH="$(brew --prefix openssl@3)/bin:$PATH"
fi
openssl list -signature-algorithms 2>/dev/null | grep -q ML-DSA-65 \
    || die "this openssl has no ML-DSA-65 (need OpenSSL >= 3.5: brew install openssl@3)"

head -1 "$DOC" | grep -qx 'ntm-delegation 1' || die "$DOC is not an ntm-delegation document"
echo "Signing with root $ROOT:"
sed -n '2,3p' "$DOC"
echo "  keys: $(grep -c '^key: ' "$DOC")    sha256: $(openssl dgst -sha256 -r "$DOC" | cut -c1-64)"
echo

SEED=""
if [ "$ROOT" = r1 ]; then
    SEED=$(security find-generic-password -s ntm-root-r1 -w) || die "ntm-root-r1 not found in Keychain"
else
    printf 'Type the %s card (spaces allowed), then Enter: ' "$ROOT" >&2
    read -rs SEED; echo >&2
    SEED=$(printf '%s' "$SEED" | tr -d ' ')
fi
printf '%s' "$SEED" | grep -Eq '^[0-9a-fA-F]{64}$' || { SEED=""; die "seed is not 64 hex characters"; }

tmp="${OUT}.tmp"
trap 'rm -f "$tmp"; SEED=""' EXIT
openssl pkeyutl -sign -rawin \
    -inkey <(openssl genpkey -algorithm ML-DSA-65 -pkeyopt "hexseed:$SEED") \
    -in "$DOC" -out "$tmp"
SEED=""

openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$PUB" -in "$DOC" -sigfile "$tmp" >/dev/null 2>&1 \
    || die "signature does NOT verify against $PUB (wrong card / typo?) - nothing written"
mv "$tmp" "$OUT"
echo "OK: $OUT ($(wc -c < "$OUT" | tr -d ' ') bytes) verifies against $PUB"
