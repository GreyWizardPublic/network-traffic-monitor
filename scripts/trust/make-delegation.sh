#!/usr/bin/env bash
# make-delegation.sh — write an unsigned NTM delegation document.
#
# Usage:
#   scripts/trust/make-delegation.sh <version> <expires> <out-file> <id>:<platform>:<spki.der> [...]
#
# Example:
#   scripts/trust/make-delegation.sh 1 2027-04-23T00:00:00Z signing/delegation.txt \
#       linux-build:linux-amd64:signing/keys/linux-build.pub.der \
#       windows-build:windows-amd64:signing/keys/windows-build.pub.der
#
# The document is the exact byte string the root keys sign. Grammar (strict;
# enforced by src/trust.hpp — any deviation is rejected):
#
#   ntm-delegation 1\n
#   version: <decimal, 1..2^63-1, no leading zeros>\n
#   expires: <YYYY-MM-DDTHH:MM:SSZ>\n
#   key: <id> <platform> ML-DSA-65 <base64 SPKI DER, unwrapped>\n     (1..8 lines)
#
# See docs/signing-trust-model.md §4. Public material only — no secrets here.

set -euo pipefail

die() { echo "ERROR [make-delegation]: $*" >&2; exit 1; }

[[ $# -ge 4 ]] || die "usage: $0 <version> <expires> <out-file> <id>:<platform>:<spki.der> [...]"

VERSION="$1"; EXPIRES="$2"; OUT="$3"; shift 3

[[ "$VERSION" =~ ^[1-9][0-9]{0,17}$ ]] || die "version must be a positive decimal without leading zeros"
[[ "$EXPIRES" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] \
    || die "expires must be YYYY-MM-DDTHH:MM:SSZ"
[[ $# -le 8 ]] || die "at most 8 keys"

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

{
    printf 'ntm-delegation 1\n'
    printf 'version: %s\n' "$VERSION"
    printf 'expires: %s\n' "$EXPIRES"
} > "$tmp"

declare -A seen=()
for spec in "$@"; do
    IFS=: read -r id platform der <<< "$spec"
    [[ "$id" =~ ^[a-z0-9-]{1,32}$ ]] || die "bad key id '$id'"
    [[ "$platform" == linux-amd64 || "$platform" == windows-amd64 ]] \
        || die "unknown platform '$platform'"
    [[ -z "${seen[$id]:-}" ]] || die "duplicate key id '$id'"
    seen[$id]=1
    [[ -f "$der" ]] || die "no such file: $der"
    openssl pkey -pubin -inform DER -in "$der" -text -noout 2>/dev/null \
        | grep -q '^ML-DSA-65 Public-Key' || die "$der is not an ML-DSA-65 SPKI"
    printf 'key: %s %s ML-DSA-65 %s\n' "$id" "$platform" "$(openssl base64 -A -in "$der")" >> "$tmp"
done

mv "$tmp" "$OUT"
trap - EXIT
echo "[make-delegation] wrote $OUT ($(wc -c < "$OUT") bytes)"
echo "[make-delegation] sha256 $(openssl dgst -sha256 -r "$OUT" | cut -c1-64)"
