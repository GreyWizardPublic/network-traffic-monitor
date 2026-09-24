#!/usr/bin/env bash
# verify-bundle.sh — check an NTMSIG 2 bundle with the OpenSSL CLI.
#
# Usage: scripts/trust/verify-bundle.sh <binary> [<sig>] [platform]
#   sig defaults to <binary>.sig; platform defaults to one inferred from the
#   file name (…-windows-amd64-…/.exe → windows-amd64, else linux-amd64).
#
# An independent, script-side cross-check of src/trust.hpp: >= 2 valid root
# signatures over the embedded delegation (against signing/roots/), the key id
# present and scoped to the platform, and the binary signature valid. It does
# NOT check expiry or the rollback floor (runtime policy).

set -euo pipefail
NTM_TOOL=verify-bundle
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ $# -ge 1 && $# -le 3 ]] || ntm_die "usage: $0 <binary> [<sig>] [platform]"
BINARY="$1"; SIG="${2:-$1.sig}"
case "$BINARY" in *windows-amd64*|*.exe) guess=windows-amd64 ;; *) guess=linux-amd64 ;; esac
PLATFORM="${3:-$guess}"
[[ -f "$BINARY" && -f "$SIG" ]] || ntm_die "binary or signature missing"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mapfile -t L < <(tr -d '\r' < "$SIG")
[[ "${L[0]:-}" == "NTMSIG 2" ]] || ntm_die "not an NTMSIG 2 bundle"
[[ "${L[1]:-}" == "delegation: "* ]] || ntm_die "bad delegation line"
printf '%s' "${L[1]#delegation: }" | openssl base64 -d -A > "$tmp/doc"

valid=0; i=2
while [[ "${L[$i]:-}" =~ ^root-sig:\ (r[1-3])\ ([A-Za-z0-9+/=]+)$ ]]; do
    r="${BASH_REMATCH[1]}"
    printf '%s' "${BASH_REMATCH[2]}" | openssl base64 -d -A > "$tmp/$r.sig"
    if openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$NTM_REPO_ROOT/signing/roots/$r.pub.der" \
           -in "$tmp/doc" -sigfile "$tmp/$r.sig" >/dev/null 2>&1; then
        valid=$((valid + 1)); echo "  root $r: valid"
    else
        echo "  root $r: INVALID"
    fi
    i=$((i + 1))
done
(( valid >= 2 )) || ntm_die "$valid valid root signature(s); 2 required"

[[ "${L[$i]:-}" =~ ^key-id:\ ([a-z0-9-]+)$ ]] || ntm_die "bad key-id line"
KEY_ID="${BASH_REMATCH[1]}"
[[ "${L[$((i + 1))]:-}" =~ ^signature:\ ([A-Za-z0-9+/=]+)$ ]] || ntm_die "bad signature line"
printf '%s' "${BASH_REMATCH[1]}" | openssl base64 -d -A > "$tmp/bin.sig"
(( ${#L[@]} == i + 2 )) || ntm_die "trailing lines after signature"

NTM_DELEGATION="$tmp/doc" ntm_delegated_spki "$KEY_ID" "$PLATFORM" "$tmp/key.der"
openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$tmp/key.der" \
    -in "$BINARY" -sigfile "$tmp/bin.sig" >/dev/null 2>&1 || ntm_die "binary signature INVALID"

echo "OK: $(basename "$BINARY") — $KEY_ID ($PLATFORM), $valid root sig(s), $(sed -n 2p "$tmp/doc"), $(sed -n 3p "$tmp/doc")"
