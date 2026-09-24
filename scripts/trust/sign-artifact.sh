#!/usr/bin/env bash
# sign-artifact.sh — sign a binary into an NTMSIG 2 bundle (<binary>.sig).
#
# Usage: scripts/trust/sign-artifact.sh <binary> [platform]
#   platform defaults to this host's (linux-amd64 / windows-amd64).
#
# Bundle = root-signed signing/delegation.txt + its root signatures + key id +
# this host's build-key signature over the binary. Grammar: src/trust.hpp.
# Fails (non-zero) if the delegation is not root-signed, the host key is
# missing or does not match the delegation, or the result does not verify.

set -euo pipefail
NTM_TOOL=sign-artifact
# shellcheck source=lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

[[ $# -ge 1 && $# -le 2 ]] || ntm_die "usage: $0 <binary> [platform]"
BINARY="$1"
PLATFORM="${2:-$(ntm_host_platform)}"
[[ -f "$BINARY" ]] || ntm_die "binary not found: $BINARY"

ntm_require_delegation
KEY_ID=$(ntm_key_id "$PLATFORM")

tmpsig=$(mktemp); bundle=$(mktemp)
trap 'rm -f "$tmpsig" "$bundle"' EXIT

ntm_build_sign "$PLATFORM" "$BINARY" "$tmpsig"

{
    printf 'NTMSIG 2\n'
    printf 'delegation: %s\n' "$(openssl base64 -A -in "$NTM_DELEGATION")"
    for n in 1 2 3; do
        s="$NTM_DELEGATION.r$n.sig"
        [[ -f "$s" ]] || continue
        openssl pkeyutl -verify -rawin -pubin -keyform DER \
            -inkey "$NTM_REPO_ROOT/signing/roots/r$n.pub.der" \
            -in "$NTM_DELEGATION" -sigfile "$s" >/dev/null 2>&1 || continue
        printf 'root-sig: r%s %s\n' "$n" "$(openssl base64 -A -in "$s")"
    done
    printf 'key-id: %s\n' "$KEY_ID"
    printf 'signature: %s\n' "$(openssl base64 -A -in "$tmpsig")"
} > "$bundle"

"$NTM_REPO_ROOT/scripts/trust/verify-bundle.sh" "$BINARY" "$bundle" "$PLATFORM" >/dev/null \
    || ntm_die "the new bundle does not verify"

mv "$bundle" "${BINARY}.sig"
trap - EXIT
rm -f "$tmpsig"
echo "[sign-artifact] $(basename "$BINARY") ($(wc -c < "$BINARY" | tr -d ' ') bytes) -> $(basename "$BINARY").sig" \
     "(NTMSIG 2, $KEY_ID, delegation $(sed -n 2p "$NTM_DELEGATION"))"
