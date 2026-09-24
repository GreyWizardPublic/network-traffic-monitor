#!/usr/bin/env bash
# sign-server.sh — sign an ntm-server binary (CMake POST_BUILD entry point).
#
# Usage: ./scripts/sign-server.sh <path-to-server-binary>
# Output: <binary>.sig — an NTMSIG 2 bundle (docs/signing-trust-model.md).
#
# Thin wrapper over scripts/trust/sign-artifact.sh. Fails — and so fails the
# build — if this host's build key or a root-signed delegation is missing.
# Unsigned ntm-server builds are never produced.

set -euo pipefail
[[ $# -eq 1 ]] || { echo "Usage: $0 <path-to-server-binary>" >&2; exit 1; }
exec "$(dirname "${BASH_SOURCE[0]}")/trust/sign-artifact.sh" "$1"
