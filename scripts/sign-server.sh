#!/usr/bin/env bash
# sign-server.sh — ML-DSA-65 binary signing for ntm-server.
#
# Usage:
#   ./scripts/sign-server.sh <path-to-server-binary>
#
# Output:
#   <binary-path>.sig  — written in the same directory as the binary
#
# Called automatically by CMake's POST_BUILD step for ntm-server.
# Requires the private key at ~/.ntm/privatebuildkey.secret.
# If the key is missing, the script exits with a clear error so the build fails.

set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 <path-to-server-binary>" >&2
    exit 1
fi

BINARY="$1"
PRIVATE_KEY_PATH="${HOME}/.ntm/privatebuildkey.secret"
SIG_FILE="${BINARY}.sig"

# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

if [[ ! -f "${BINARY}" ]]; then
    echo "ERROR [sign-server]: Binary not found: ${BINARY}" >&2
    exit 1
fi

if [[ ! -f "${PRIVATE_KEY_PATH}" ]]; then
    echo "" >&2
    echo "FATAL [sign-server]: Private signing key not found." >&2
    echo "  Expected: ${PRIVATE_KEY_PATH}" >&2
    echo "" >&2
    echo "  Run the following to generate a key pair:" >&2
    echo "    ./scripts/manage-build-keys.sh" >&2
    echo "" >&2
    echo "  Unsigned ntm-server builds are not allowed." >&2
    exit 1
fi

# Validate the key is ML-DSA-65
ALGO=$(openssl pkey -in "${PRIVATE_KEY_PATH}" -text -noout 2>/dev/null | grep -o 'ML-DSA-[0-9]*' | head -1 || true)
if [[ "${ALGO}" != "ML-DSA-65" ]]; then
    echo "ERROR [sign-server]: ${PRIVATE_KEY_PATH} is not an ML-DSA-65 private key (found: '${ALGO}')" >&2
    echo "  Delete the key and re-run ./scripts/manage-build-keys.sh" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Sign
# ---------------------------------------------------------------------------

openssl pkeyutl \
    -sign \
    -rawin \
    -inkey "${PRIVATE_KEY_PATH}" \
    -in    "${BINARY}" \
    -out   "${SIG_FILE}"

BINARY_SIZE=$(wc -c < "${BINARY}")
SIG_SIZE=$(wc -c < "${SIG_FILE}")
echo "[sign-server] Signed: $(basename "${BINARY}") (${BINARY_SIZE} bytes) → $(basename "${SIG_FILE}") (${SIG_SIZE} bytes)"
