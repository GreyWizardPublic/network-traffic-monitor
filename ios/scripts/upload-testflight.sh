#!/usr/bin/env bash
# upload-testflight.sh — upload ios/Build/Export/NTMDashboard.ipa to TestFlight.
#
# The App Store Connect API .p8 is materialised from the macOS Keychain,
# used for the altool upload, then wiped from disk via a trap that fires on
# every exit path. The keychain entry is the durable copy; nothing sensitive
# is left on disk after this script returns.
#
# Store the .p8 in keychain first (one-time setup):
#   ./ios/scripts/store-asc-key.sh <KEY_ID> /path/to/AuthKey_<KEY_ID>.p8
#
# Required env vars:
#   ASC_KEY_ID     — 10-char App Store Connect API key ID (e.g. REDACTED_KEY_ID)
#   ASC_ISSUER_ID  — Issuer UUID from appstoreconnect.apple.com
#                    Users and Access → Integrations → App Store Connect API
#
# Optional env vars:
#   IPA_PATH       — defaults to ios/Build/Export/NTMDashboard.ipa

set -euo pipefail

: "${ASC_KEY_ID:?ASC_KEY_ID must be set (10-char App Store Connect key ID)}"
: "${ASC_ISSUER_ID:?ASC_ISSUER_ID must be set (UUID issuer)}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IPA_PATH="${IPA_PATH:-${REPO_ROOT}/ios/Build/Export/NTMDashboard.ipa}"

[[ -f "${IPA_PATH}" ]] || {
    echo "ERROR: .ipa not found at ${IPA_PATH}" >&2
    echo "Run ./ios/scripts/archive-app.sh first." >&2
    exit 1
}

KEY_DIR="${HOME}/.appstoreconnect/private_keys"
KEY_FILE="${KEY_DIR}/AuthKey_${ASC_KEY_ID}.p8"
WROTE_KEY_FILE=0

cleanup() {
    if [[ "${WROTE_KEY_FILE}" -eq 1 && -f "${KEY_FILE}" ]]; then
        local size
        size=$(stat -f%z "${KEY_FILE}" 2>/dev/null || echo 0)
        if [[ "${size}" -gt 0 ]]; then
            dd if=/dev/urandom of="${KEY_FILE}" bs="${size}" count=1 conv=notrunc 2>/dev/null || true
        fi
        rm -fP "${KEY_FILE}" 2>/dev/null || rm -f "${KEY_FILE}"
        echo "[upload-testflight] Wiped temporary .p8 at ${KEY_FILE}" >&2
    fi
}
trap cleanup EXIT INT TERM HUP

if [[ -f "${KEY_FILE}" ]]; then
    echo "[upload-testflight] WARNING: stale .p8 already present at ${KEY_FILE}." >&2
    echo "                    Re-using it; will not wipe on exit (was not ours)." >&2
else
    echo "[upload-testflight] Reading .p8 from keychain (service=appstoreconnect-api-key, account=${ASC_KEY_ID})..."
    hex_pw=$(security find-generic-password \
                 -s appstoreconnect-api-key -a "${ASC_KEY_ID}" -w 2>/dev/null) || {
        echo "ERROR: no keychain entry for App Store Connect key ${ASC_KEY_ID}" >&2
        echo "Run: ./ios/scripts/store-asc-key.sh ${ASC_KEY_ID} /path/to/AuthKey_${ASC_KEY_ID}.p8" >&2
        exit 1
    }

    mkdir -p "${KEY_DIR}"
    chmod 700 "${KEY_DIR}"
    umask 077
    printf "%s" "${hex_pw}" | xxd -r -p > "${KEY_FILE}"
    chmod 600 "${KEY_FILE}"
    WROTE_KEY_FILE=1
fi

echo "[upload-testflight] Uploading ${IPA_PATH} to App Store Connect..."
xcrun altool --upload-app \
    -f "${IPA_PATH}" \
    -t ios \
    --apiKey "${ASC_KEY_ID}" \
    --apiIssuer "${ASC_ISSUER_ID}"

echo "[upload-testflight] Upload complete. TestFlight processing may take 5–15 minutes."
