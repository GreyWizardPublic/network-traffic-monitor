#!/usr/bin/env bash
# store-asc-key.sh — store an App Store Connect API .p8 in macOS Keychain.
#
# The .p8 private key is stored hex-encoded under
#   service = "appstoreconnect-api-key"
#   account = "<KEY_ID>"
# so it lives only in the keychain. Scripts that need the key materialise
# it to disk briefly, then wipe automatically via trap.
#
# Usage:
#   ./ios/scripts/store-asc-key.sh <KEY_ID> /path/to/AuthKey_<KEY_ID>.p8
#
# After running this you SHOULD wipe the original .p8 from disk — the
# script prints the exact commands.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <KEY_ID> <path-to-AuthKey_KEY_ID.p8>" >&2
    exit 1
fi

KEY_ID="$1"
P8_PATH="$2"

[[ -f "${P8_PATH}" ]] || { echo "ERROR: file not found: ${P8_PATH}" >&2; exit 1; }

if ! head -1 "${P8_PATH}" | grep -q "BEGIN PRIVATE KEY"; then
    echo "ERROR: ${P8_PATH} does not look like a PEM private key" >&2
    exit 1
fi

hex_content=$(xxd -p -c 0 "${P8_PATH}" | tr -d '\n')

security add-generic-password \
    -U \
    -s "appstoreconnect-api-key" \
    -a "${KEY_ID}" \
    -w "${hex_content}"

cat <<EOF
[store-asc-key] Stored App Store Connect key ${KEY_ID} in keychain
                (service=appstoreconnect-api-key, account=${KEY_ID}).

Now wipe the original .p8 from disk so the durable copy lives only in
the keychain:

  dd if=/dev/urandom of="${P8_PATH}" bs=\$(stat -f%z "${P8_PATH}") count=1 conv=notrunc
  rm -P "${P8_PATH}"

(If the .p8 was in ~/Downloads or similar, also empty the Trash.)
EOF
