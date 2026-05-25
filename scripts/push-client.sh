#!/usr/bin/env bash
# push-client.sh — push a signed ntm-client binary to the live server's update_dir.
#
# SAFETY POLICY (enforced by this script — do NOT bypass):
#   • Only binaries built from the main branch may be pushed.
#   • The local branch must be 'main', must be clean, and must match origin/main.
#   • A dry-run is performed by default; --confirm is REQUIRED to push.
#   • A human must explicitly invoke this script with --confirm; agents MUST NOT
#     pass --confirm autonomously.
#
# Prerequisites:
#   ~/.ntm/ntmserver.info   — server=<host>  port=<port>  (one key per line)
#   ~/.ntm/privatebuildkey.secret — ML-DSA-65 private key (PEM, mode 600)
#
# Usage:
#   ./scripts/push-client.sh <binary>            # dry-run (validates, no push)
#   ./scripts/push-client.sh <binary> --confirm  # actually push
#
# <binary> must be a signed ntm-client binary produced by 'cmake --build'.
# Its companion .sig file must be in the same directory as the binary.
# The filename must match: ntm-client-<platform>-<version>[.exe]
#
# The server-side endpoint verifies:
#   1. ML-DSA-65 auth proof (RAND nonce + SHA3-256(binary), signed with build key)
#   2. ML-DSA-65 binary signature (same key)
#   3. Version is strictly newer than the current version in update_dir for this platform
# If any check fails the server rejects the push; no file is written.

set -euo pipefail

die()  { echo "push-client: ERROR: $*" >&2; exit 1; }
warn() { echo "push-client: WARNING: $*" >&2; }
info() { echo "push-client: $*"; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

BINARY=""
CONFIRM=0

for arg in "$@"; do
    case "$arg" in
        --confirm) CONFIRM=1 ;;
        --help|-h)
            echo "Usage: $0 <binary> [--confirm]"
            echo "  <binary>    signed ntm-client binary (companion .sig must exist)"
            echo "  --confirm   actually push (omit for dry-run)"
            exit 0
            ;;
        -*)
            die "unknown flag: $arg  (use --confirm or --help)"
            ;;
        *)
            [ -z "$BINARY" ] || die "too many positional arguments"
            BINARY="$arg"
            ;;
    esac
done

[ -n "$BINARY" ] || die "missing required argument: <binary>  (see --help)"

require_cmd git
require_cmd curl
require_cmd openssl
require_cmd stat

# ---------------------------------------------------------------------------
# Branch safety checks
# ---------------------------------------------------------------------------
info "Checking git branch safety..."

GIT_BRANCH=$(git rev-parse --abbrev-ref HEAD 2>/dev/null) \
    || die "not inside a git repository"
[ "$GIT_BRANCH" = "main" ] \
    || die "current branch is '$GIT_BRANCH'; only 'main' may be pushed. Refusing."

if ! git diff --quiet || ! git diff --cached --quiet; then
    die "working tree is dirty — commit or stash changes before pushing"
fi

git fetch origin main --quiet 2>/dev/null || warn "could not fetch origin/main; skipping remote check"
LOCAL_SHA=$(git rev-parse HEAD)
REMOTE_SHA=$(git rev-parse origin/main 2>/dev/null || echo "")
if [ -n "$REMOTE_SHA" ] && [ "$LOCAL_SHA" != "$REMOTE_SHA" ]; then
    die "local main ($LOCAL_SHA) does not match origin/main ($REMOTE_SHA). Pull or push first."
fi
info "Branch check passed: main, clean, matches origin/main"

# ---------------------------------------------------------------------------
# Validate binary and signature
# ---------------------------------------------------------------------------
BINARY=$(realpath "$BINARY")
[ -f "$BINARY" ] || die "binary not found: $BINARY"

SIG_FILE="${BINARY}.sig"
[ -f "$SIG_FILE" ] || die "signature file not found: $SIG_FILE"

# Extract platform and version from filename (ntm-client-<platform>-<version>[.exe])
BASENAME=$(basename "$BINARY")
# Strip .exe if present
NAMEBASE="${BASENAME%.exe}"
# Remove prefix
REST="${NAMEBASE#ntm-client-}"
[ "$REST" != "$NAMEBASE" ] || die "filename does not start with 'ntm-client-': $BASENAME"
# Version is the part after the last '-'
VERSION=$(echo "$REST" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$') \
    || die "cannot extract version from binary filename: $BASENAME"
# Platform is everything before the version (strip trailing -)
PLATFORM="${REST%-${VERSION}}"
[ -n "$PLATFORM" ] || die "cannot extract platform from binary filename: $BASENAME"

info "Binary:   $BINARY"
info "Sig:      $SIG_FILE"
info "Platform: $PLATFORM"
info "Version:  $VERSION"

[ -x "$BINARY" ] || die "binary is not executable: $BINARY"

PRIV_KEY="$HOME/.ntm/privatebuildkey.secret"
[ -f "$PRIV_KEY" ] || die "private key not found: $PRIV_KEY"
[ "$(stat -c '%a' "$PRIV_KEY")" = "600" ] \
    || warn "private key permissions are not 600 — tighten with: chmod 600 $PRIV_KEY"

info "Verifying binary signature locally..."
openssl pkeyutl -verify \
    -inkey "$PRIV_KEY" \
    -in "$BINARY" \
    -sigfile "$SIG_FILE" \
    -rawin >/dev/null 2>&1 \
    || die "local signature verification FAILED — binary or .sig file is corrupted"
info "Local signature verification: OK"

# ---------------------------------------------------------------------------
# Load server connection info
# ---------------------------------------------------------------------------
SERVER_INFO="$HOME/.ntm/ntmserver.info"
[ -f "$SERVER_INFO" ] || die "server info file not found: $SERVER_INFO"

SERVER_HOST=""
SERVER_PORT=""
while IFS='=' read -r k v; do
    k="${k// /}"; v="${v// /}"
    case "$k" in
        server) SERVER_HOST="$v" ;;
        port)   SERVER_PORT="$v" ;;
        \#*|"") ;;
    esac
done < "$SERVER_INFO"

[ -n "$SERVER_HOST" ] || die "$SERVER_INFO: missing 'server' field"
[ -n "$SERVER_PORT" ] || die "$SERVER_INFO: missing 'port' field"
info "Server: $SERVER_HOST:$SERVER_PORT"

BASE_URL="https://$SERVER_HOST:$SERVER_PORT"

# ---------------------------------------------------------------------------
# Dry-run exit point
# ---------------------------------------------------------------------------
if [ "$CONFIRM" -eq 0 ]; then
    echo ""
    echo "push-client: DRY-RUN complete — all pre-flight checks passed."
    echo "push-client: To push, re-run with --confirm:"
    echo "  $0 $BINARY --confirm"
    echo ""
    echo "  Server:   $BASE_URL"
    echo "  Binary:   $BINARY"
    echo "  Platform: $PLATFORM"
    echo "  Version:  $VERSION"
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 1: Request a nonce from the server
# ---------------------------------------------------------------------------
info "Requesting nonce from $BASE_URL/admin/client/nonce ..."
NONCE_RESP=$(curl --silent --show-error --fail \
    --insecure \
    "$BASE_URL/admin/client/nonce") \
    || die "failed to contact server at $BASE_URL/admin/client/nonce"

NONCE=$(echo "$NONCE_RESP" | grep -oE '"nonce"\s*:\s*"[0-9a-f]+"' | grep -oE '[0-9a-f]{64}') \
    || die "could not parse nonce from server response: $NONCE_RESP"
info "Server nonce: $NONCE"

# ---------------------------------------------------------------------------
# Step 2: Build auth proof
# ---------------------------------------------------------------------------
info "Computing binary SHA3-256 ..."
BINARY_HASH=$(openssl dgst -sha3-256 -binary "$BINARY" | xxd -p -c 256 | tr -d '\n')
info "Binary SHA3-256: $BINARY_HASH"

AUTH_MSG_FILE=$(mktemp /tmp/ntm_client_push_authmsg.XXXXXX)
AUTH_PROOF_FILE=$(mktemp /tmp/ntm_client_push_authproof.XXXXXX)
trap 'rm -f "$AUTH_MSG_FILE" "$AUTH_PROOF_FILE"' EXIT

echo -n "$NONCE" | xxd -r -p > "$AUTH_MSG_FILE"
echo -n "$BINARY_HASH" | xxd -r -p >> "$AUTH_MSG_FILE"

info "Signing auth message with ML-DSA-65 ..."
openssl pkeyutl -sign \
    -inkey "$PRIV_KEY" \
    -in "$AUTH_MSG_FILE" \
    -out "$AUTH_PROOF_FILE" \
    -rawin \
    || die "failed to sign auth message"

AUTH_PROOF_B64=$(openssl base64 -in "$AUTH_PROOF_FILE" | tr -d '\n')
info "Auth proof ready (${#AUTH_PROOF_B64} b64 chars)"

# ---------------------------------------------------------------------------
# Step 3: Push binary + signature + auth proof to server
# ---------------------------------------------------------------------------
# On Windows/MSYS2, MinGW curl misparses POSIX paths (/c/Users/...) when a
# ;type= suffix is appended to -F @file fields (curl error 26). Converting to
# Windows mixed paths (C:/Users/...) via cygpath -m avoids the issue.
# On Linux, cygpath is absent and BINARY_FOR_CURL == BINARY.
if command -v cygpath >/dev/null 2>&1; then
    BINARY_FOR_CURL=$(cygpath -m "$BINARY")
    SIG_FOR_CURL=$(cygpath -m "$SIG_FILE")
else
    BINARY_FOR_CURL="$BINARY"
    SIG_FOR_CURL="$SIG_FILE"
fi

info "Uploading binary and signature to $BASE_URL/admin/client/push ..."
PUSH_RESP=$(curl --silent --show-error --fail \
    --insecure \
    -F "platform=$PLATFORM" \
    -F "version=$VERSION" \
    -F "nonce=$NONCE" \
    -F "auth_proof=$AUTH_PROOF_B64" \
    -F "binary=@$BINARY_FOR_CURL;type=application/octet-stream" \
    -F "signature=@$SIG_FOR_CURL;type=application/octet-stream" \
    "$BASE_URL/admin/client/push") \
    || die "server rejected the push (see server logs for details)"

echo ""
echo "push-client: SUCCESS"
echo "push-client: Server response: $PUSH_RESP"
echo "push-client: Binary placed in update_dir; clients will receive it on next update check."
