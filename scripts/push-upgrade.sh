#!/usr/bin/env bash
# push-upgrade.sh — push a signed ntm-server binary to the live server.
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
#   ./scripts/push-upgrade.sh <binary>       # dry-run (validates, no push)
#   ./scripts/push-upgrade.sh <binary> --confirm   # actually push
#
# <binary> must be a signed ntm-server binary produced by 'cmake --build'.
# Its companion .sig file must be in the same directory as the binary.
#
# The server-side endpoint verifies:
#   1. ML-DSA-65 auth proof (RAND nonce + SHA3-256(binary), signed with build key)
#   2. ML-DSA-65 binary signature (same key)
#   3. Version is strictly newer than the running server version
# If any check fails the server rejects the push; no binary is written.

set -euo pipefail

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
die() { echo "push-upgrade: ERROR: $*" >&2; exit 1; }
warn() { echo "push-upgrade: WARNING: $*" >&2; }
info() { echo "push-upgrade: $*"; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"; }

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
BINARY=""
CONFIRM=0

for arg in "$@"; do
    case "$arg" in
        --confirm) CONFIRM=1 ;;
        --help|-h)
            echo "Usage: $0 <binary> [--confirm]"
            echo "  <binary>    signed ntm-server binary (companion .sig must exist)"
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

# ---------------------------------------------------------------------------
# Check required commands
# ---------------------------------------------------------------------------
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

# Ensure working tree is clean (no uncommitted changes)
if ! git diff --quiet || ! git diff --cached --quiet; then
    die "working tree is dirty — commit or stash changes before pushing"
fi

# Ensure local main matches origin/main
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

# Extract version from filename (ntm-server-linux-amd64-X.Y.Z)
BASENAME=$(basename "$BINARY")
VERSION=$(echo "$BASENAME" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+$') \
    || die "cannot extract version from binary filename: $BASENAME"
info "Binary: $BINARY"
info "Signature: $SIG_FILE"
info "Version: $VERSION"

# Quick sanity: binary must be executable
[ -x "$BINARY" ] || die "binary is not executable: $BINARY"

# Verify the binary signature locally before uploading
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
    k="${k// /}"
    v="${v// /}"
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
    echo "push-upgrade: DRY-RUN complete — all pre-flight checks passed."
    echo "push-upgrade: To push, re-run with --confirm:"
    echo "  $0 $BINARY --confirm"
    echo ""
    echo "  Server:  $BASE_URL"
    echo "  Binary:  $BINARY"
    echo "  Version: $VERSION"
    exit 0
fi

# ---------------------------------------------------------------------------
# Step 1: Request a nonce from the server
# ---------------------------------------------------------------------------
info "Requesting nonce from $BASE_URL/admin/upgrade/nonce ..."
NONCE_RESP=$(curl --silent --show-error --fail \
    --insecure \
    "$BASE_URL/admin/upgrade/nonce") \
    || die "failed to contact server at $BASE_URL/admin/upgrade/nonce"

# Extract nonce value from JSON: {"nonce":"...","server_version":"..."}
NONCE=$(echo "$NONCE_RESP" | grep -oE '"nonce"\s*:\s*"[0-9a-f]+"' | grep -oE '[0-9a-f]{64}') \
    || die "could not parse nonce from server response: $NONCE_RESP"
SERVER_VER=$(echo "$NONCE_RESP" | grep -oE '"server_version"\s*:\s*"[^"]+"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+') \
    || warn "could not parse server_version from response (version check skipped)"

info "Server nonce: $NONCE"
[ -n "$SERVER_VER" ] && info "Server version: $SERVER_VER"

# ---------------------------------------------------------------------------
# Step 2: Build auth proof
#   auth_message = hex_decode(nonce) || SHA3-256(binary_bytes)
#   auth_proof   = ML-DSA-65 signature over auth_message
# ---------------------------------------------------------------------------
info "Computing binary SHA3-256 ..."
BINARY_HASH=$(openssl dgst -sha3-256 -binary "$BINARY" | xxd -p -c 256 | tr -d '\n')
info "Binary SHA3-256: $BINARY_HASH"

# Concatenate nonce bytes (raw) with binary hash bytes (raw) into a temp file
# openssl pkeyutl -sign reads the message from stdin or -in; we write to a temp file.
AUTH_MSG_FILE=$(mktemp /tmp/ntm_upgrade_authmsg.XXXXXX)
trap 'rm -f "$AUTH_MSG_FILE" "$AUTH_PROOF_FILE"' EXIT

# Write nonce bytes (hex → binary)
echo -n "$NONCE" | xxd -r -p > "$AUTH_MSG_FILE"
# Append binary SHA3-256 bytes
echo -n "$BINARY_HASH" | xxd -r -p >> "$AUTH_MSG_FILE"

AUTH_PROOF_FILE=$(mktemp /tmp/ntm_upgrade_authproof.XXXXXX)

info "Signing auth message with ML-DSA-65 ..."
openssl pkeyutl -sign \
    -inkey "$PRIV_KEY" \
    -in "$AUTH_MSG_FILE" \
    -out "$AUTH_PROOF_FILE" \
    -rawin \
    || die "failed to sign auth message"

# Base64-encode the auth proof for multipart upload
AUTH_PROOF_B64=$(openssl base64 -in "$AUTH_PROOF_FILE" | tr -d '\n')
info "Auth proof ready (${#AUTH_PROOF_B64} b64 chars)"

# ---------------------------------------------------------------------------
# Step 3: Push binary + signature + auth proof to server
# ---------------------------------------------------------------------------
info "Uploading binary and signature to $BASE_URL/admin/upgrade/push ..."
PUSH_RESP=$(curl --silent --show-error --fail \
    --insecure \
    -F "version=$VERSION" \
    -F "nonce=$NONCE" \
    -F "auth_proof=$AUTH_PROOF_B64" \
    -F "binary=@$BINARY;type=application/octet-stream" \
    -F "signature=@$SIG_FILE;type=application/octet-stream" \
    "$BASE_URL/admin/upgrade/push") \
    || die "server rejected the push (see server logs for details)"

echo ""
echo "push-upgrade: SUCCESS"
echo "push-upgrade: Server response: $PUSH_RESP"
echo "push-upgrade: Server will apply the upgrade and restart within ~30 seconds."
