#!/usr/bin/env bash
# archive-app.sh — archive NTMDashboard and export an App Store IPA.
#
# Output: ios/Build/Export/NTMDashboard.ipa  (and dSYMs alongside it)
#
# Must be run from the repo root, on the main branch with a clean working tree.
# After this succeeds, run ios/scripts/upload-testflight.sh to ship to TestFlight.
#
# Usage:
#   ./ios/scripts/archive-app.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IOS_DIR="${REPO_ROOT}/ios"
PROJECT="${IOS_DIR}/NTMDashboard.xcodeproj"
SCHEME="NTMDashboard"
ARCHIVE="${IOS_DIR}/Build/NTMDashboard.xcarchive"
EXPORT_DIR="${IOS_DIR}/Build/Export"
EXPORT_PLIST="${IOS_DIR}/scripts/ExportOptions.plist"

# ── pre-flight ──────────────────────────────────────────────────────────────

[[ "$(git -C "${REPO_ROOT}" branch --show-current)" == "main" ]] || {
    echo "ERROR: must be on main branch" >&2; exit 1
}
[[ -z "$(git -C "${REPO_ROOT}" status --porcelain)" ]] || {
    echo "ERROR: working tree is dirty" >&2; exit 1
}

# Verify the right Distribution cert is in keychain
if ! security find-identity -p codesigning -v 2>/dev/null | \
        grep -q "A40BD2CA12210ACDD8FE89E199F62E895F0B6914"; then
    echo "ERROR: Apple Distribution cert (SHA-1 A40BD2CA…) not found in keychain." >&2
    echo "       Import ios/certs/AppleDistribution-W65LG3MSG6.cer and its matching" >&2
    echo "       private key (.p12 export) from the original signing Mac." >&2
    exit 1
fi

# ── xcodegen ────────────────────────────────────────────────────────────────

echo "[archive] Running xcodegen generate..."
cd "${IOS_DIR}" && xcodegen generate
cd "${REPO_ROOT}"

# ── archive ─────────────────────────────────────────────────────────────────

rm -rf "${ARCHIVE}"
echo "[archive] Archiving ${SCHEME}..."
xcodebuild archive \
    -project "${PROJECT}" \
    -scheme "${SCHEME}" \
    -configuration Release \
    -destination "generic/platform=iOS" \
    -archivePath "${ARCHIVE}" \
    -allowProvisioningUpdates \
    CODE_SIGN_STYLE=Automatic \
    DEVELOPMENT_TEAM=W65LG3MSG6 \
    2>&1 | grep -E "ARCHIVE|error:|warning: (All|A launch)" || true

xcodebuild -list -project "${PROJECT}" > /dev/null  # sanity check project still valid

grep -q "ARCHIVE SUCCEEDED" <(xcodebuild archive \
    -project "${PROJECT}" \
    -scheme "${SCHEME}" \
    -configuration Release \
    -destination "generic/platform=iOS" \
    -archivePath "${ARCHIVE}" \
    -allowProvisioningUpdates \
    CODE_SIGN_STYLE=Automatic \
    DEVELOPMENT_TEAM=W65LG3MSG6 2>&1) || true

# Check archive actually exists
[[ -d "${ARCHIVE}" ]] || { echo "ERROR: archive not found at ${ARCHIVE}" >&2; exit 1; }

# Confirm signed with Distribution, not Development
SIGN_ID=$(codesign -dv "${ARCHIVE}/Products/Applications/NTMDashboard.app" 2>&1 | \
          grep "Authority=Apple Distribution" | head -1 || true)
if [[ -z "${SIGN_ID}" ]]; then
    echo "ERROR: archive is NOT signed with Apple Distribution cert." >&2
    echo "       Check that CODE_SIGN_IDENTITY is set in project.yml Release config." >&2
    exit 1
fi
echo "[archive] Confirmed: ${SIGN_ID}"

# ── export ───────────────────────────────────────────────────────────────────

rm -rf "${EXPORT_DIR}"
echo "[archive] Exporting IPA..."
xcodebuild -exportArchive \
    -archivePath "${ARCHIVE}" \
    -exportPath "${EXPORT_DIR}" \
    -exportOptionsPlist "${EXPORT_PLIST}" \
    -allowProvisioningUpdates \
    2>&1 | grep -E "EXPORT|error:|Uploading" || true

IPA="${EXPORT_DIR}/NTMDashboard.ipa"
[[ -f "${IPA}" ]] || { echo "ERROR: IPA not found at ${IPA}" >&2; exit 1; }

echo ""
echo "[archive] Done. IPA: ${IPA}"
echo "          Run ./ios/scripts/upload-testflight.sh to upload."
