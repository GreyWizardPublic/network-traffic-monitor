#!/usr/bin/env bash
# build-rpms.sh — build the ntm-server and ntm-client RPMs from build-linux/.
#
# Usage (repo root):  packaging/rpm/build-rpms.sh [--out DIR]
#
# Inputs: the signed release binaries CMake already produced in build-linux/
# (ntm-<kind>-linux-amd64-<version> + .sig), at the versions in
# src/server_version.hpp and src/client_version.hpp.
#
# Gates (any failure stops the build):
#   1. each input pair passes scripts/trust/verify-bundle.sh
#   2. rpmbuild succeeds
#   3. the payload binary + .sig, re-extracted from the finished .rpm, are
#      byte-identical to the inputs AND still pass verify-bundle.sh — the check
#      that nothing (strip, debuginfo, build-id) touched the signed bytes.
#
# Output RPMs are UNSIGNED; packaging/rpm/publish.sh GPG-signs them.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="$REPO/build-rpm"
[[ "${1:-}" == "--out" && -n "${2:-}" ]] && OUT="$2"

die()  { echo "ERROR [build-rpms]: $*" >&2; exit 1; }
step() { echo "[build-rpms] $*"; }

ver() { sed -nE "s/.*$1\[\] = \"([0-9.]+)\".*/\1/p" "$REPO/src/$2"; }
declare -A VERSION=(
    [server]="$(ver kServerVersion server_version.hpp)"
    [client]="$(ver kClientVersion client_version.hpp)"
)

TOP="$OUT/rpmbuild"
rm -rf "$TOP"
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,RPMS,SRPMS} "$OUT"

for kind in server client; do
    v="${VERSION[$kind]}"
    [[ -n "$v" ]] || die "could not read the $kind version"
    bin="$REPO/build-linux/ntm-$kind-linux-amd64-$v"
    [[ -f "$bin" && -f "$bin.sig" ]] \
        || die "missing $bin(.sig) — build it first: cmake --build build-linux"

    step "ntm-$kind $v: verifying signed input"
    "$REPO/scripts/trust/verify-bundle.sh" "$bin" "$bin.sig" linux-amd64 | tail -1

    cp -p "$bin" "$bin.sig" "$TOP/SOURCES/"
    cp -p "$REPO/packaging/rpm/ntm-$kind.service" "$REPO/packaging/rpm/ntm-$kind.sysusers" \
          "$REPO/ntm-$kind.conf.example" "$REPO/LICENSE" "$REPO/LICENSES.md" "$TOP/SOURCES/"
    doc=SERVER_DEPLOYMENT.md; [[ $kind == client ]] && doc=CLIENT_DEPLOYMENT.md
    cp -p "$REPO/$doc" "$TOP/SOURCES/"
    cp -p "$REPO/packaging/rpm/ntm-$kind.spec" "$TOP/SPECS/"

    step "ntm-$kind $v: rpmbuild"
    rpmbuild --quiet -bb \
        --define "_topdir $TOP" \
        --define "ntm_version $v" \
        "$TOP/SPECS/ntm-$kind.spec"

    rpm_file=$(find "$TOP/RPMS" -name "ntm-$kind-$v-*.rpm" | head -1)
    [[ -n "$rpm_file" ]] || die "rpmbuild produced no ntm-$kind rpm"

    step "ntm-$kind $v: payload must be byte-identical to the signed input"
    x=$(mktemp -d)
    (cd "$x" && rpm2cpio "$rpm_file" | cpio -idm --quiet)
    cmp "$bin"     "$x/usr/bin/ntm-$kind"     || die "packaged ntm-$kind differs from the signed binary"
    cmp "$bin.sig" "$x/usr/bin/ntm-$kind.sig" || die "packaged .sig differs from the input"
    "$REPO/scripts/trust/verify-bundle.sh" "$x/usr/bin/ntm-$kind" "$x/usr/bin/ntm-$kind.sig" linux-amd64 \
        | tail -1
    rm -rf "$x"

    cp -p "$rpm_file" "$OUT/"
    step "ntm-$kind $v: OK -> $OUT/$(basename "$rpm_file")"
done
