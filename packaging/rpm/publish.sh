#!/usr/bin/env bash
# publish.sh — GPG-sign build-rpm/*.rpm and publish them to the public NTM repo.
#
# RUN BY THE MAINTAINER in their own terminal: rpmsign/gpg prompt for the
# Code1One Package Signing key's passphrase (the key lives in ~/.gnupg).
#
#   packaging/rpm/publish.sh            # interactive (asks before publishing)
#   packaging/rpm/publish.sh --dry-run  # show what would happen
#
# Layout (separate from Secure Vault's tree; same host, same GPG key):
#   /var/www/dl.code1one.com/ntm.repo
#   /var/www/dl.code1one.com/rpm/ntm/fedora/{44,45}/x86_64/
#
# ORDER IS LOAD-BEARING (same as Secure Vault's release.sh):
#   1. sign the .rpm   2. createrepo_c   3. detach-sign repomd.xml
# Reversed, dnf reports a checksum or signature error that reads like
# corruption. Afterwards run: packaging/rpm/verify-install.sh --public

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WEB=/var/www/dl.code1one.com
RELEASES=(44 45)
ARCH=x86_64
DRY=0; [[ "${1:-}" == "--dry-run" ]] && DRY=1

die()  { echo "ERROR [publish]: $*" >&2; exit 1; }
step() { echo "[publish] $*"; }

mapfile -t RPMS < <(ls "$REPO"/build-rpm/ntm-*.rpm 2>/dev/null)
[[ ${#RPMS[@]} -gt 0 ]] || die "no build-rpm/ntm-*.rpm — run packaging/rpm/build-rpms.sh"
SIGN_ID="$(rpm --eval '%{?_openpgp_sign_id}')"
[[ -n "$SIGN_ID" ]] || die "no %_openpgp_sign_id in ~/.rpmmacros"
gpg --list-secret-keys "$SIGN_ID" >/dev/null 2>&1 || die "signing key $SIGN_ID not in this keyring"
[[ -w "$WEB" ]] || die "$WEB not writable by $(id -un) (needs group webdeploy)"

step "packages: $(printf '%s ' "${RPMS[@]##*/}")"
step "signing key: $SIGN_ID"
step "targets: ${RELEASES[*]/#/fedora/} under $WEB/rpm/ntm/"
if [[ $DRY -eq 1 ]]; then step "DRY RUN — nothing signed or published"; exit 0; fi

signed() {
    local t v
    for t in RSAHEADER OPENPGP DSAHEADER; do
        v="$(rpm -qp --qf "%{${t}:pgpsig}" "$1" 2>/dev/null)"
        [[ -n "$v" && "$v" != "(none)" ]] && return 0
    done
    return 1
}

step "1/3 signing packages (gpg will ask for the passphrase)"
for r in "${RPMS[@]}"; do
    signed "$r" || rpmsign --addsign "$r" || die "rpmsign failed for $r"
    signed "$r" || die "$r carries no signature after rpmsign"
done
step "packages signed"

printf '\n\033[1;33mPublish %s to the PUBLIC repo https://dl.code1one.com/rpm/ntm/ ?\033[0m [y/N] ' "${RPMS[*]##*/}"
read -r reply; [[ "$reply" =~ ^[Yy]$ ]] || die "aborted by operator"

for rel in "${RELEASES[@]}"; do
    dir="$WEB/rpm/ntm/fedora/$rel/$ARCH"
    mkdir -p "$dir"
    install -m0644 "${RPMS[@]}" "$dir/"
    step "2/3 fedora/$rel: createrepo_c"
    createrepo_c --quiet --update --retain-old-md=1 "$dir" || die "createrepo_c failed in $dir"
    step "3/3 fedora/$rel: detach-sign repomd.xml"
    rm -f "$dir/repodata/repomd.xml.asc"
    gpg --batch --yes --detach-sign --armor --local-user "$SIGN_ID" \
        -o "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml" \
        || die "failed to sign repomd.xml in $dir"
    gpg --verify "$dir/repodata/repomd.xml.asc" "$dir/repodata/repomd.xml" 2>/dev/null \
        || die "repomd.xml.asc does not verify in $dir"
    chmod -R a+rX "$WEB/rpm/ntm"
    step "fedora/$rel: $(ls "$dir"/*.rpm | wc -l) package(s) published"
done

install -m0644 "$REPO/packaging/rpm/ntm.repo" "$WEB/ntm.repo"
step "repo file: https://dl.code1one.com/ntm.repo"
step "next: packaging/rpm/verify-install.sh --public"
