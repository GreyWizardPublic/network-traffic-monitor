#!/usr/bin/env bash
# verify-install.sh — consumer-side gate: can a CLEAN Fedora install the NTM
# packages from a signed dnf repo, and do the installed binaries run?
#
#   packaging/rpm/verify-install.sh --local  [--release 44]   # rehearsal (default)
#   packaging/rpm/verify-install.sh --public [--release 44]   # gate the live repo
#
# --local  builds a scratch repo from build-rpm/*.rpm, signed with a THROWAWAY
#          GPG key in a scratch GNUPGHOME (the real signing key is never used),
#          and bind-mounts it into a bare fedora container.
# --public installs from https://dl.code1one.com/ntm.repo with the real key.
#
# Both run the SAME assertions inside the container (gpgcheck=1 and
# repo_gpgcheck=1 enforced): packages install, users exist, files are in place,
# `rpm -V` is clean, each binary self-verifies its NTMSIG 2 signature at
# startup, and both packages remove cleanly. Modeled on Secure Vault's
# verify-repo-install.sh: a producer-side check cannot see a consumer-only bug.

set -euo pipefail

MODE=local; REL=44
while [[ $# -gt 0 ]]; do
    case "$1" in
        --local) MODE=local ;; --public) MODE=public ;;
        --release) REL="$2"; shift ;;
        *) echo "usage: $0 [--local|--public] [--release N]" >&2; exit 2 ;;
    esac; shift
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="registry.fedoraproject.org/fedora:$REL"
die() { echo "ERROR [verify-install]: $*" >&2; exit 1; }

# The assertion body — identical for both modes.
read -r -d '' CONSUMER <<'EOS' || true
set -euo pipefail
ok() { echo "  PASS  $*"; }
dnf -y -q install ntm-server ntm-client
ok "dnf install (gpgcheck=1, repo_gpgcheck=1)"
rpm -q ntm-server ntm-client
getent passwd ntm-server >/dev/null && getent passwd ntmclient >/dev/null && ok "system users created"
for k in server client; do
    test -x /usr/bin/ntm-$k && test -f /usr/bin/ntm-$k.sig
    test -f /usr/lib/systemd/system/ntm-$k.service
done
ok "binaries, .sig files and units in place"
stat -c '%U:%G %a %n' /etc/ntm-server /var/lib/ntm-server /etc/ntmclient
out=$(rpm -V ntm-server ntm-client || true); [ -z "$out" ] || { echo "$out"; exit 1; }
ok "rpm -V clean (nothing modified since install)"
for k in server client; do
    line=$(/usr/bin/ntm-$k --help 2>&1 | head -1)
    echo "        $line"
    case "$line" in *"signature verified OK"*"delegation v1"*) ;; *) echo "self-check failed for ntm-$k"; exit 1 ;; esac
done
ok "both binaries self-verify their NTMSIG 2 signature"
cp /usr/bin/ntm-client /tmp/t && cp /usr/bin/ntm-client.sig /tmp/t.sig
printf 'X' | dd of=/tmp/t bs=1 seek=4096 conv=notrunc 2>/dev/null
if /tmp/t --help >/dev/null 2>&1; then echo "tampered copy STARTED"; exit 1; fi
ok "a tampered copy refuses to start"
dnf -y -q remove ntm-server ntm-client
! rpm -q ntm-server ntm-client >/dev/null 2>&1 && ok "clean removal"
echo "ALL CONSUMER CHECKS PASSED"
EOS

if [[ $MODE == local ]]; then
    ls "$REPO"/build-rpm/ntm-*.rpm >/dev/null 2>&1 || die "no build-rpm/*.rpm — run packaging/rpm/build-rpms.sh"
    S=$(mktemp -d); trap 'rm -rf "$S"' EXIT
    export GNUPGHOME="$S/gnupg"; mkdir -m700 "$GNUPGHOME"
    gpg --batch --quiet --passphrase '' --quick-gen-key "NTM throwaway test key <test@invalid>" rsa3072 sign 1d
    KID=$(gpg --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
    gpg --armor --export "$KID" > "$S/KEY"
    mkdir -p "$S/repo"; cp "$REPO"/build-rpm/ntm-*.rpm "$S/repo/"
    rpmsign --quiet --define "_openpgp_sign_id $KID" --define "_gpg_name $KID" --addsign "$S"/repo/*.rpm
    createrepo_c --quiet "$S/repo"
    gpg --batch --yes --detach-sign --armor -o "$S/repo/repodata/repomd.xml.asc" "$S/repo/repodata/repomd.xml"
    cat > "$S/ntm.repo" <<EOF
[ntm]
name=NTM local rehearsal
baseurl=file:///repo
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///KEY
EOF
    echo "[verify-install] local rehearsal in $IMAGE (throwaway key $KID)"
    podman run --rm -v "$S/repo:/repo:ro,Z" -v "$S/KEY:/KEY:ro,Z" -v "$S/ntm.repo:/etc/yum.repos.d/ntm.repo:ro,Z" \
        "$IMAGE" bash -c "$CONSUMER"
else
    echo "[verify-install] PUBLIC gate in $IMAGE against https://dl.code1one.com/ntm.repo"
    podman run --rm "$IMAGE" bash -c \
        "curl -fsSL -o /etc/yum.repos.d/ntm.repo https://dl.code1one.com/ntm.repo && $CONSUMER"
fi
