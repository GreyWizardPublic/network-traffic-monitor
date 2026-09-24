# lib.sh — shared helpers for trust-v2 signing (sourced, not executed).
#
# Build keys (docs/signing-trust-model.md §6):
#   linux-amd64   linux-build    seed in systemd-creds: ~/.config/ntm/linux-build.cred
#   windows-amd64 windows-build  seed DPAPI-held, released by windows-build-seed.ps1
#
# The seed only ever lives in a shell variable and in pipes. The private key
# is materialised by `openssl genpkey` into a pipe and read via /dev/stdin;
# it is never written to disk.

NTM_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
NTM_DELEGATION="${NTM_DELEGATION:-$NTM_REPO_ROOT/signing/delegation.txt}"

ntm_die() { echo "ERROR [${NTM_TOOL:-trust}]: $*" >&2; exit 1; }

# Platform of this host: linux-amd64 or windows-amd64 (MSYS2/MinGW bash).
ntm_host_platform() {
    case "$(uname -s)" in
        Linux)                echo linux-amd64 ;;
        MINGW*|MSYS*|CYGWIN*) echo windows-amd64 ;;
        *) ntm_die "unsupported host $(uname -s)" ;;
    esac
}

# Build-key id for a platform (override with NTM_BUILD_KEY_ID).
ntm_key_id() {
    if [[ -n "${NTM_BUILD_KEY_ID:-}" ]]; then echo "$NTM_BUILD_KEY_ID"; return; fi
    case "$1" in
        linux-amd64)   echo linux-build ;;
        windows-amd64) echo windows-build ;;
        *) ntm_die "no build key for platform '$1'" ;;
    esac
}

# Print the build-key seed (64 hex, no newline). Use only inside $(...).
ntm_build_seed() {
    local seed
    case "$(ntm_host_platform)" in
        linux-amd64)
            local cred="${NTM_BUILD_CRED:-$HOME/.config/ntm/linux-build.cred}"
            [[ -f "$cred" ]] || ntm_die "linux-build key not found at $cred (docs/signing-trust-model.md §6)"
            seed=$(systemd-creds decrypt --user --name=ntm-linux-build "$cred" -) \
                || ntm_die "systemd-creds could not decrypt $cred"
            ;;
        windows-amd64)
            local ps ps1
            ps="$(cygpath -u "${SYSTEMROOT:-C:\\Windows}")/System32/WindowsPowerShell/v1.0/powershell.exe"
            ps1="$(cygpath -w "$NTM_REPO_ROOT/scripts/trust/windows-build-seed.ps1")"
            seed=$("$ps" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$ps1") \
                || ntm_die "windows-build-seed.ps1 failed (see its message above)"
            ;;
    esac
    seed="${seed//$'\r'/}"
    seed="${seed//$'\n'/}"
    [[ "$seed" =~ ^[0-9a-fA-F]{64}$ ]] || ntm_die "build-key seed has the wrong shape"
    printf '%s' "$seed"
}

# Require a root-signed delegation (>= 2 valid root signatures).
ntm_require_delegation() {
    [[ -f "$NTM_DELEGATION" ]] || ntm_die "delegation not found: $NTM_DELEGATION"
    if grep -q $'\r' "$NTM_DELEGATION"; then
        ntm_die "$NTM_DELEGATION has CRLF line endings (EOL-converted checkout); root signatures cover the LF bytes. Re-checkout: git rm -rq --cached signing && git checkout -- signing  (see .gitattributes)"
    fi
    local valid=0 n
    for n in 1 2 3; do
        [[ -f "$NTM_DELEGATION.r$n.sig" ]] || continue
        openssl pkeyutl -verify -rawin -pubin -keyform DER \
            -inkey "$NTM_REPO_ROOT/signing/roots/r$n.pub.der" \
            -in "$NTM_DELEGATION" -sigfile "$NTM_DELEGATION.r$n.sig" >/dev/null 2>&1 \
            && valid=$((valid + 1))
    done
    (( valid >= 2 )) || ntm_die "delegation has $valid valid root signature(s); 2 required (not root-signed yet? #133 phase 4)"
}

# Write the DER SPKI the delegation names for <key-id>/<platform> to <out>.
ntm_delegated_spki() {
    local id="$1" platform="$2" out="$3" line
    line=$(grep -E "^key: $id $platform ML-DSA-65 [A-Za-z0-9+/=]+\$" "$NTM_DELEGATION" || true)
    [[ -n "$line" ]] || ntm_die "delegation has no key '$id' for $platform"
    printf '%s' "${line##* }" | openssl base64 -d -A > "$out"
}

# Sign <in> with this host's build key for <platform>, writing a raw ML-DSA-65
# signature to <out>. Refuses if the key does not match the delegation.
ntm_build_sign() {
    local platform="$1" in="$2" out="$3" id seed want have
    id=$(ntm_key_id "$platform")
    want=$(mktemp); have=$(mktemp)
    ntm_delegated_spki "$id" "$platform" "$want"
    seed=$(ntm_build_seed) || exit 1
    openssl genpkey -algorithm ML-DSA-65 -pkeyopt "hexseed:$seed" \
        | openssl pkey -pubout -outform DER > "$have"
    if ! cmp -s "$want" "$have"; then
        seed=""; rm -f "$want" "$have"
        ntm_die "this host's build key does not match '$id' in the delegation"
    fi
    openssl genpkey -algorithm ML-DSA-65 -pkeyopt "hexseed:$seed" \
        | openssl pkeyutl -sign -rawin -inkey /dev/stdin -in "$in" -out "$out"
    seed=""
    openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "$want" -in "$in" -sigfile "$out" \
        >/dev/null 2>&1 || { rm -f "$want" "$have" "$out"; ntm_die "self-check of the new signature failed"; }
    rm -f "$want" "$have"
}
