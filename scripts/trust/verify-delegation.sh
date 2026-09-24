#!/usr/bin/env bash
# verify-delegation.sh — check a delegation's root signatures with the OpenSSL CLI.
#
# Usage: scripts/trust/verify-delegation.sh [signing/delegation.txt]
#
# Verifies every <doc>.rN.sig present against signing/roots/rN.pub.der and
# requires at least 2 distinct valid roots (the threshold compiled into
# src/trust_roots.hpp). Also prints version/expiry. Exit 0 = usable.
# An independent cross-check of what src/trust.hpp does at runtime.

set -euo pipefail

DOC="${1:-signing/delegation.txt}"
[[ -f "$DOC" ]] || { echo "ERROR: no such file: $DOC" >&2; exit 1; }

valid=0
for n in 1 2 3; do
    sig="${DOC}.r${n}.sig"
    [[ -f "$sig" ]] || continue
    if openssl pkeyutl -verify -rawin -pubin -keyform DER -inkey "signing/roots/r${n}.pub.der" \
           -in "$DOC" -sigfile "$sig" >/dev/null 2>&1; then
        echo "  r${n}: valid"; valid=$((valid + 1))
    else
        echo "  r${n}: INVALID"
    fi
done
sed -n '2,3p' "$DOC" | sed 's/^/  /'
echo "  keys: $(grep '^key: ' "$DOC" | cut -d' ' -f2-3 | tr '\n' ';')"
if (( valid >= 2 )); then echo "OK: $valid valid root signatures (threshold 2)"; exit 0; fi
echo "NOT USABLE: $valid valid root signatures (threshold 2)" >&2
exit 1
