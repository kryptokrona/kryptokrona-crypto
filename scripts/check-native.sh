#!/usr/bin/env bash
# Consistency checks of the native parts (no build of their own):
#   manifest rust/Cargo.toml takes the xkr crates from the git release tag (not a local path)
#   header   cpp/xkr_crypto_ffi.h is the header of the pinned xkr-crypto-ffi release
#   symbols  a built static library exports every function the header declares
# usage: scripts/check-native.sh manifest
#        scripts/check-native.sh header
#        scripts/check-native.sh symbols <libkryptokrona_crypto_mobile.a>
# Needs cargo (header: reads `cargo metadata`), jq, nm.
set -euo pipefail
cd "$(dirname "$0")/.."

HEADER=cpp/xkr_crypto_ffi.h

case ${1:-} in
    manifest)
        lines=$(grep -E '^xkr-(crypto-ffi|crypto|types) *=' rust/Cargo.toml)
        if [[ $(grep -c 'git = ' <<< "$lines") == 3 ]]; then
            echo "manifest: xkr crates from the git release tag"
        else
            echo "manifest: rust/Cargo.toml uses local xkr paths; run scripts/xkr-source.sh git" >&2
            echo "$lines" >&2
            exit 1
        fi
        ;;
    header)
        manifest=$(cd rust && cargo metadata --format-version 1 \
            | jq -r '.packages[] | select(.name == "xkr-crypto-ffi") | .manifest_path')
        upstream="$(dirname "$manifest")/include/xkr_crypto_ffi.h"
        if cmp -s "$HEADER" "$upstream"; then
            echo "header: $HEADER = $upstream"
        else
            echo "header: $HEADER differs from $upstream (copy it after bumping the tag)" >&2
            diff "$HEADER" "$upstream" >&2 || true
            exit 1
        fi
        ;;
    symbols)
        lib=${2:?usage: check-native.sh symbols <lib.a>}
        want=$(grep -o 'xkr_crypto_[a-z0-9_]*(' "$HEADER" | tr -d '(' | sort -u)
        have=$(nm -g "$lib" 2>/dev/null | awk '$2 == "T" { print $3 }' | sed 's/^_//' \
            | grep '^xkr_crypto_' | sort -u)
        missing=$(comm -23 <(echo "$want") <(echo "$have"))
        if [[ -n $missing ]]; then
            echo "symbols: missing in $lib:" >&2
            echo "$missing" >&2
            exit 1
        fi
        echo "symbols: all $(echo "$want" | wc -l) functions of $HEADER in $lib"
        ;;
    *)
        echo "usage: $0 manifest | header | symbols <lib.a>" >&2
        exit 2
        ;;
esac
