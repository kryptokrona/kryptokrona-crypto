#!/usr/bin/env bash
# Switches the three xkr-* dependencies of rust/Cargo.toml between
#   git    the pinned revision of [workspace.metadata.xkr] (the committed form), and
#   local  path dependencies on a checkout of the node repository (development, and builds
#          while the repository is not reachable; Cargo needs network access for a git
#          source even when a [patch] replaces it).
# usage: scripts/xkr-source.sh git
#        scripts/xkr-source.sh local [xkr checkout, relative to rust/ or absolute; default ../../xkr]
set -euo pipefail
cd "$(dirname "$0")/../rust"

meta() {
    sed -n "/^\[workspace.metadata.xkr\]/,/^\[/{s/^$1 *= *\"\([^\"]*\)\".*/\1/p}" Cargo.toml
}

case ${1:-} in
    git)
        url=$(meta repository)
        rev=$(meta rev)
        [[ -n $url && -n $rev ]] || { echo "no [workspace.metadata.xkr] repository/rev" >&2; exit 2; }
        source_of() { echo "{ git = \"$url\", rev = \"$rev\" }"; }
        ;;
    local)
        dir=${2:-../../xkr}
        [[ -f $dir/crates/xkr-crypto-ffi/Cargo.toml ]] || { echo "no xkr checkout at $dir" >&2; exit 2; }
        source_of() { echo "{ path = \"$dir/crates/$1\" }"; }
        ;;
    *)
        echo "usage: $0 git | local [xkr checkout]" >&2
        exit 2
        ;;
esac

for name in xkr-crypto-ffi xkr-crypto xkr-types; do
    line=$(printf '%-14s = %s' "$name" "$(source_of "$name")")
    # "xkr-crypto *=" does not match "xkr-crypto-ffi =" (a '-' follows, not a space or '=')
    sed -i.bak -E "s|^$name *=.*|$line|" Cargo.toml
done
rm -f Cargo.toml.bak
grep -E '^xkr-(crypto-ffi|crypto|types) *=' Cargo.toml
