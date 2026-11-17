#!/usr/bin/env bash
# Builds the static Rust library of the React Native module for Android:
#   prebuilt/android/<abi>/libkryptokrona_crypto_mobile.a
# Needs: Android NDK (ANDROID_NDK_HOME), cargo-ndk, the rustup targets
#   aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android
# env: ABIS (default: all four the app builds), ANDROID_API (default 24),
#      JOBS (cargo -j; default: cargo's own)
set -euo pipefail
cd "$(dirname "$0")/.."

ABIS=${ABIS:-"arm64-v8a armeabi-v7a x86_64 x86"}
API=${ANDROID_API:-24}

triple() {
    case $1 in
        arm64-v8a) echo aarch64-linux-android ;;
        armeabi-v7a) echo armv7-linux-androideabi ;;
        x86_64) echo x86_64-linux-android ;;
        x86) echo i686-linux-android ;;
        *) echo "unknown ABI $1" >&2; exit 2 ;;
    esac
}

targets=()
for abi in $ABIS; do
    targets+=(-t "$abi")
done

(
    cd rust
    # shellcheck disable=SC2086 # JOBS is optional
    cargo ndk "${targets[@]}" --platform "$API" build --release -p kryptokrona-crypto-mobile ${JOBS:+-j "$JOBS"}
)

for abi in $ABIS; do
    mkdir -p "prebuilt/android/$abi"
    cp "rust/target/$(triple "$abi")/release/libkryptokrona_crypto_mobile.a" "prebuilt/android/$abi/"
    echo "prebuilt/android/$abi/libkryptokrona_crypto_mobile.a"
done
