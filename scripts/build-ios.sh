#!/usr/bin/env bash
# Builds the static Rust library of the React Native module for iOS (macOS with Xcode only):
#   prebuilt/ios/KryptokronaCryptoFFI.xcframework  (device arm64; simulator arm64 + x86_64)
# Needs the rustup targets aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios.
# env: JOBS (cargo -j; default: cargo's own)
set -euo pipefail
cd "$(dirname "$0")/.."

export IPHONEOS_DEPLOYMENT_TARGET=15.1
LIB=libkryptokrona_crypto_mobile.a
OUT=prebuilt/ios/KryptokronaCryptoFFI.xcframework

(
    cd rust
    for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
        # shellcheck disable=SC2086 # JOBS is optional
        cargo build --release --target "$target" -p kryptokrona-crypto-mobile ${JOBS:+-j "$JOBS"}
    done
)

mkdir -p build/ios-sim
lipo -create \
    "rust/target/aarch64-apple-ios-sim/release/$LIB" \
    "rust/target/x86_64-apple-ios/release/$LIB" \
    -output "build/ios-sim/$LIB"

# The header is not part of the framework: the pod compiles cpp/, which has xkr_crypto_ffi.h.
rm -rf "$OUT"
xcodebuild -create-xcframework \
    -library "rust/target/aarch64-apple-ios/release/$LIB" \
    -library "build/ios-sim/$LIB" \
    -output "$OUT"
echo "$OUT"
