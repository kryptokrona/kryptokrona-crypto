#!/bin/bash

# Set up emscripten

echo "Installing emscripten..."
echo ""
cd emsdk
./emsdk install latest && ./emsdk activate latest
source ./emsdk_env.sh
cd ..

# This applies a patch to fastcomp to make sure that the
# environment is set correctly for react environments
patch -N --verbose emsdk/fastcomp/emscripten/src/shell.js scripts/emscripten.patch

mkdir -p jsbuild && cd jsbuild && rm -rf *
emcmake cmake .. -DNO_AES=1 -DARCH=default -DBUILD_WASM=1 -DBUILD_JS=0
make && cp turtlecoin-crypto-wasm.js ../dist
emcmake cmake .. -DNO_AES=1 -DARCH=default -DBUILD_WASM=0 -DBUILD_JS=1
make && cp turtlecoin-crypto.js ../dist
