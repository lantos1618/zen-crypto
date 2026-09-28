#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
compiler=${ZEN_COMPILER:-../zen-actor-runtime/zen}
export ZEN_STD=${ZEN_STD:-../zen-actor-runtime/src}
mkdir -p build/chacha-native-source
ln -sfn "$root/src/chacha20poly1305.zen" build/chacha-native-source/chacha20poly1305.zen
ln -sfn "$root/tests/chacha20poly1305_native.zen" build/chacha-native-source/main.zen
"$compiler" build build/chacha-native-source --emit-c -o build/chacha_native.c
${CC:-clang} -O3 -Wno-parentheses-equality build/chacha_native.c -o build/chacha-native
build/chacha-native
${CC:-clang} -O2 -Wno-parentheses-equality -fsanitize=undefined -fno-sanitize-recover=all build/chacha_native.c -o build/chacha-native-ubsan
build/chacha-native-ubsan

# Private arithmetic edge cases are compiled into a separate temporary module.
mkdir -p build/chacha-poly-source
cat src/chacha20poly1305.zen tests/chacha20poly1305_poly_edges.zen > build/chacha-poly-source/main.zen
"$compiler" build build/chacha-poly-source --emit-c -o build/chacha_poly.c
${CC:-clang} -O2 -Wno-parentheses-equality -fsanitize=undefined -fno-sanitize-recover=all build/chacha_poly.c -o build/chacha-poly-ubsan
build/chacha-poly-ubsan
