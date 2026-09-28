#!/bin/sh
# Optional differential checks. src remains independent of this C oracle.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
compiler=${ZEN_COMPILER:-../zen-actor-runtime/zen}
export ZEN_STD=${ZEN_STD:-../zen-actor-runtime/src}
case "$(uname -s)" in Darwin) target=macos ;; Linux) target=linux ;; *) exit 1 ;; esac
prefix=${SODIUM_PREFIX:-../zen-sodium/build/sodium/$target}
test -f "$prefix/lib/libsodium.a" || { echo 'Build the sibling zen-sodium test oracle or set SODIUM_PREFIX.' >&2; exit 1; }
mkdir -p build/chacha-oracle-source
ln -sfn "$root/src/chacha20poly1305.zen" build/chacha-oracle-source/chacha20poly1305.zen
ln -sfn "$root/tests/chacha20poly1305_oracle.zen" build/chacha-oracle-source/main.zen
"$compiler" build build/chacha-oracle-source --emit-c -o build/chacha_oracle.c
${CC:-clang} -O3 -Wno-parentheses-equality -I"$prefix/include" build/chacha_oracle.c "$prefix/lib/libsodium.a" -o build/chacha-oracle
build/chacha-oracle
${CC:-clang} -O2 -Wno-parentheses-equality -fsanitize=undefined -fno-sanitize-recover=all -I"$prefix/include" build/chacha_oracle.c "$prefix/lib/libsodium.a" -o build/chacha-oracle-ubsan
build/chacha-oracle-ubsan
sh scripts/check-chacha20poly1305-native.sh
