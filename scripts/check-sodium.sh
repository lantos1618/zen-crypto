#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
compiler=${ZEN_COMPILER:-../zen/build/dev/actor-zen}
export ZEN_STD=${ZEN_STD:-../zen/src}
if [ ! -f build/sodium/macos/lib/libsodium.a ]; then scripts/build-sodium.sh macos; fi
"$compiler" build src --entry ../tests/sodium_test.zen --emit-c -o build/sodium_test.c
clang -O2 -fsanitize=undefined -fno-sanitize-recover=all -Ibuild/sodium/macos/include \
  build/sodium_test.c build/sodium/macos/lib/libsodium.a -o build/sodium_test
build/sodium_test
