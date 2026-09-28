#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
compiler=${ZEN_COMPILER:-../zen-actor-runtime/zen}
export ZEN_STD=${ZEN_STD:-../zen-actor-runtime/src}
case "$(uname -s)" in
    Darwin) target=macos ;;
    Linux) target=linux ;;
    *) echo 'Unsupported host for libsodium differential tests' >&2; exit 1 ;;
esac
sodium_prefix=${SODIUM_PREFIX:-../zen-sodium/build/sodium/$target}
if [ ! -f "$sodium_prefix/lib/libsodium.a" ]; then
    echo "Build libsodium first or set SODIUM_PREFIX: $sodium_prefix/lib/libsodium.a" >&2
    exit 1
fi
# Only this test staging root imports the external oracle binding.
root=$(pwd)
oracle=${SODIUM_SOURCE:-$root/../zen-sodium/src/sodium.zen}
test -f "$oracle" || { echo "Missing test oracle binding: $oracle" >&2; exit 1; }
mkdir -p build/differential-source
ln -sfn "$root/src/blake2b.zen" build/differential-source/blake2b.zen
ln -sfn "$oracle" build/differential-source/sodium.zen
ln -sfn "$root/tests/blake2b_test.zen" build/differential-source/main.zen
"$compiler" build build/differential-source --emit-c -o build/blake2b_test.c
${CC:-clang} -O3 -I"$sodium_prefix/include" build/blake2b_test.c \
    "$sodium_prefix/lib/libsodium.a" -o build/blake2b_test
build/blake2b_test
${CC:-clang} -O2 -fsanitize=undefined -fno-sanitize-recover=all \
    -I"$sodium_prefix/include" build/blake2b_test.c \
    "$sodium_prefix/lib/libsodium.a" -o build/blake2b_test_ubsan
build/blake2b_test_ubsan

sh scripts/check-blake2b-native.sh
