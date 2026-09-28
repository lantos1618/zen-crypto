#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
compiler=${ZEN_COMPILER:-../zen-actor-runtime/zen}
export ZEN_STD=${ZEN_STD:-../zen-actor-runtime/src}
mkdir -p build
"$compiler" build test > build/compile.log 2>&1
./build/test
"$compiler" build src --entry ../tests/main.zen --emit-c -o build/test.c
# Test-only attribute preserves this one generated function for inspection.
# Arithmetic helpers still inline. Library source and production build unchanged.
sed 's/static bool zu_f2_6crypto21equal_bytes_candidate/static __attribute__((noinline,used)) bool zu_f2_6crypto21equal_bytes_candidate/g' build/test.c > build/audit.c
clang -O2 -S build/audit.c -o build/audit.s 2> build/audit-compile.log
# Normal project optimization, including inlining and auto-vectorization.
clang -O2 -S build/test.c -o build/optimized.s 2> build/optimized-compile.log
clang -O2 build/test.c -o build/emitted-test 2> build/emitted-compile.log
./build/emitted-test

sh scripts/check-blake2b-native.sh
