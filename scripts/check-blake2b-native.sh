#!/bin/sh
# Native algorithm tests: no OpenSSL/libsodium checkout, header or library needed.
set -eu
cd "$(dirname "$0")/.."
compiler=${ZEN_COMPILER:-../zen-actor-runtime/zen}
export ZEN_STD=${ZEN_STD:-../zen-actor-runtime/src}
mkdir -p build
"$compiler" build src --entry ../tests/blake2b_native_test.zen --emit-c -o build/blake2b_native_test.c
${CC:-clang} -O2 -fsanitize=undefined -fno-sanitize-recover=all \
    build/blake2b_native_test.c -o build/blake2b_native_test
build/blake2b_native_test

# The standalone executable must not acquire an external crypto dependency.
nm -u build/blake2b_native_test > build/blake2b-native-undefined-symbols.txt
${PYTHON:-python3} - <<'PY'
from pathlib import Path
import re

symbols = Path('build/blake2b-native-undefined-symbols.txt').read_text()
crypto = re.compile(r'^(?:sodium_|randombytes|crypto_|SSL_|OPENSSL_|EVP_|BLAKE2|blake2b)')
for line in symbols.splitlines():
    fields = line.split()
    if fields:
        symbol = fields[-1].lstrip('_').split('@', 1)[0]
        assert not crypto.match(symbol), f'Unexpected external crypto symbol: {symbol}'
print('Standalone undefined symbols: no sodium/OpenSSL/BLAKE2 references')

# Mutate a generated-C copy only. A one-bit IV error must fail known answers.
source = Path('build/blake2b_native_test.c').read_text()
original = 'return 7640891576956012808;'
assert source.count(original) == 1, 'Expected exactly one first BLAKE2b IV return'
mutated = source.replace(original, 'return 7640891576956012809;', 1)
Path('build/blake2b_negative_control.c').write_text(mutated)
PY
${CC:-clang} -O2 -fsanitize=undefined -fno-sanitize-recover=all \
    build/blake2b_negative_control.c -o build/blake2b_negative_control
${PYTHON:-python3} - <<'PY'
from pathlib import Path
import subprocess

result = subprocess.run(['build/blake2b_negative_control'], capture_output=True, text=True)
log = result.stdout + result.stderr + f'Negative control exit: {result.returncode}\n'
Path('build/blake2b-negative-control.log').write_text(log)
assert result.returncode == 1, f'IV mutation did not exit 1: {log}'
assert 'Standalone native BLAKE2b:' in result.stdout and ': false' in result.stdout, log
print('Negative control: IV bit flip rejected by known-answer tests (exit 1)')
PY
