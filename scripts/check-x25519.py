#!/usr/bin/env python3
"""Native RFC 7748 X25519 tests; cryptography is an independent test oracle.
Specification/KATs: https://www.rfc-editor.org/rfc/rfc7748#section-5
No reference crypto library is linked into the emitted native executable.
"""
from pathlib import Path
import os
import random
import re
import shutil
import subprocess
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build' / 'x25519-check'
WORK.mkdir(parents=True, exist_ok=True)
compiler = Path(os.environ.get('ZEN_COMPILER', ROOT.parent / 'zen-actor-runtime' / 'zen')).resolve()
std = Path(os.environ.get('ZEN_STD', ROOT.parent / 'zen-actor-runtime' / 'src')).resolve()
shutil.copyfile(ROOT / 'src/x25519.zen', WORK / 'x25519.zen')
shutil.copyfile(ROOT / 'tests/x25519_test_support.zen', WORK / 'support.zen')
lines = []
counts = {'vectors': 0, 'rejects': 0}
base = '09' + '00' * 31
alice = '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a'
alice_public = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
bob = '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb'
bob_public = 'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'
shared = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742'

def add(key, peer, expected, public=False):
    expression = f'h.vector("{key}", "{peer}", "{expected}", {str(public).lower()})'
    lines.append(f'    good = check({expression}, {len(lines)}) && good;')
    counts['vectors'] += 1

def oracle(key, peer, public=False):
    private = X25519PrivateKey.from_private_bytes(key)
    try:
        expected = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw) if public else private.exchange(X25519PublicKey.from_public_bytes(peer))
    except ValueError:
        lines.append(f'    good = check(h.reject("{key.hex()}", "{peer.hex()}"), {len(lines)}) && good;')
        counts['rejects'] += 1
    else:
        add(key.hex(), peer.hex(), expected.hex(), public)

# Fixed published answers do not depend on the oracle.
add('a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4',
    'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c',
    'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552')
add('4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d',
    'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493',
    '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957')
add(alice, base, alice_public, True); add(bob, base, bob_public, True)
add(alice, bob_public, shared); add(bob, alice_public, shared)
rng = random.Random(7748)
for _ in range(64):
    key, peer = rng.randbytes(32), rng.randbytes(32)
    oracle(key, peer); oracle(key, bytes.fromhex(base), True)
# Exhaust all combinations of scalar bits removed/forced by clamping.
for low in range(8):
    for high in range(4):
        key = bytearray.fromhex(alice)
        key[0] = (key[0] & 248) | low
        key[31] = (key[31] & 63) | (high << 6)
        add(key.hex(), bob_public, shared)
# Noncanonical u in [p, 2^255-1], near-boundary limbs, and masked high bit.
p = 2**255 - 19
for n in [0, 1, 2, 9, 32767, 32768, 2**254 - 1, *range(p - 20, p + 19)]:
    for high in (0, 2**255):
        oracle(bytes.fromhex(alice), (n + high).to_bytes(32, 'little'))
# Other low-order u coordinates (order 8), plus top-bit equivalents.
for text in ['e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800',
             '5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157']:
    for high in (0, 128):
        peer = bytearray.fromhex(text); peer[31] |= high
        oracle(bytes.fromhex(alice), bytes(peer))
for key in (bytes(32), b'\xff' * 32, b'\x55' * 32, b'\xaa' * 32):
    oracle(key, bytes.fromhex(base), True)
source = '''Support = support
check = (value: bool, index: usize) bool {
    (!value).then(() { println("FAIL X25519 vector {}", index); });
    value
}
main = (env: Env) Res<i32, AllocError> {
    a = env.mem.alloc();
    h = Support.Harness(bytes: a.raw(200, 8).try(), words: a.raw(354 * 8, 8).try().to<u64>());
    good ::= true;
''' + '\n'.join(lines) + '''
    good = check(h.invalid(), 10000) && good;
    good = check(h.iterations(), 10001) && good;
    println("X25519 RFC7748 + independent differential, clamping, canonicalization, low order, aliases, bounds, 1/1000 iterations: {}", good);
    Ok(good.match({true => 0, false => 1}))
}
'''
(WORK / 'main.zen').write_text(source)

def run(command, log):
    with (WORK / log).open('w') as output:
        result = subprocess.run(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
    if result.returncode:
        print((WORK / log).read_text()[-6000:])
        raise SystemExit(f'Failed: {command[0]} (see {WORK / log})')

run([str(compiler), 'build', str(WORK), '--std', str(std), '--emit-c', '-o', str(WORK / 'test.c')], 'emit.log')
for mode, flags in [('O3', ['-O3']), ('ubsan', ['-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all'])]:
    run([os.environ.get('CC', 'clang'), *flags, str(WORK / 'test.c'), '-o', str(WORK / mode)], mode + '-build.log')
    run([str(WORK / mode)], mode + '-run.log')
    print(mode + ': ' + (WORK / (mode + '-run.log')).read_text().strip(), flush=True)
symbols = subprocess.check_output(['nm', '-u', str(WORK / 'O3')], text=True)
assert not re.search(r'\b_?(?:X25519|EVP_|OPENSSL_|crypto_|sodium_)', symbols), symbols
(WORK / 'undefined-symbols.txt').write_text(symbols)
mutated = (WORK / 'test.c').read_text()
assert '121665' in mutated
(WORK / 'mutated.c').write_text(mutated.replace('121665', '121664'))
run([os.environ.get('CC', 'clang'), '-O2', str(WORK / 'mutated.c'), '-o', str(WORK / 'mutated')], 'mutated-build.log')
result = subprocess.run([str(WORK / 'mutated')], capture_output=True, text=True)
(WORK / 'mutated-run.log').write_text(result.stdout + result.stderr)
assert result.returncode == 1 and 'FAIL X25519 vector' in result.stdout, result
print('Known-answer negative control: wrong Montgomery constant rejected; no external crypto symbols')
print('Vector counts:', counts, '(each successful vector in five output alias modes; rejected secrets in three alias modes); 11 invalid arguments; 1/1000 iteration KATs')
