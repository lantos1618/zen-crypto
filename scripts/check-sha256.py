#!/usr/bin/env python3
"""Native SHA-256/HMAC/HKDF KATs plus deterministic Python stdlib oracles.
RFC 6234 SHA-256, RFC 4231 HMAC, RFC 5869 appendix A SHA-256 vectors.
No external crypto implementation is linked into the Zen test executable.
"""
from pathlib import Path
import hashlib
import hmac
import os
import random
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / 'build' / 'sha256-check'
WORK.mkdir(parents=True, exist_ok=True)
compiler = Path(os.environ.get('ZEN_COMPILER', ROOT.parent / 'zen-actor-runtime' / 'zen')).resolve()
std = Path(os.environ.get('ZEN_STD', ROOT.parent / 'zen-actor-runtime' / 'src')).resolve()
for name in ('sha256', 'hmac_sha256', 'hkdf'):
    shutil.copyfile(ROOT / 'src' / (name + '.zen'), WORK / (name + '.zen'))
shutil.copyfile(ROOT / 'tests' / 'sha256_test_support.zen', WORK / 'support.zen')
lines = []
counts = {'sha': 0, 'hmac': 0, 'hkdf': 0}

def add(kind, *parts):
    values = [p.hex() if isinstance(p, bytes) else p for p in parts]
    expression = 'h.' + kind + '(' + ', '.join('"' + p + '"' for p in values) + ')'
    lines.append(f'    good = check({expression}, {len(lines)}) && good;')
    counts[kind] += 1

def derive(salt, ikm, info, length):
    prk = hmac.digest(salt, ikm, 'sha256')
    out = b''
    previous = b''
    for n in range(1, (length + 31) // 32 + 1):
        previous = hmac.digest(prk, previous + info + bytes([n]), 'sha256')
        out += previous
    return prk, out[:length]

# Fixed published answers, independent of the Python oracle below.
add('sha', b'', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
add('sha', b'abc', 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
add('sha', b'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq', '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1')
add('hmac', b'\x0b' * 20, b'Hi There', 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
add('hmac', b'Jefe', b'what do ya want for nothing?', '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843')
add('hmac', b'\xaa' * 20, b'\xdd' * 50, '773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe')
add('hmac', bytes(range(1, 26)), b'\xcd' * 50, '82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b')
add('hmac', b'\x0c' * 20, b'Test With Truncation', 'a3b6167473100ee06e0c796c2955552b')
add('hmac', b'\xaa' * 131, b'Test Using Larger Than Block-Size Key - Hash Key First', '60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54')
add('hmac', b'\xaa' * 131, b'This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.', '9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2')
add('hkdf', bytes(range(13)), b'\x0b' * 22, bytes(range(240, 250)),
    '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
    '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
add('hkdf', bytes(range(96, 176)), bytes(range(80)), bytes(range(176, 256)),
    '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
    'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87')
add('hkdf', b'', b'\x0b' * 22, b'',
    '19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
    '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8')
rng = random.Random(623442315869)
for length in list(range(130)) + [255, 256, 257, 511, 512, 513, 1024, 8193]:
    data = rng.randbytes(length)
    add('sha', data, hashlib.sha256(data).digest())
for key_length in [0, 1, 31, 32, 63, 64, 65, 127, 128, 131, 255]:
    for data_length in [0, 1, 55, 56, 63, 64, 65, 129, 1024]:
        key = rng.randbytes(key_length); data = rng.randbytes(data_length)
        add('hmac', key, data, hmac.digest(key, data, 'sha256'))
for length in [0, 1, 31, 32, 33, 63, 64, 65, 255, 1024, 8160]:
    for salt_length in [0, 32, 65]:
        salt = rng.randbytes(salt_length); ikm = rng.randbytes(97); info = rng.randbytes(131)
        prk, okm = derive(salt, ikm, info, length)
        add('hkdf', salt, ikm, info, prk, okm)
source = '''Support = support
check = (value: bool, index: usize) bool {
    (!value).then(() { println("FAIL vector {}", index); });
    value
}
main = (env: Env) Res<i32, AllocError> {
    a = env.mem.alloc();
    h = Support.Harness(
        input: a.realloc<u8>(null_ptr<u8>(), 1000000).try(),
        key: a.realloc<u8>(null_ptr<u8>(), 512).try(),
        info: a.realloc<u8>(null_ptr<u8>(), 1024).try(),
        output: a.realloc<u8>(null_ptr<u8>(), 8160).try(),
        prk: a.realloc<u8>(null_ptr<u8>(), 32).try(),
        bytes: a.realloc<u8>(null_ptr<u8>(), 256).try(),
        words: a.realloc<u32>(null_ptr<u32>(), 72).try()
    );
    good ::= true;
''' + '\n'.join(lines) + '''
    good = check(h.million(), 10000) && good;
    good = check(h.invalid(), 10001) && good;
    println("SHA256/HMAC/HKDF RFC + Python oracle + incremental/alias/invalid checks: {}", good);
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
    print(mode + ': ' + (WORK / (mode + '-run.log')).read_text().strip())
symbols = subprocess.check_output(['nm', '-u', str(WORK / 'O3')], text=True)
assert not re.search(r'\b_?(?:SHA256|HMAC|EVP_|OPENSSL_|crypto_|sodium_)', symbols), symbols
(WORK / 'undefined-symbols.txt').write_text(symbols)
mutated = (WORK / 'test.c').read_text()
assert '1779033703' in mutated
(WORK / 'mutated.c').write_text(mutated.replace('1779033703', '1779033702'))
run([os.environ.get('CC', 'clang'), '-O2', str(WORK / 'mutated.c'), '-o', str(WORK / 'mutated')], 'mutated-build.log')
result = subprocess.run([str(WORK / 'mutated')], capture_output=True, text=True)
(WORK / 'mutated-run.log').write_text(result.stdout + result.stderr)
assert result.returncode == 1 and 'FAIL vector' in result.stdout, result
print('Known-answer negative control: changed SHA-256 IV rejected; no external crypto symbols')
print('Vector counts:', counts, '+ million-byte SHA, incremental/alias/invalid checks')
