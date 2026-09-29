#!/usr/bin/env python3
"""Independent Python SHA256/HMAC/HKDF and cryptography record oracles."""
import argparse
import hashlib
import hmac
import os
import re
from pathlib import Path
import shutil
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument('--zen', type=Path, default=ROOT.parent / 'zen-actor-runtime/zen')
p.add_argument('--std', type=Path, default=ROOT.parent / 'zen-actor-runtime/src')
a = p.parse_args()
work = ROOT / 'build/tls13-tests'
stage = work / 'stage'
stage.mkdir(parents=True, exist_ok=True)
for source in (ROOT / 'src').glob('*.zen'):
    shutil.copy(source, stage / source.name)

def extract(salt, ikm): return hmac.digest(salt, ikm, 'sha256')
def expand(secret, info, count):
    result = last = b''
    for i in range(1, (count + 31) // 32 + 1):
        last = hmac.digest(secret, last + info + bytes([i]), 'sha256')
        result += last
    return result[:count]
def label(secret, name, context, count=32):
    name = b'tls13 ' + name.encode()
    return expand(secret, count.to_bytes(2, 'big') + bytes([len(name)]) + name + bytes([len(context)]) + context, count)
def finished(secret, digest): return hmac.digest(label(secret, 'finished', b''), digest, 'sha256')
lines = []
def load(target, value): lines.append(f'    unhex({target}, "{value.hex()}");')
def check(call, target, value):
    lines.append(f'    good = {call} && good;')
    lines.append(f'    good = same({target}, "{value.hex()}") && good;')
psk = bytes(range(32)); th = hashlib.sha256(b'client hello + server hello fixture').digest()
load('psk', psk); load('hash', th)
early = extract(bytes(32), psk)
handshake = extract(label(early, 'derived', hashlib.sha256(b'').digest()), bytes(32))
client = label(handshake, 'c hs traffic', th); server = label(handshake, 's hs traffic', th)
check('tls13_handshake_secrets(schedule, 128, psk, 32, hash, scratch, 4096)', 'schedule', early + handshake + client + server)
# The public additive DHE helper must retain PSK-only compatibility and bind
# all 32 shared-secret bytes into HKDF extraction. Expected 128-byte schedules
# come from Python hashlib/hmac, independently of the Zen implementation.
for shared_input in [bytes(32), bytes(range(32)), bytes([255]) * 32,
                     bytes.fromhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742')]:
    load('secret', shared_input)
    hs_dhe = extract(label(early, 'derived', hashlib.sha256(b'').digest()), shared_input)
    expected_dhe = early + hs_dhe + label(hs_dhe, 'c hs traffic', th) + label(hs_dhe, 's hs traffic', th)
    check('tls13_handshake_secrets_dhe(schedule, 128, psk, 32, secret, hash, scratch, 4096)', 'schedule', expected_dhe)
for call in [
    'tls13_handshake_secrets_dhe(schedule, 128, psk, 32, null_ptr<u8>(), hash, scratch, 4096)',
    'tls13_handshake_secrets_dhe(schedule, 127, psk, 32, secret, hash, scratch, 4096)',
    'tls13_handshake_secrets_dhe(schedule, 128, psk, 32, secret, hash, scratch, 4095)',
    'tls13_handshake_secrets_dhe(null_ptr<u8>(), 128, psk, 32, secret, hash, scratch, 4096)',
    'tls13_handshake_secrets_dhe(schedule, 128, null_ptr<u8>(), 32, secret, hash, scratch, 4096)',
    'tls13_handshake_secrets_dhe(schedule, 128, psk, 0, secret, hash, scratch, 4096)',
    'tls13_handshake_secrets_dhe(schedule, 128, psk, 32, secret, null_ptr<u8>(), scratch, 4096)',
    'tls13_handshake_secrets_dhe(schedule, 128, psk, 32, secret, hash, null_ptr<u64>(), 4096)',
]:
    lines.append('    Range(0, 128).loop((i) { schedule.write(i, 165); });')
    lines.append(f'    good = !{call} && good;')
    lines.append('    Range(0, 128).loop((i) { good = schedule.read(i) == 165 && good; });')
# Restore the original zero-DHE schedule used by the existing tests below.
check('tls13_handshake_secrets(schedule, 128, psk, 32, hash, scratch, 4096)', 'schedule', early + handshake + client + server)
check('tls13_binder(output, 64, psk, 32, hash, scratch, 4096)', 'output', finished(label(early, 'ext binder', hashlib.sha256(b'').digest()), th))
check('tls13_finished(output, 64, schedule.offset(64), hash, scratch, 4096)', 'output', finished(client, th))
master = extract(label(handshake, 'derived', hashlib.sha256(b'').digest()), bytes(32))
check('tls13_application_secrets(output, 96, schedule.offset(32), hash, scratch, 4096)', 'output', master + label(master, 'c ap traffic', th) + label(master, 's ap traffic', th))
check('tls13_traffic_keys(output, 44, schedule.offset(64), scratch, 4096)', 'output', label(client, 'key', b'', 32) + label(client, 'iv', b'', 12))
# RFC8448 section4 fixed derive-secret values, distinct from our Python fixture.
rfc_secret=bytes.fromhex('005cb112fd8eb4ccc623bb88a07c64b3ede1605363fc7d0df8c7ce4ff0fb4ae6')
rfc_hash=bytes.fromhex('f736cb34fe25e701551bee6fd24c1cc7102a7daf9405cb15d97aafe16f757d03')
rfc_expected=bytes.fromhex('2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f')
assert label(rfc_secret, 'c hs traffic', rfc_hash) == rfc_expected
load('secret',rfc_secret);load('hash',rfc_hash)
check('tls13_derive_secret(output, 32, secret, "c hs traffic", hash, scratch, 4096)', 'output', rfc_expected)
# Largest encodable label/context catches internal workspace overlap.
load('expected', bytes(range(255)))
check('tls13_expand_label(output, 128, 128, secret, "' + 'x'*249 + '", expected, 255, scratch, 4096)', 'output', label(rfc_secret, 'x'*249, bytes(range(255)),128))
key=bytes(range(32));iv=bytes(range(12));load('key',key);load('iv',iv)
for size in [0,1,127,128,129,16384]:
 for sequence in [0,0x0102030405060708]:
    message=bytes(i%256 for i in range(size));inner=message+b'\x17';header=b'\x17\x03\x03'+(len(inner)+16).to_bytes(2,'big')
    nonce=bytes(x^y for x,y in zip(iv,sequence.to_bytes(12,'big')))
    record=header+ChaCha20Poly1305(key).encrypt(nonce,inner,header)
    lines.append(f'    good = tls13_seal(output, 17000, message, {size}, 23, key, iv, {sequence}, scratch, 4096).try() == {len(record)} && good;')
    check(f'sha256_candidate(digest, 32, output, {len(record)}, hash_bytes, 64, separate_words, 72)', 'digest', hashlib.sha256(record).digest())
    lines.append(f'    opened{size}_{sequence} = tls13_open(expected, 17000, output, {len(record)}, key, iv, {sequence}, scratch, 4096).try();')
    lines.append(f'    good = opened{size}_{sequence}.count == {size} && opened{size}_{sequence}.kind == 23 && good;')
    lines.append(f'    Range(0, {size}).loop((i) {{ good = expected.read(i) == message.read(i) && good; }});')
# Independent padded records, including padding-only application data.
for index,inner in enumerate([b'hello\x17'+bytes(64), b'\x17'+bytes(8), bytes(32), b'bad\x14']):
 header=b'\x17\x03\x03'+(len(inner)+16).to_bytes(2,'big');record=header+ChaCha20Poly1305(key).encrypt(iv,inner,header);load('output',record)
 if index<2:
    lines.append(f'    padded{index} = tls13_open(expected, 17000, output, {len(record)}, key, iv, 0, scratch, 4096).try();')
    lines.append(f'    good = padded{index}.count == {[5,0][index]} && padded{index}.kind == 23 && good;')
 else:
    lines.append('    Range(0, 64).loop((i) { expected.write(i, 165); });')
    lines.append(f'    good = tls13_open(expected, 17000, output, {len(record)}, key, iv, 0, scratch, 4096).match({{Ok(_) => false, Err(_) => true}}) && good;')
    lines.append('    Range(0, 64).loop((i) { good = expected.read(i) == 165 && good; });')
# RFC8446 section5.4 includes padding in the 2^14+1 inner-plaintext limit.
# Both records authenticate correctly and contain only five content bytes.
for inner_size in (16385, 16386):
    inner = b'hello\x17' + bytes(inner_size - 6)
    header = b'\x17\x03\x03' + (len(inner) + 16).to_bytes(2, 'big')
    record = header + ChaCha20Poly1305(key).encrypt(iv, inner, header)
    load('output', record)
    lines.append('    Range(0, 64).loop((i) { expected.write(i, 165); });')
    call = f'tls13_open(expected, 64, output, {len(record)}, key, iv, 0, scratch, 4096)'
    if inner_size == 16385:
        lines.append(f'    maximum_padding = {call}.try();')
        lines.append('    good = maximum_padding.count == 5 && maximum_padding.kind == 23 && good;')
        lines.append('    good = same(expected, "68656c6c6f") && good;')
    else:
        lines.append(f'    good = {call}.match({{Ok(_) => false, Err(_) => true}}) && good;')
        lines.append('    Range(0, 64).loop((i) { good = expected.read(i) == 165 && good; });')
# Corrupt every byte of a small record; output must stay unchanged.
inner=b'hello\x17';header=b'\x17\x03\x03'+(len(inner)+16).to_bytes(2,'big');record=header+ChaCha20Poly1305(key).encrypt(iv,inner,header);load('output',record)
lines += [f'    Range(0, {len(record)}).loop((i) {{', '        old = output.read(i); output.write(i, old +% 1);', '        Range(0, 64).loop((j) { expected.write(j, 165); });', f'        good = tls13_open(expected, 64, output, {len(record)}, key, iv, 0, scratch, 4096).match({{Ok(_) => false, Err(_) => true}}) && good;', '        Range(0, 64).loop((j) { good = expected.read(j) == 165 && good; });', '        output.write(i, old);', '    });']
for call in ['tls13_seal(output, 17000, message, 1, 23, key, iv, 18446744073709551615, scratch, 4096)', 'tls13_seal(output, 21, message, 0, 23, key, iv, 0, scratch, 4096)', 'tls13_seal(output, 17000, message, 0, 22, key, iv, 0, scratch, 4096)', 'tls13_open(expected, 4, output, 27, key, iv, 0, scratch, 4096)', 'tls13_open(expected, 64, output, 27, key, iv, 1, scratch, 4096)']:
 lines.append(f'    good = {call}.match({{Ok(_) => false, Err(_) => true}}) && good;')
source=(ROOT/'tests/tls13_test.zen').read_text().replace('    // VECTORS','\n'.join(lines))
(stage/'main.zen').write_text(source)
subprocess.run([str(a.zen.resolve()),'build',str(stage),'--std',str(a.std.resolve()),'--emit-c','-o',str(work/'test.c')],check=True)
subprocess.run([os.getenv('CC','clang'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(work/'test.c'),'-o',str(work/'test')],check=True)
subprocess.run([str(work/'test')],check=True)
print('PASS independent PSK/DHE schedules (4 DHE vectors, 8 invalid cases) + 12 ChaCha20 record vectors, padding boundaries and tampering; no external crypto linked')

symbols = subprocess.run(['nm','-u',str(work/'test')],check=True,capture_output=True,text=True).stdout
(work/'undefined-symbols.txt').write_text(symbols)
for line in symbols.splitlines():
    fields=line.split()
    if fields:
        symbol=fields[-1].lstrip('_').split('@',1)[0]
        assert not re.match(r'(sodium_|crypto_|SSL_|OPENSSL_|EVP_|randombytes)',symbol),symbol
# Alter TLS domain separation in a staged copy only; vectors must reject it.
original=(stage/'tls13.zen').read_text()
assert original.count('prefix: str = "tls13 "') == 1
(stage/'tls13.zen').write_text(original.replace('prefix: str = "tls13 "','prefix: str = "tls12 "',1))
try:
    subprocess.run([str(a.zen.resolve()),'build',str(stage),'--std',str(a.std.resolve()),'--emit-c','-o',str(work/'negative.c')],check=True)
    subprocess.run([os.getenv('CC','clang'),'-O2',str(work/'negative.c'),'-o',str(work/'negative')],check=True)
    bad=subprocess.run([str(work/'negative')],capture_output=True,text=True)
    assert bad.returncode == 1 and ': false' in bad.stdout,(bad.returncode,bad.stdout,bad.stderr)
finally:
    (stage/'tls13.zen').write_text(original)
print('PASS no external crypto symbols and wrong TLS label negative control')
