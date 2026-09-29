#!/usr/bin/env python3
"""Deterministic resumable record tests; Python crypto is only an oracle."""
import os
from pathlib import Path
import re
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[1]
ZEN = Path(os.environ.get('ZEN_COMPILER', ROOT.parent / 'zen-crypto-numeric/zen')).resolve()
STD = Path(os.environ.get('ZEN_STD', ROOT.parent / 'zen-crypto-numeric/src')).resolve()
WORK = ROOT / 'build/tls13-record-engine'
STAGE = WORK / 'source'
STAGE.mkdir(parents=True, exist_ok=True)
for source in (ROOT / 'src').glob('*.zen'):
    (STAGE / source.name).write_text(source.read_text())

def record(sending, sequence, message, kind=23):
    key = bytes(range(0 if sending else 32, 32 if sending else 64))
    iv = bytes(range(0 if sending else 12, 12 if sending else 24))
    nonce = bytes(x ^ y for x, y in zip(iv, sequence.to_bytes(12, 'big')))
    head = b'\x17\x03\x03' + (len(message) + 17).to_bytes(2, 'big')
    return head + ChaCha20Poly1305(key).encrypt(nonce, message + bytes([kind]), head)

vectors = [record(True, 0, b'outbound'), record(True, 1, b'next'),
           record(False, 0, b'hello'), record(False, 1, b'world'),
           record(False, 2, b''), record(False, 3, b'\x01\x00', 21),
           record(False, 0, b'\x01\x00', 21), record(True, 2, b'\x01\x00', 21), record(True, 1, b'\x01\x00', 21)]
source = ['ORACLE_COUNT*: usize = 9', 'oracle* = (index: usize, out: Ptr<u8>) usize { index.match({']
for index, value in enumerate(vectors):
    source += [f'{index} => {{']
    source += [f'out.write({i}, {byte});' for i, byte in enumerate(value)]
    source += [f'{len(value)} }},']
source += ['_ => 0,', '}) }']
(STAGE / 'record_oracle.zen').write_text('\n'.join(source))
(STAGE / 'main.zen').write_text((ROOT / 'tests/tls13_record_engine.zen').read_text())
with (WORK / 'compile.log').open('w') as log:
    subprocess.run([str(ZEN), 'build', str(STAGE), '--std', str(STD), '--emit-c', '-o', str(WORK/'test.c')], check=True, stdout=log, stderr=log)
    subprocess.run([os.environ.get('CC', 'clang'), '-O2', '-g', '-Werror=parentheses-equality', '-fsanitize='+os.environ.get('SANITIZERS', 'undefined'), '-fno-sanitize-recover=all', str(WORK/'test.c'), '-o', str(WORK/'test')], check=True, stdout=log, stderr=log)
symbols = subprocess.check_output(['nm', '-u', str(WORK/'test')], text=True)
assert not re.search(r'\b_?(?:SSL_|OPENSSL_|EVP_|sodium_|crypto_|randombytes)', symbols), symbols
subprocess.run([str(WORK/'test')], check=True, timeout=30)
print('PASS independent ChaCha20-Poly1305 record oracle, sanitizer and native symbol gates')

# A private-state boundary fixture checks both directions at sequence exhaustion.
# Only staged source is changed; the production constructor remains untouched.
session_path = STAGE / 'tls13_session.zen'
original_session = session_path.read_text()
def compile_variant(name):
    with (WORK / (name + '.log')).open('w') as log:
        subprocess.run([str(ZEN), 'build', str(STAGE), '--std', str(STD), '--emit-c', '-o', str(WORK / (name + '.c'))], check=True, stdout=log, stderr=log)
        subprocess.run([os.environ.get('CC', 'clang'), '-O2', '-g', '-Werror=parentheses-equality', '-fsanitize='+os.environ.get('SANITIZERS', 'undefined'), '-fno-sanitize-recover=all', str(WORK / (name + '.c')), '-o', str(WORK / name)], check=True, stdout=log, stderr=log)
    return WORK / name
try:
    exhausted, count = re.subn(r'(sending|receiving): 0,', r'\1: 18446744073709551615,', original_session)
    assert count == 2, 'sequence initializer contract changed'
    session_path.write_text(exhausted)
    helpers = (ROOT/'tests/tls13_record_engine.zen').read_text().split('exercise =',1)[0]
    limits = r"""
main = (env: Env) Res<(), AllocError | Failure | Tls13ClientError> {
    base=env.mem.alloc(); counts=base.realloc<usize>(null_ptr<usize>(),2).try();
    counts.write(0,0); counts.write(1,0);
    a=Tracking(base:base,allocations:counts,frees:counts.offset(1));
    sender ::= new_session(a).try();
    sender.queue_record("x".ptr(),1).match({Err(Limit)=>Ok(()),_=>Err(Failure.Accepted)}).try();
    sender.abort();
    receiver ::= new_session(a).try(); wire=base.raw(64,8).try(); count=oracle(2,wire);
    receiver.feed(wire,count).match({Err(Limit)=>Ok(()),_=>Err(Failure.Accepted)}).try();
    receiver.abort();
    (counts.read(0)==4 && counts.read(1)==4).ensure(Failure.Ownership).try();
    println("record engine: both sequence exhaustion paths and exactly-once cleanup PASS");
    Ok(())
}
"""
    (STAGE/'main.zen').write_text(helpers+limits)
    subprocess.run([str(compile_variant('exhaustion'))], check=True, timeout=30)
    # Deliberately consume a nonce on each partial output acknowledgement.
    needle = 'self.acknowledged = self.acknowledged + count;'
    assert original_session.count(needle) == 1
    session_path.write_text(original_session.replace(needle, needle+'\n        (count > 0).then(() { self.sending = self.sending + 1; });'))
    (STAGE/'main.zen').write_text((ROOT/'tests/tls13_record_engine.zen').read_text())
    negative = subprocess.run([str(compile_variant('nonce-negative'))], capture_output=True, text=True, timeout=30)
    assert negative.returncode == 1, (negative.returncode, negative.stdout, negative.stderr)
    assert 'record engine:' not in negative.stdout
    print('PASS negative control: advancing nonce on partial acknowledgement is rejected')
finally:
    session_path.write_text(original_session)
    (STAGE/'main.zen').write_text((ROOT/'tests/tls13_record_engine.zen').read_text())
