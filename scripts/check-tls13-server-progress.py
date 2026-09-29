#!/usr/bin/env python3
"""Independent deterministic server-handshake progress tests, no socket I/O."""
import ast
import hashlib
import hmac
import os
from pathlib import Path
import re
import subprocess
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
ROOT = Path(__file__).resolve().parents[1]
ZEN = Path(os.environ.get('ZEN_COMPILER', ROOT.parent/'zen-crypto-numeric/zen')).resolve()
STD = Path(os.environ.get('ZEN_STD', ROOT.parent/'zen-crypto-numeric/src')).resolve()
WORK = ROOT/'build/tls13-server-progress'
STAGE = WORK/'source'
STAGE.mkdir(parents=True, exist_ok=True)
for source in (ROOT/'src').glob('*.zen'):
    (STAGE/source.name).write_text(source.read_text())
# Reuse only independent Python wire/derivation helpers, not its network suite.
names = {'extract', 'label', 'finished', 'hs', 'plain', 'encrypted', 'extension'}
tree = ast.parse((ROOT/'scripts/check-tls13-server.py').read_text())
exec(compile(ast.Module(body=[n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in names], type_ignores=[]), '<independent TLS oracle>', 'exec'))
psk = bytes(range(32)); server_random = bytes(range(32,64)); server_private = bytes(range(64,96))
client_private = X25519PrivateKey.from_private_bytes(bytes(range(96,128)))
server_key = X25519PrivateKey.from_private_bytes(server_private)
client_public = client_private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
server_public = server_key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
sid = bytes(range(128,160)); random = bytes(range(160,192))
identity = b'ZenTest'; identities = len(identity).to_bytes(2,'big') + identity + bytes(4)
share = b'\0\x1d\0\x20' + client_public
exts = extension(43,b'\2\3\4') + extension(45,b'\1\1') + extension(10,b'\0\2\0\x1d') + extension(51,len(share).to_bytes(2,'big')+share)
exts += extension(41,len(identities).to_bytes(2,'big')+identities+b'\0\x21\x20'+bytes(32))
ch = hs(1,b'\3\3'+random+bytes([len(sid)])+sid+b'\0\2\x13\3\1\0'+len(exts).to_bytes(2,'big')+exts)
early = extract(bytes(32),psk)
ch = ch[:-32] + finished(label(early,'ext binder',hashlib.sha256(b'').digest()),ch[:-35])
exts = extension(43,b'\3\4') + extension(51,b'\0\x1d\0\x20'+server_public) + extension(41,b'\0\0')
sh = hs(2,b'\3\3'+server_random+bytes([len(sid)])+sid+b'\x13\3\0'+len(exts).to_bytes(2,'big')+exts)
secret = extract(label(early,'derived',hashlib.sha256(b'').digest()),client_private.exchange(server_key.public_key()))
transcript = ch+sh; digest = hashlib.sha256(transcript).digest()
client = label(secret,'c hs traffic',digest); server = label(secret,'s hs traffic',digest)
ee = hs(8,b'\0\0'); sf = hs(20,finished(server,transcript+ee)); transcript += ee+sf
cf = hs(20,finished(client,transcript))
master = extract(label(secret,'derived',hashlib.sha256(b'').digest()),bytes(32)); digest = hashlib.sha256(transcript).digest()
capp = label(master,'c ap traffic',digest); sapp = label(master,'s ap traffic',digest)
bad_binder = ch[:-1] + bytes([ch[-1]^1]); bad_finished = cf[:-1]+bytes([cf[-1]^1])
bad_tag = bytearray(encrypted(client,0,cf)); bad_tag[-1] ^= 1
vectors = [plain(22,ch), plain(22,ch[:7])+plain(22,ch[7:]), plain(22,sh)+encrypted(server,0,ee+sf), encrypted(client,0,cf), encrypted(client,0,cf[:8])+encrypted(client,1,cf[8:]), plain(22,bad_binder), encrypted(client,0,bad_finished), encrypted(capp,0,b'hello',23), encrypted(sapp,0,b'world',23),bytes(bad_tag),encrypted(client,0,b'early',23)]
lines=['VECTOR_COUNT*: usize = 11','fixture* = (index: usize, out: Ptr<u8>) usize { index.match({']
for index,value in enumerate(vectors):
    lines += [f'{index} => {{'] + [f'out.write({i},{b});' for i,b in enumerate(value)] + [f'{len(value)} }},']
lines += ['_ => 0,','}) }']
(STAGE/'progress_oracle.zen').write_text('\n'.join(lines))
(STAGE/'main.zen').write_text((ROOT/'tests/tls13_server_progress.zen').read_text())
def build(name):
    with (WORK/(name+'.log')).open('w') as log:
        subprocess.run([str(ZEN),'build',str(STAGE),'--std',str(STD),'--emit-c','-o',str(WORK/(name+'.c'))],check=True,stdout=log,stderr=log)
        subprocess.run([os.environ.get('CC','clang'),'-O2','-g','-Werror=parentheses-equality','-fsanitize='+os.environ.get('SANITIZERS','undefined'),'-fno-sanitize-recover=all',str(WORK/(name+'.c')),'-o',str(WORK/name)],check=True,stdout=log,stderr=log)
    return WORK/name
binary=build('test')
symbols=subprocess.check_output(['nm','-u',str(binary)],text=True)
assert not re.search(r'\b_?(?:SSL_|OPENSSL_|EVP_|sodium_|crypto_|randombytes)',symbols),symbols
subprocess.run([str(binary)],check=True,timeout=60)
print('PASS independent X25519/HKDF/AEAD handshake oracle and native-symbol gate')

# A deliberate staged bypass must fail the independently generated bad-Finished case.
server_source = STAGE/'tls13_server.zen'
original = server_source.read_text()
needle = 'equal(verify, pending.offset(4), 32).ensure(Tls13ClientError.Authentication).try();'
assert original.count(needle) == 1, 'Finished verification boundary changed'
try:
    server_source.write_text(original.replace(needle, 'true.ensure(Tls13ClientError.Authentication).try();'))
    negative = subprocess.run([str(build('finished-negative'))],capture_output=True,text=True,timeout=60)
    assert negative.returncode == 1, (negative.returncode,negative.stdout,negative.stderr)
    assert 'server progress:' not in negative.stdout
    print('PASS negative control: bypassing client Finished authentication is rejected')
finally:
    server_source.write_text(original)
