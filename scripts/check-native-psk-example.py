#!/usr/bin/env python3
"""Compile the loopback entropy example; OpenSSL is only its external test peer."""
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
ZEN = Path(os.getenv('ZEN_COMPILER', ROOT.parent / 'zen-crypto-numeric/zen')).resolve()
STD = Path(os.getenv('ZEN_STD', ROOT.parent / 'zen-crypto-numeric/src')).resolve()
OPENSSL = Path(os.getenv('OPENSSL', ROOT.parent / 'zen-http/build/openssl/bin/openssl')).resolve()
WORK = ROOT / 'build/native-psk-example'
STAGE = WORK / 'stage'
STAGE.mkdir(parents=True, exist_ok=True)
for source in (ROOT / 'src').glob('*.zen'):
    shutil.copyfile(source, STAGE / source.name)
shutil.copyfile(ROOT / 'examples/native_psk_client.zen', STAGE / 'main.zen')
with (WORK / 'compile.log').open('w') as log:
    subprocess.run([str(ZEN), 'build', str(STAGE), '--std', str(STD), '--emit-c', '-o', str(WORK / 'client.c')], check=True, stdout=log, stderr=log, timeout=120)
    subprocess.run([os.getenv('CC', 'clang'), '-O2', '-fsanitize=undefined', '-fno-sanitize-recover=all', str(WORK / 'client.c'), '-o', str(WORK / 'client')], check=True, stdout=log, stderr=log, timeout=120)
symbols = subprocess.check_output(['nm', '-u', str(WORK / 'client')], text=True)
for line in symbols.splitlines():
    fields = line.split()
    if fields:
        name = fields[-1].lstrip('_').split('@', 1)[0]
        assert not re.match(r'(sodium_|crypto_|SSL_|OPENSSL_|EVP_|randombytes)', name), name
assert re.search(r'\b_?getentropy(?:@\S+)?\s*$', symbols, re.M), symbols
(WORK / 'undefined-symbols.txt').write_text(symbols)
with socket.socket() as reservation:
    reservation.bind(('127.0.0.1', 0))
    port = reservation.getsockname()[1]
# Fresh test credential only. Both demo processes receive it in argv; this
# fixture intentionally does not model production PSK provisioning.
psk = os.urandom(32).hex()
with (WORK / 'peer.log').open('w') as log:
    peer = subprocess.Popen([str(OPENSSL), 's_server', '-accept', f'127.0.0.1:{port}', '-nocert', '-psk', psk, '-psk_identity', 'ZenTest', '-groups', 'X25519', '-ciphersuites', 'TLS_CHACHA20_POLY1305_SHA256', '-tls1_3', '-num_tickets', '0', '-rev', '-quiet'], stdin=subprocess.DEVNULL, stdout=log, stderr=log)
    try:
        for _ in range(100):
            if peer.poll() is not None:
                raise RuntimeError('OpenSSL peer exited; see peer.log')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=.1):
                    break
            except OSError:
                time.sleep(.02)
        else:
            raise RuntimeError('OpenSSL peer did not listen')
        result = subprocess.run([str(WORK / 'client'), psk, str(port)], capture_output=True, text=True, timeout=30)
        (WORK / 'run.log').write_text(result.stdout + result.stderr)
        assert result.returncode == 0 and 'Native PSK-DHE echo and authenticated close: true' in result.stdout, (result.returncode, result.stdout, result.stderr)
        print(result.stdout, end='')
    finally:
        peer.terminate()
        try:
            peer.wait(timeout=3)
        except subprocess.TimeoutExpired:
            peer.kill(); peer.wait()
print('PASS two independent std.entropy calls, UBSan, OpenSSL peer and no linked external crypto')
