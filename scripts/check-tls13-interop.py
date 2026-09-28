#!/usr/bin/env python3
"""OpenSSL peer plus independent PSK peers. Python cryptography is test-only."""
import hashlib,hmac,os,re,shutil,socket,subprocess,threading,time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
ROOT=Path(__file__).resolve().parents[1]
ZEN=Path(os.getenv('ZEN_COMPILER',ROOT.parent/'zen-actor-runtime/zen')).resolve()
STD=Path(os.getenv('ZEN_STD',ROOT.parent/'zen-actor-runtime/src')).resolve()
OPENSSL=Path(os.getenv('OPENSSL',ROOT.parent/'zen-http/build/openssl/bin/openssl')).resolve()
WORK=ROOT/'build/tls13-interop';STAGE=WORK/'stage';STAGE.mkdir(parents=True,exist_ok=True)
PSK=bytes(range(32))
for source in (ROOT/'src').glob('*.zen'):shutil.copy(source,STAGE/source.name)
def build(port):
    source=(ROOT/'tests/tls13_client_test.zen').read_text().replace('TEST_PORT',str(port))
    source=source.replace('// RANDOM','\n'.join(f'random.write({i}, {b});' for i,b in enumerate(os.urandom(32))))
    (STAGE/'main.zen').write_text(source)
    with (WORK/'compile.log').open('w') as log:
        subprocess.run([str(ZEN),'build',str(STAGE),'--std',str(STD),'--emit-c','-o',str(WORK/'client.c')],check=True,stdout=log,stderr=log)
        subprocess.run([os.getenv('CC','clang'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(WORK/'client.c'),'-o',str(WORK/'client')],check=True,stdout=log,stderr=log)
    symbols=subprocess.check_output(['nm','-u',str(WORK/'client')],text=True)
    for line in symbols.splitlines():
        fields=line.split()
        if fields:assert not re.match(r'(sodium_|crypto_|SSL_|OPENSSL_|EVP_|randombytes)',fields[-1].lstrip('_'))
    return WORK/'client'
def run_client(binary,success,alignment_control=False):
    r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=20)
    if alignment_control:
        assert r.returncode != 0 and 'misaligned address' in r.stderr,(r.returncode,r.stdout,r.stderr)
        return 'alignment mutation rejected by UBSan before handshake'
    assert r.returncode==(0 if success else 1),(r.returncode,r.stdout,r.stderr)
    assert 'explicit TLS allocation alignment: true' in r.stdout,r.stdout
    assert ('application authenticated: true' if success else 'output unchanged: true') in r.stdout,r.stdout
    return r.stdout

def listener():
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',0));s.listen(1);s.settimeout(20);return s

def openssl_case(wrong=False,alignment_control=False):
    s=listener();port=s.getsockname()[1];s.close();binary=build(port)
    with (WORK/('openssl-wrong.log' if wrong else 'openssl.log')).open('w') as log:
        proc=subprocess.Popen([str(OPENSSL),'s_server','-accept',f'127.0.0.1:{port}','-nocert','-psk',('ff'*32 if wrong else PSK.hex()),'-psk_identity','ZenTest','-ciphersuites','TLS_CHACHA20_POLY1305_SHA256','-tls1_3','-allow_no_dhe_kex','-num_tickets','0','-rev','-quiet'],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            for _ in range(100):
                if proc.poll() is not None:raise RuntimeError('OpenSSL exited; inspect log')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:time.sleep(.02)
            else:raise RuntimeError('OpenSSL did not listen')
            print(run_client(binary,not wrong,alignment_control).strip())
        finally:
            proc.terminate()
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
    print('PASS OpenSSL '+('alignment regression control' if alignment_control else ('wrong PSK rejected' if wrong else 'PSK authenticated exchange')))

def extract(salt,ikm):return hmac.digest(salt,ikm,'sha256')
def label(secret,name,context,count=32):
    name=b'tls13 '+name.encode();info=count.to_bytes(2,'big')+bytes([len(name)])+name+bytes([len(context)])+context
    out=last=b''
    for i in range(1,(count+31)//32+1):last=hmac.digest(secret,last+info+bytes([i]),'sha256');out+=last
    return out[:count]
def finished(secret,transcript):return hmac.digest(label(secret,'finished',b''),hashlib.sha256(transcript).digest(),'sha256')
def hs(kind,body):return bytes([kind])+len(body).to_bytes(3,'big')+body
def plain(kind,body):return bytes([kind,3,3])+len(body).to_bytes(2,'big')+body
def encrypted(secret,sequence,body,kind=22):
    iv=label(secret,'iv',b'',12);nonce=bytes(x^y for x,y in zip(iv,sequence.to_bytes(12,'big')))
    header=bytes([23,3,3])+(len(body)+17).to_bytes(2,'big')
    return header+ChaCha20Poly1305(label(secret,'key',b'')).encrypt(nonce,body+bytes([kind]),header)
def receive_exact(conn,count):
    data=b''
    while len(data)<count:
        chunk=conn.recv(count-len(data))
        if not chunk:raise EOFError('client closed')
        data+=chunk
    return data
def receive_record(conn):
    header=receive_exact(conn,5);return header,receive_exact(conn,int.from_bytes(header[3:],'big'))
def decrypt(secret,sequence,record):
    header,body=record;iv=label(secret,'iv',b'',12);nonce=bytes(x^y for x,y in zip(iv,sequence.to_bytes(12,'big')))
    return ChaCha20Poly1305(label(secret,'key',b'')).decrypt(nonce,body,header).rstrip(b'\0')
def reference_case(mode):
    server=listener();port=server.getsockname()[1];binary=build(port);errors=[]
    def peer():
        try:
            with server.accept()[0] as conn:
                conn.settimeout(10);_,ch=receive_record(conn);early=extract(bytes(32),PSK)
                binder=finished(label(early,'ext binder',hashlib.sha256(b'').digest()),ch[:-35])
                assert hmac.compare_digest(ch[-32:],binder),'client binder incorrect'
                server_random=(bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c') if mode=='hrr' else os.urandom(32))
                if mode=='oversized-plaintext':
                    conn.sendall(b'\x16\x03\x03\x40\x01')
                    assert not conn.recv(100),'client accepted oversized plaintext header'
                    return
                sh=hs(2,b'\x03\x03'+server_random+b'\0\x13\x03\0'+b'\0\x0c'+b'\0\x2b\0\2\3\4'+b'\0\x29\0\2\0\0')
                for fragment in [sh[:3],sh[3:]]:
                    wire=plain(22,fragment)
                    for i in range(0,len(wire),3):conn.sendall(wire[i:i+3])
                if mode=='hrr':
                    assert not conn.recv(100),'client accepted unsupported HRR'
                    return
                handshake=extract(label(early,'derived',hashlib.sha256(b'').digest()),bytes(32));transcript=ch+sh
                chsecret=label(handshake,'c hs traffic',hashlib.sha256(transcript).digest());shsecret=label(handshake,'s hs traffic',hashlib.sha256(transcript).digest())
                ee=hs(8,b'\0\0');verify=finished(shsecret,transcript+ee)
                if mode=='bad-finished':verify=bytes([verify[0]^1])+verify[1:]
                sf=hs(20,verify)
                if mode=='truncated-finished':sf=sf[:17]
                for seq,fragment in enumerate([ee[:2],ee[2:]+sf[:7],sf[7:]]):
                    wire=encrypted(shsecret,seq,fragment)
                    if mode=='tamper' and seq==2:wire=wire[:-1]+bytes([wire[-1]^1])
                    conn.sendall(wire)
                if mode=='truncated-finished':conn.shutdown(socket.SHUT_WR)
                if mode!='valid':
                    try:extra=conn.recv(100)
                    except ConnectionResetError:extra=b''
                    assert not extra,'client sent data before authenticating Finished'
                    return
                transcript+=ee+sf;cf=decrypt(chsecret,0,receive_record(conn))
                assert cf==hs(20,finished(chsecret,transcript))+b'\x16','client Finished incorrect'
                master=extract(label(handshake,'derived',hashlib.sha256(b'').digest()),bytes(32));digest=hashlib.sha256(transcript).digest()
                clientapp=label(master,'c ap traffic',digest);serverapp=label(master,'s ap traffic',digest)
                assert decrypt(clientapp,0,receive_record(conn))==b'native zen\n\x17'
                conn.sendall(encrypted(serverapp,0,b'nez evitan\n',23))
        except BaseException as exc:errors.append(exc)
        finally:server.close()
    thread=threading.Thread(target=peer,daemon=True);thread.start()
    try:print(run_client(binary,mode=='valid').strip())
    finally:thread.join(12)
    assert not thread.is_alive(),'reference peer hung'
    if errors:raise errors[0]
    print('PASS independent fragmented PSK peer '+mode)
openssl_case()
openssl_case(True)
for mode in ['valid','bad-finished','truncated-finished','tamper','hrr','oversized-plaintext']:reference_case(mode)
print('PASS native-only client symbols, interoperability and malicious peer rejection')

# Reintroduce the old byte-aligned workspace only in a staged source copy.
# The odd-byte allocator must expose an actual misaligned SHA word access.
original=(STAGE/'tls13_client.zen').read_text()
old='a.raw(180000, 8)'
assert original.count(old)==1
(STAGE/'tls13_client.zen').write_text(original.replace(old,'a.raw(180000, 1)',1))
try:
    openssl_case(alignment_control=True)
finally:
    (STAGE/'tls13_client.zen').write_text(original)
