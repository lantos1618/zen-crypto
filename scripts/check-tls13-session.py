#!/usr/bin/env python3
"""Native session interoperability and hostile record peers. Crypto is test-only."""
import hashlib,hmac,os,re,shutil,socket,subprocess,threading,time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
ROOT=Path(__file__).resolve().parents[1]
ZEN=Path(os.getenv('ZEN_COMPILER',ROOT.parent/'zen-crypto-numeric/zen')).resolve()
STD=Path(os.getenv('ZEN_STD',ROOT.parent/'zen-crypto-numeric/src')).resolve()
OPENSSL=Path(os.getenv('OPENSSL',ROOT.parent/'zen-http/build/openssl/bin/openssl')).resolve()
WORK=ROOT/'build/tls13-session';STAGE=WORK/'stage';STAGE.mkdir(parents=True,exist_ok=True)
PSK=bytes(range(32));DATA=bytes(i%251+1 for i in range(50000))
for source in (ROOT/'src').glob('*.zen'):shutil.copy(source,STAGE/source.name)
def build(port,mode):
    source=(ROOT/'tests/tls13_session_test.zen').read_text().replace('TEST_PORT',str(port)).replace('MODE',str(mode))
    if mode in (9,10,11):
        start=source.index('    session ::=');end=source.index('main = (env:',start)
        capacity=0 if mode==11 else 137
        request=1 if mode==10 else 0
        source=source[:start]+f'''    Range(0, 137).loop((i) {{ output.write(i, 165); }});
    good = tls13_psk_round_trip(a, socket, "ZenTest", psk, 32, random, data, {request}, output, {capacity}).match({{
        Ok(n) => n == 0 && {mode} != 10, Err(_) => {mode} == 10,
    }});
    Range(0, 137).loop((i) {{ (output.read(i) == 165).ensure(Tls13ClientError.Protocol).try(); }});
    Ok(good)
}}
'''+source[end:]
    if mode==8:
        start=source.index('    // DISCONNECT_TEST');end=source.index('    Ok(true)',start)
        source=source[:start]+'''    (Shutdown.shutdown(socket.raw_handle(), 2) == 0).ensure(Tls13ClientError.Io).try();
    rejected = session.write(data, 50000).match({Ok(_) => false, Err(e) => e.match({Io => true, _ => false})});
    rejected.ensure(Tls13ClientError.Protocol).try();
    closed = session.write(data, 1).match({Ok(_) => false, Err(e) => e.match({Closed => true, _ => false})});
    closed.ensure(Tls13ClientError.Protocol).try();
    session.abort(); session.abort();
'''+source[end:]
    source=source.replace('// RANDOM' ,'\n'.join(f'random.write({i}, {b});' for i,b in enumerate(os.urandom(32))))
    (STAGE/'main.zen').write_text(source)
    with (WORK/'compile.log').open('w') as log:
        subprocess.run([str(ZEN),'build',str(STAGE),'--std',str(STD),'--emit-c','-o',str(WORK/'client.c')],check=True,stdout=log,stderr=log)
        subprocess.run([os.getenv('CC','clang'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(WORK/'client.c'),'-o',str(WORK/'client')],check=True,stdout=log,stderr=log)
    symbols=subprocess.check_output(['nm','-u',str(WORK/'client')],text=True)
    for line in symbols.splitlines():
        fields=line.split()
        if fields:assert not re.match(r'(sodium_|crypto_|SSL_|OPENSSL_|EVP_|randombytes)',fields[-1].lstrip('_'))
    return WORK/'client'
def run(binary):
    r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
    assert r.returncode==0,(r.returncode,r.stdout,r.stderr)
    assert 'session behavior: true alignment and release: true' in r.stdout,r.stdout

def listener():
    s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('127.0.0.1',0));s.listen(1);s.settimeout(20);return s

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
def handshake(conn):
    _,ch=receive_record(conn);early=extract(bytes(32),PSK)
    binder=finished(label(early,'ext binder',hashlib.sha256(b'').digest()),ch[:-35])
    assert hmac.compare_digest(ch[-32:],binder)
    sh=hs(2,b'\x03\x03'+os.urandom(32)+b'\0\x13\x03\0'+b'\0\x0c'+b'\0\x2b\0\2\3\4'+b'\0\x29\0\2\0\0')
    conn.sendall(plain(22,sh))
    secret=extract(label(early,'derived',hashlib.sha256(b'').digest()),bytes(32));transcript=ch+sh
    client=label(secret,'c hs traffic',hashlib.sha256(transcript).digest());server=label(secret,'s hs traffic',hashlib.sha256(transcript).digest())
    ee=hs(8,b'\0\0');sf=hs(20,finished(server,transcript+ee));conn.sendall(encrypted(server,0,ee+sf));transcript+=ee+sf
    assert decrypt(client,0,receive_record(conn))==hs(20,finished(client,transcript))+b'\x16'
    master=extract(label(secret,'derived',hashlib.sha256(b'').digest()),bytes(32));digest=hashlib.sha256(transcript).digest()
    return label(master,'c ap traffic',digest),label(master,'s ap traffic',digest)
def reference(mode):
    server=listener();binary=build(server.getsockname()[1],mode);errors=[]
    def peer():
        try:
            with server.accept()[0] as conn:
                conn.settimeout(15);client,secret=handshake(conn)
                if mode in (9,10,11):
                    part=decrypt(client,0,receive_record(conn))
                    assert part==(DATA[:1]+b'\x17' if mode==10 else b'\x17')
                    conn.sendall(encrypted(secret,0,b'x'*200 if mode==10 else b'',23))
                    return
                if mode==8:
                    assert not conn.recv(1),'write after shutdown produced data'
                    return
                received=b'';seq=0
                while len(received)<len(DATA):
                    part=decrypt(client,seq,receive_record(conn));assert part[-1]==23
                    assert len(part)<=16385
                    received+=part[:-1];seq+=1
                assert received==DATA and seq==4,'multi-record client send differs'
                if mode==0:
                    fragments=[b'',DATA[:13],DATA[13:16397],DATA[16397:16474],DATA[16474:32858],DATA[32858:49242],DATA[49242:]]
                    for number,part in enumerate(fragments):
                        wire=encrypted(secret,number,part,23)
                        for at in range(0,len(wire),101):conn.sendall(wire[at:at+101])
                    assert decrypt(client,seq,receive_record(conn))==b'\1\0\x15'
                    # TLS1.3 ignores legacy alert level; exercise a non-warning value.
                    conn.sendall(encrypted(secret,len(fragments),b'\2\0',21))
                elif mode==1:
                    wire=encrypted(secret,0,b'unauthenticated',23);conn.sendall(wire[:-1]+bytes([wire[-1]^1]))
                elif mode==2:
                    conn.sendall(encrypted(secret,0,b'truncated',23)[:-3]);conn.shutdown(socket.SHUT_WR)
                elif mode==3:
                    wire=encrypted(secret,0,DATA[:100],23);conn.sendall(wire+wire)
                elif mode==4:conn.sendall(encrypted(secret,0,b'unsupported handshake',22))
                elif mode==5:conn.sendall(b'\x17\x03\x03\xff\xff')
                elif mode==6:
                    conn.sendall(b''.join(encrypted(secret,i,b'',23) for i in range(65)))
        except BaseException as e:errors.append(e);print('peer failure',repr(e),flush=True)
        finally:server.close()
    thread=threading.Thread(target=peer,daemon=True);thread.start()
    try:run(binary)
    finally:thread.join(20)
    assert not thread.is_alive(),'peer hung'
    if errors:raise errors[0]
    print('PASS session reference '+str(mode),flush=True)
def openssl():
    s=listener();port=s.getsockname()[1];s.close();binary=build(port,7)
    with (WORK/'openssl.log').open('w') as log:
        peer=subprocess.Popen([str(OPENSSL),'s_server','-accept',f'127.0.0.1:{port}','-nocert','-psk',PSK.hex(),'-psk_identity','ZenTest','-ciphersuites','TLS_CHACHA20_POLY1305_SHA256','-tls1_3','-allow_no_dhe_kex','-num_tickets','0','-rev','-quiet'],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            for _ in range(100):
                if peer.poll() is not None:raise RuntimeError('OpenSSL exited')
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.1):break
                except OSError:time.sleep(.02)
            run(binary)
        finally:
            peer.terminate()
            try:peer.wait(timeout=3)
            except subprocess.TimeoutExpired:peer.kill();peer.wait()
    print('PASS OpenSSL 100 exchanges, partial reads and close_notify',flush=True)
for mode in [0,1,2,3,4,5,6,8,9,10,11]:reference(mode)
openssl()
print('PASS native-only symbols, UBSan, aligned allocation and exactly-once release')
