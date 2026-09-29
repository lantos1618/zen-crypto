#!/usr/bin/env python3
"""External PSK+X25519 TLS1.3 peers. cryptography/OpenSSL are test-only."""
import hashlib,hmac,os,re,shutil,socket,subprocess,threading,time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
ROOT=Path(__file__).resolve().parents[1]
ZEN=Path(os.getenv('ZEN_COMPILER',ROOT.parent/'zen-crypto-numeric/zen')).resolve()
STD=Path(os.getenv('ZEN_STD',ROOT.parent/'zen-crypto-numeric/src')).resolve()
OPENSSL=Path(os.getenv('OPENSSL',ROOT.parent/'zen-http/build/openssl/bin/openssl')).resolve()
WORK=ROOT/'build/tls13-dhe';STAGE=WORK/'stage';STAGE.mkdir(parents=True,exist_ok=True)
PSK=bytes(range(32))
for source in (ROOT/'src').glob('*.zen'):shutil.copy(source,STAGE/source.name)
def build(port,success):
    source=(ROOT/'tests/tls13_dhe_test.zen').read_text().replace('TEST_PORT',str(port)).replace('EXPECT_SUCCESS','true' if success else 'false')
    source=source.replace('// RANDOM','\n'.join(f'{name}.write({i}, {b});' for name in ('random','private') for i,b in enumerate(os.urandom(32))))
    (STAGE/'main.zen').write_text(source)
    with (WORK/'compile.log').open('w') as log:
        subprocess.run([str(ZEN),'build',str(STAGE),'--std',str(STD),'--emit-c','-o',str(WORK/'client.c')],check=True,stdout=log,stderr=log)
        subprocess.run([os.getenv('CC','clang'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(WORK/'client.c'),'-o',str(WORK/'client')],check=True,stdout=log,stderr=log)
    for line in subprocess.check_output(['nm','-u',str(WORK/'client')],text=True).splitlines():
        fields=line.split()
        if fields:assert not re.match(r'(sodium_|crypto_|SSL_|OPENSSL_|EVP_|randombytes)',fields[-1].lstrip('_'))
    return WORK/'client'
def run(binary):
    r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=30)
    assert r.returncode==0,(r.returncode,r.stdout,r.stderr)
    assert 'DHE result: true unchanged buffers: true allocation: true' in r.stdout,r.stdout

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
def extension(kind,body):return kind.to_bytes(2,'big')+len(body).to_bytes(2,'big')+body
def client_share(ch):
    # Parse the actual ClientHello vectors rather than relying on fixed offsets.
    assert ch[0]==1 and int.from_bytes(ch[1:4],'big')==len(ch)-4
    at=4+2+32;at+=1+ch[at]
    n=int.from_bytes(ch[at:at+2],'big');at+=2+n
    at+=1+ch[at];n=int.from_bytes(ch[at:at+2],'big');at+=2
    assert at+n==len(ch)
    exts={};order=[]
    while at<len(ch):
        kind=int.from_bytes(ch[at:at+2],'big');n=int.from_bytes(ch[at+2:at+4],'big');at+=4
        assert kind not in exts and at+n<=len(ch)
        exts[kind]=ch[at:at+n];order.append(kind);at+=n
    assert order[-1]==41 and exts[45]==b'\1\1','must offer only psk_dhe_ke and keep PSK last'
    assert exts[10]==b'\0\2\0\x1d'
    share=exts[51];assert share[:6]==b'\0\x24\0\x1d\0\x20' and len(share)==38
    return share[6:]
def reference(mode):
    server=listener();binary=build(server.getsockname()[1],mode=='valid');errors=[]
    def peer():
        try:
            with server.accept()[0] as conn:
                conn.settimeout(12);_,ch=receive_record(conn);public=client_share(ch)
                early=extract(bytes(32),PSK)
                assert hmac.compare_digest(ch[-32:],finished(label(early,'ext binder',hashlib.sha256(b'').digest()),ch[:-35])),'binder mismatch'
                private=X25519PrivateKey.generate();server_public=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
                group=23 if mode=='wrong-group' else 29
                if mode=='low-order-zero':server_public=bytes(32)
                if mode=='low-order-one':server_public=b'\1'+bytes(31)
                share=group.to_bytes(2,'big')+len(server_public).to_bytes(2,'big')+server_public
                if mode=='short-share':share=share[:-1]
                exts=extension(43,b'\3\4')+extension(41,b'\0\0')
                if mode!='missing-share':exts+=extension(51,share)
                if mode=='duplicate-share':exts+=extension(51,share)
                sh=hs(2,b'\3\3'+os.urandom(32)+b'\0\x13\3\0'+len(exts).to_bytes(2,'big')+exts)
                conn.sendall(plain(22,sh[:3])+plain(22,sh[3:]))
                malformed=mode in ('wrong-group','missing-share','duplicate-share','short-share','low-order-zero','low-order-one')
                if not malformed:
                    shared=private.exchange(X25519PublicKey.from_public_bytes(public))
                    secret=extract(label(early,'derived',hashlib.sha256(b'').digest()),shared)
                    transcript=ch+sh;digest=hashlib.sha256(transcript).digest()
                    client=label(secret,'c hs traffic',digest);server_secret=label(secret,'s hs traffic',digest)
                    ee=hs(8,b'\0\0');verify=finished(server_secret,transcript+ee)
                    if mode=='forged-finished':verify=bytes([verify[0]^1])+verify[1:]
                    sf=hs(20,verify)
                    for seq,fragment in enumerate([ee[:3],ee[3:]+sf[:9],sf[9:]]):
                        wire=encrypted(server_secret,seq,fragment)
                        if mode=='tampered-record' and seq==2:wire=wire[:-1]+bytes([wire[-1]^1])
                        conn.sendall(wire)
                    if mode=='valid':
                        transcript+=ee+sf
                        assert decrypt(client,0,receive_record(conn))==hs(20,finished(client,transcript))+b'\x16'
                        master=extract(label(secret,'derived',hashlib.sha256(b'').digest()),bytes(32));digest=hashlib.sha256(transcript).digest()
                        clientapp=label(master,'c ap traffic',digest);serverapp=label(master,'s ap traffic',digest)
                        assert decrypt(clientapp,0,receive_record(conn))==b'native zen\n\x17'
                        conn.sendall(encrypted(serverapp,0,b'nez evitan\n',23));return
                try:extra=conn.recv(1)
                except ConnectionResetError:extra=b''
                assert not extra,'client sent Finished/application data after rejected server input'
        except BaseException as e:errors.append(e)
        finally:server.close()
    thread=threading.Thread(target=peer,daemon=True);thread.start()
    try:run(binary)
    finally:thread.join(15)
    assert not thread.is_alive(),'reference peer hung'
    if errors:raise errors[0]
    print('PASS independent PSK-DHE '+mode,flush=True)
def openssl(wrong=False):
    s=listener();port=s.getsockname()[1];s.close();binary=build(port,not wrong)
    with (WORK/('openssl-wrong.log' if wrong else 'openssl.log')).open('w') as log:
        # Deliberately no -allow_no_dhe_kex: this peer requires DHE.
        peer=subprocess.Popen([str(OPENSSL),'s_server','-accept',f'127.0.0.1:{port}','-nocert','-psk',('ff'*32 if wrong else PSK.hex()),'-psk_identity','ZenTest','-groups','X25519','-ciphersuites','TLS_CHACHA20_POLY1305_SHA256','-tls1_3','-num_tickets','0','-rev','-quiet'],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
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
    print('PASS OpenSSL required-DHE '+('wrong PSK rejected' if wrong else 'authenticated exchange'),flush=True)
for mode in ('valid','wrong-group','missing-share','duplicate-share','short-share','low-order-zero','low-order-one','forged-finished','tampered-record'):reference(mode)
openssl();openssl(True)
print('PASS native-only symbols, UBSan, fresh private input unchanged and aligned allocation cleanup')
