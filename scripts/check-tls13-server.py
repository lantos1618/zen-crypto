#!/usr/bin/env python3
"""Native TLS server-role peers. TCP relay only; crypto references are test-only."""
import hashlib,hmac,os,re,shutil,socket,subprocess,threading,time
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat
ROOT=Path(__file__).resolve().parents[1]
ZEN=Path(os.getenv('ZEN_COMPILER',ROOT.parent/'zen-crypto-numeric/zen')).resolve()
STD=Path(os.getenv('ZEN_STD',ROOT.parent/'zen-crypto-numeric/src')).resolve()
OPENSSL=Path(os.getenv('OPENSSL',ROOT.parent/'zen-http/build/openssl/bin/openssl')).resolve()
WORK=ROOT/'build/tls13-server';STAGE=WORK/'stage';STAGE.mkdir(parents=True,exist_ok=True)
PSK=bytes(range(32))
for source in (ROOT/'src').glob('*.zen'):shutil.copy(source,STAGE/source.name)
def build(port,success,role="server"):
    source=(ROOT/'tests/tls13_server_test.zen').read_text().replace('TEST_PORT',str(port)).replace('EXPECT_SUCCESS','true' if success else 'false')
    if role=="client":
        source=source.replace('tls13_psk_dhe_accept = tls13_server','tls13_psk_dhe_connect = tls13_client').replace('tls13_psk_dhe_accept(', 'tls13_psk_dhe_connect(')
        start=source.index('            received ::=');end=source.index('            session.abort(); valid',start)
        source=source[:start]+'''            request: str = "native zen\\n";
            valid ::= session.write(request.ptr(), request.len).match({Ok(n) => n == request.len, Err(_) => false});
            received ::= 0;
            loop(() { received < 50000 && valid }, (h) {
                session.read(output, 127).match({
                    Ok(n) => {
                        valid = n > 0 && n <= 50000 - received;
                        Range(0, n).loop((i) { valid = valid && output.read(i) == payload.read(received + i); });
                        received = received + n;
                    },
                    Err(_) => { valid = false; },
                });
            });
            valid = session.read(output, 127).match({Ok(n) => n == 0 && valid, Err(_) => false});
'''+source[end:]
    source=source.replace('// RANDOM','\n'.join(f'{name}.write({i}, {b});' for name in ('random','private') for i,b in enumerate(os.urandom(32))))
    (STAGE/'main.zen').write_text(source)
    with (WORK/'compile.log').open('w') as log:
        subprocess.run([str(ZEN),'build',str(STAGE),'--std',str(STD),'--emit-c','-o',str(WORK/'client.c')],check=True,stdout=log,stderr=log)
        subprocess.run([os.getenv('CC','clang'),'-O2','-fsanitize=undefined','-fno-sanitize-recover=all',str(WORK/'client.c'),'-o',str(WORK/role)],check=True,stdout=log,stderr=log)
    for line in subprocess.check_output(['nm','-u',str(WORK/role)],text=True).splitlines():
        fields=line.split()
        if fields:assert not re.match(r'(sodium_|crypto_|SSL_|OPENSSL_|EVP_|randombytes)',fields[-1].lstrip('_'))
    return WORK/role
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
DATA=bytes(i%251+1 for i in range(50000))
def check_process(proc):
    stdout,stderr=proc.communicate(timeout=30)
    assert proc.returncode==0,(proc.returncode,stdout,stderr)
    assert 'native server: true unchanged: true allocation: true' in stdout,stdout

def hello(private,mode):
    public=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
    if mode=='low-order':public=bytes(32)
    if mode=='low-order-one':public=b'\1'+bytes(31)
    if mode=='short-share':public=public[:-1]
    groups=b'\0\4\0\x1d\0\x17' if mode=='share-order' else b'\0\2\0\x1d'
    if mode=='group-limit':groups=(130).to_bytes(2,'big')+b'\0\x1d'+b''.join(i.to_bytes(2,'big') for i in range(100,164))
    exts=extension(43,b'\2\3\4')+extension(45,b'\1\0' if mode=='psk-only' else b'\1\1')+extension(10,groups)
    share=b'\0\x1d'+len(public).to_bytes(2,'big')+public
    if mode=='share-order':share=b'\0\x17\0\x20'+bytes(32)+share
    exts+=extension(51,len(share).to_bytes(2,'big')+share)
    if mode=='cookie':exts+=extension(44,b'\0\1x')
    if mode=='duplicate-ignored':exts+=extension(65000,b'')+extension(65000,b'')
    if mode=='extension-limit':exts+=b''.join(extension(i,b'') for i in range(1000,1126))
    if mode=='duplicate':exts+=extension(43,b'\2\3\4')
    if mode=='early-data':exts+=extension(42,b'')
    identity=b'WrongIdentity' if mode=='wrong-identity' else b'ZenTest';identities=len(identity).to_bytes(2,'big')+identity+bytes(4)
    pskext=len(identities).to_bytes(2,'big')+identities+b'\0\x21\x20'+bytes(32)
    exts+=extension(41,pskext)
    if mode=='psk-not-last':exts+=extension(65000,b'')
    sid=os.urandom(32)
    body=b'\3\3'+os.urandom(32)+bytes([len(sid)])+sid+b'\0\2\x13\3\1\0'+len(exts).to_bytes(2,'big')+exts
    ch=hs(1,body);tail=4 if mode=='psk-not-last' else 0;truncated=ch[:-35-tail] if tail else ch[:-35];early=extract(bytes(32),b'wrong secret' if mode=='wrong-psk' else PSK)
    binder=finished(label(early,'ext binder',hashlib.sha256(b'').digest()),truncated)
    if mode=='bad-binder':binder=bytes([binder[0]^1])+binder[1:]
    return (ch[:-32-tail]+binder+ch[-tail:] if tail else ch[:-32]+binder),early,sid

def independent(mode):
    listen=listener();binary=build(listen.getsockname()[1],mode=='valid')
    proc=subprocess.Popen([str(binary)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        with listen.accept()[0] as conn:
            conn.settimeout(15);private=X25519PrivateKey.generate();ch,early,sid=hello(private,mode)
            if mode=='oversized-record':conn.sendall(b'\x16\x03\x03\x40\x01')
            elif mode=='truncated-hello':conn.sendall(plain(22,ch)[:-8]);conn.shutdown(socket.SHUT_WR)
            else:conn.sendall(plain(22,ch[:7])+plain(22,ch[7:]))
            if mode in ('wrong-psk','bad-binder','duplicate','low-order','low-order-one','short-share','early-data','truncated-hello','psk-only','wrong-identity','psk-not-last','cookie','share-order','duplicate-ignored','group-limit','extension-limit','oversized-record'):
                try:wire=conn.recv(1)
                except ConnectionResetError:wire=b''
                assert not wire,'server emitted flight for refused ClientHello'
            else:
                header,sh=receive_record(conn);assert header[0]==22 and sh[0]==2
                assert int.from_bytes(sh[1:4],'big')==len(sh)-4 and sh[4:6]==b'\3\3'
                n=sh[38];assert sh[39:39+n]==sid
                at=39+n;assert sh[at:at+3]==b'\x13\3\0';at+=3
                length=int.from_bytes(sh[at:at+2],'big');at+=2;assert at+length==len(sh)
                exts={}
                while at<len(sh):
                    kind=int.from_bytes(sh[at:at+2],'big');n=int.from_bytes(sh[at+2:at+4],'big');at+=4
                    assert kind not in exts;exts[kind]=sh[at:at+n];at+=n
                assert exts[43]==b'\3\4' and exts[41]==b'\0\0'
                assert exts[51][:4]==b'\0\x1d\0\x20' and len(exts[51])==36
                shared=private.exchange(X25519PublicKey.from_public_bytes(exts[51][4:]));transcript=ch+sh
                secret=extract(label(early,'derived',hashlib.sha256(b'').digest()),shared);digest=hashlib.sha256(transcript).digest()
                client=label(secret,'c hs traffic',digest);server=label(secret,'s hs traffic',digest)
                flight=b'';seq=0
                while len(flight)<42:
                    record=receive_record(conn)
                    if record[0][0]==20:continue
                    part=decrypt(server,seq,record);assert part[-1]==22;seq+=1;flight+=part[:-1]
                assert flight[:6]==hs(8,b'\0\0') and len(flight)==42
                assert hmac.compare_digest(flight[10:],finished(server,transcript+flight[:6])),'server Finished differs'
                transcript+=flight;verify=finished(client,transcript)
                if mode=='wrong-finished':verify=bytes([verify[0]^1])+verify[1:]
                cf=hs(20,verify)
                if mode=='replay':
                    replayed=encrypted(client,0,cf[:8]);conn.sendall(replayed+replayed)
                elif mode=='early-application':conn.sendall(encrypted(client,0,b'not Finished',23))
                elif mode=='truncated-finished':
                    conn.sendall(encrypted(client,0,cf)[:-7]);conn.shutdown(socket.SHUT_WR)
                else:conn.sendall(encrypted(client,0,cf[:8])+encrypted(client,1,cf[8:]))
                if mode!='valid':
                    try:wire=conn.recv(1)
                    except ConnectionResetError:wire=b''
                    assert not wire,'server emitted application data before authenticating client Finished'
                else:
                    master=extract(label(secret,'derived',hashlib.sha256(b'').digest()),bytes(32));digest=hashlib.sha256(transcript).digest()
                    c_app=label(master,'c ap traffic',digest);s_app=label(master,'s ap traffic',digest)
                    conn.sendall(encrypted(c_app,0,b'native ',23)+encrypted(c_app,1,b'zen\n',23))
                    data=b'';seq=0
                    while len(data)<len(DATA):
                        part=decrypt(s_app,seq,receive_record(conn));seq+=1;assert part[-1]==23;data+=part[:-1]
                    assert data==DATA and seq==4
                    assert decrypt(s_app,seq,receive_record(conn))==b'\1\0\x15'
        check_process(proc)
    finally:
        listen.close()
        if proc.poll() is None:proc.kill();proc.wait()
    print('PASS native server independent '+mode,flush=True)

def relay_pair(left,right):
    import select
    sockets=[left,right]
    try:
        while sockets:
            ready,_,_=select.select(sockets,[],[],20)
            if not ready:raise TimeoutError('relay stalled')
            for source in ready:
                target=right if source is left else left
                data=source.recv(65536)
                if data:target.sendall(data)
                else:
                    sockets.remove(source)
                    try:target.shutdown(socket.SHUT_WR)
                    except OSError:pass
    except (ConnectionResetError,BrokenPipeError):pass
    finally:left.close();right.close()

def openssl():
    back=listener();front=listener();binary=build(back.getsockname()[1],True)
    server=subprocess.Popen([str(binary)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    client=None;thread=None
    try:
        native=back.accept()[0]
        client=subprocess.Popen([str(OPENSSL),'s_client','-connect',f'127.0.0.1:{front.getsockname()[1]}','-psk',PSK.hex(),'-psk_identity','ZenTest','-groups','X25519','-ciphersuites','TLS_CHACHA20_POLY1305_SHA256','-tls1_3','-quiet','-ign_eof'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        peer=front.accept()[0];thread=threading.Thread(target=relay_pair,args=(native,peer),daemon=True);thread.start()
        out,err=client.communicate(b'native zen\n',timeout=30)
        assert client.returncode==0 and out==DATA,(client.returncode,len(out),err)
        check_process(server);thread.join(3);assert not thread.is_alive()
    finally:
        back.close();front.close()
        for p in (server,client):
            if p and p.poll() is None:p.kill();p.wait()
    print('PASS OpenSSL s_client to native server: X25519, 50000 bytes, close_notify',flush=True)

def native_pair():
    back=listener();front=listener()
    serverbin=build(back.getsockname()[1],True,"server")
    clientbin=build(front.getsockname()[1],True,"client")
    server=subprocess.Popen([str(serverbin)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    client=None
    try:
        left=back.accept()[0]
        client=subprocess.Popen([str(clientbin)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        right=front.accept()[0]
        thread=threading.Thread(target=relay_pair,args=(left,right),daemon=True);thread.start()
        check_process(client);check_process(server);thread.join(3);assert not thread.is_alive()
    finally:
        back.close();front.close()
        for p in (server,client):
            if p and p.poll() is None:p.kill();p.wait()
    print('PASS native client to native server: 50000 bytes, partial reads, close_notify',flush=True)

for mode in ('valid','wrong-psk','bad-binder','duplicate','low-order','low-order-one','short-share','early-data','truncated-hello','psk-only','wrong-identity','psk-not-last','cookie','share-order','duplicate-ignored','group-limit','extension-limit','oversized-record','early-application','wrong-finished','replay','truncated-finished'):independent(mode)
openssl();native_pair()
print('PASS server native-only symbols, UBSan, aligned cleanup and private input preservation')
