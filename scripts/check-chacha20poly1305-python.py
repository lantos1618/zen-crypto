#!/usr/bin/env python3
"""Independent AEAD differential and authentication-failure checks."""
import ctypes
import os
from pathlib import Path
import random
import re
import subprocess

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
SOURCE = BUILD / "chacha_native.c"
code = SOURCE.read_text()


def symbol(operation):
    pattern = rf"static bool (zu_f2_16chacha20poly130521chacha20poly1305_{operation}\w+)\("
    match = re.search(pattern, code)
    assert match, f"missing generated {operation} function"
    return match.group(1)


shim = f'''#define main generated_main
#include "{SOURCE}"
#undef main
int zen_seal(unsigned char*out,size_t outcap,unsigned char*msg,size_t msg_n,unsigned char*aad,size_t aad_n,unsigned char*key,unsigned char*nonce){{uint64_t scratch[40]={{0}};return {symbol("seal")}(out,outcap,msg,msg_n,aad,aad_n,key,nonce,scratch,40);}}
int zen_open(unsigned char*out,size_t outcap,unsigned char*cipher,size_t cipher_n,unsigned char*aad,size_t aad_n,unsigned char*key,unsigned char*nonce){{uint64_t scratch[40]={{0}};return {symbol("open")}(out,outcap,cipher,cipher_n,aad,aad_n,key,nonce,scratch,40);}}
'''
wrapper = BUILD / "chacha_python_oracle.c"
library = BUILD / "chacha_python_oracle.so"
wrapper.write_text(shim)
subprocess.run(
    [os.environ.get("CC", "clang"), "-O3", "-shared", "-fPIC", str(wrapper), "-o", str(library)],
    check=True,
)
native = ctypes.CDLL(str(library))
byte = ctypes.c_ubyte
pointer = ctypes.POINTER(byte)
for function in (native.zen_seal, native.zen_open):
    function.argtypes = [pointer, ctypes.c_size_t, pointer, ctypes.c_size_t,
                         pointer, ctypes.c_size_t, pointer, pointer]
    function.restype = ctypes.c_int


def buffer(value):
    return (byte * max(1, len(value)))(*value)


rng = random.Random(8439)
cases = 0
for seed in range(8):
    key = rng.randbytes(32)
    nonce = rng.randbytes(12)
    key_buffer, nonce_buffer = buffer(key), buffer(nonce)
    for message_count in (0, 1, 2, 15, 16, 17, 31, 32, 63, 64, 65, 127, 128, 16384, 16385):
        message = rng.randbytes(message_count)
        message_buffer = buffer(message)
        for aad_count in (0, 1, 2, 15, 16, 17, 31, 32, 65):
            aad = rng.randbytes(aad_count)
            aad_buffer = buffer(aad)
            expected = ChaCha20Poly1305(key).encrypt(nonce, message, aad)
            sealed = (byte * (message_count + 16))()
            assert native.zen_seal(sealed, len(sealed), message_buffer, message_count,
                                   aad_buffer, aad_count, key_buffer, nonce_buffer) == 1
            assert bytes(sealed) == expected, (seed, message_count, aad_count)
            plain = (byte * max(1, message_count))()
            assert native.zen_open(plain, message_count, sealed, len(sealed),
                                   aad_buffer, aad_count, key_buffer, nonce_buffer) == 1
            assert bytes(plain)[:message_count] == message
            sealed[message_count + seed % 16] ^= 1
            unchanged = (byte * max(1, message_count))(*([0xA5] * max(1, message_count)))
            assert native.zen_open(unchanged, message_count, sealed, len(sealed),
                                   aad_buffer, aad_count, key_buffer, nonce_buffer) == 0
            assert bytes(unchanged) == bytes([0xA5]) * max(1, message_count)
            cases += 1

print(f"Python cryptography independent AEAD oracle: {cases} seal/open/tamper cases passed")
