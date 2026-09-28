# Native TLS 1.3 development profile

The native implementation uses Zen SHA-256, HMAC/HKDF and IETF
ChaCha20-Poly1305. `src/tls13.zen` provides the key schedule and record layer;
`src/tls13_client.zen` provides a bounded external-PSK client exchange.
There are no OpenSSL or libsodium runtime calls in these modules. Zen still
uses its C compiler backend and standard OS socket/allocation adapters.

## Supported boundary

The client targets TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` with an external
pre-shared key and the `psk_ke` mode. Both peers must already have the same
secret and identity. It verifies the server Finished before sending application
data. This mode has no forward secrecy and does not authenticate web
certificates or hostnames. It is a development profile, not a general HTTPS
client or a replacement for zen-http's current zen-openssl backend.

The first client API sends one application record and returns the first
authenticated application response record; that record need not contain a
complete application message. It uses a borrowed connected socket. The caller owns the socket, timeout policy,
allocation and secret storage, and supplies 32 fresh bytes from an OS
cryptographic random source. Never use `std.core.rand`. Close the socket after
any exchange result; this API does not return a reusable TLS session.

Certificate validation, X25519, HelloRetryRequest, session resumption,
early data, post-handshake authentication, KeyUpdate and a native TLS server
are outside this profile. EncryptedExtensions must be empty, so ALPN is not
negotiated. Tickets and other post-handshake messages are rejected. The client
does not implement TLS close_notify shutdown; the caller closes the socket.
No HTTP/2 or HTTP/1 performance claim follows from
this TLS work. Independent security review, constant-time analysis and secure
secret lifecycle management remain unfinished.

## Primitive and record APIs

SHA-256 uses 72 aligned u32 scratch words and a 64-byte block. HMAC requires
192 scratch bytes plus 72 words; HKDF expansion requires 256 bytes plus 72
words. HKDF output is at most 8160 bytes. Read the module-level contracts for
aliasing and lifetime requirements.

ChaCha20-Poly1305 uses a 32-byte key, 12-byte nonce, full 16-byte tag and 40
aligned u64 scratch words. Never reuse a nonce with a key. Exact in-place
operation is supported; partial overlap and overlap with key/nonce/AAD are
outside the contract. Authentication failure does not write plaintext.

TLS helpers require 4096 aligned u64 scratch words, disjoint from the other
buffers. Record seal/open take an explicit traffic key, IV and sequence number.
The caller maintains independent read/write sequences and advances only after
success. Sequence exhaustion is rejected; sequence MAX is reserved. Opening a
record stages decrypted bytes until authentication and inner-type validation
succeed, leaving output unchanged on errors. The record layer alone does not
supply handshake state or session ownership.

## Reproducible checks

Build matching compiler and std from [Zen PR #8](https://github.com/lantos1618/zen/pull/8),
commit `64942424` (`native-tls-bits`).
The generic u32/u64 operations and borrowed endian cursors are upstream std
work; TLS-specific state remains here.

```sh
export ZEN_COMPILER=/path/to/zen/zen
export ZEN_STD=/path/to/zen/src
scripts/check.sh

# Optional libsodium oracle; only the test executable links it.
scripts/check-chacha20poly1305.sh

# Python cryptography is a test-only dependency for independent AEAD records.
python3 tests/check_tls13.py --zen "$ZEN_COMPILER" --std "$ZEN_STD"
# OpenSSL 3 reference peer; the native client links no crypto backend.
OPENSSL=/path/to/openssl python3 scripts/check-tls13-interop.py
```

Known-answer and independent tests include RFC 4231 HMAC, RFC 5869 HKDF,
RFC 8439 AEAD, RFC 8448 derive-secret, message/block boundaries, incremental
hashing, maximum HKDF output, altered ciphertext/tags/AAD, TLS padding, record
limits and wrong sequence numbers. Deliberately broken algorithm/domain-label
controls must fail. Tests inspect unresolved symbols for external crypto calls.
Passing vectors and interoperability demonstrate tested agreement, not a
security audit, complete protocol conformance or a speed ranking.

References: [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446),
[RFC 8439](https://www.rfc-editor.org/rfc/rfc8439),
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869).

## Observed interoperability

On macOS arm64, the UBSan native client completed an authenticated request and
response with OpenSSL 3.5.4 using `-tls1_3 -nocert -allow_no_dhe_kex`, suite
`TLS_CHACHA20_POLY1305_SHA256`, and tickets disabled. A wrong PSK was rejected.
An independent Python reference peer verified the client binder and Finished,
fragmented ServerHello/EncryptedExtensions/Finished across records and TCP
writes, and exchanged application data. Correctly encrypted but forged Finished,
truncated Finished and ciphertext tampering were rejected without modifying the
response buffer or sending application data before server authentication.
The native executable's undefined symbols contained no external crypto calls.

The client explicitly requests 8-byte alignment for both internal workspaces
through `Alloc.raw`. The interoperability runner supplies an adversarial allocator
that verifies those requests. A staged change requesting byte alignment triggers
UBSan on a misaligned SHA word access before any handshake is sent. This guards
the allocation contract instead of relying on the default arena's stronger
alignment or generic `realloc` type information surviving trait dispatch.

The final implementation at `9aae3f1` also passes these TLS vector,
interoperability and alignment checks on Linux x86_64 with Clang 18.1.3.
The native primitive suite and 1,080-case optional libsodium comparison pass
there as well. [Exact revisions, commands and results](../tests/validation/tls13-linux-2026-09-28.txt)
record the run. The std prerequisites are in PR #8; focused Linux tests and its
warning gate pass, but this evidence does not claim the full compiler aggregate
passed. The full macOS corpus had 1,347 passes, 15 failures and one deferred case;
matched baseline investigations reproduced the examined failures.
