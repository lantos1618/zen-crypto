# Native TLS 1.3 development profile

The native implementation uses Zen SHA-256, HMAC/HKDF and IETF
ChaCha20-Poly1305. `src/tls13.zen` provides the key schedule and record layer;
`src/tls13_client.zen` provides a bounded external-PSK handshake and
`src/tls13_session.zen` supplies reusable blocking record I/O.
There are no OpenSSL or libsodium runtime calls in these modules. Zen still
uses its C compiler backend and standard OS socket/allocation adapters.

## Supported boundary

The client targets TLS 1.3 `TLS_CHACHA20_POLY1305_SHA256` with an external
pre-shared key. Both peers must already have the same secret and identity.
It verifies the server Finished before sending application data. The original
`psk_ke` entry point has no forward secrecy. The separate `psk_dhe_ke` entry
point mixes a fresh X25519 shared secret into the handshake key schedule; its
forward-secrecy property depends on fresh private-key entropy and effective
secret disposal. Neither mode authenticates web certificates or hostnames.
This is a development profile, not a general HTTPS client or a replacement
for zen-http's current zen-openssl backend.

`tls13_psk_connect(alloc, socket, identity, psk, psk_count, random)` returns a
`Tls13Session`. The caller owns the connected std `Socket`, timeout policy,
allocator backing storage, and PSK/random storage. The socket and allocator must
outlive the session. Supply 32 fresh bytes from an OS cryptographic random
source for every handshake; never use `std.core.rand`.

`tls13_psk_dhe_connect(alloc, socket, identity, psk, psk_count, random,
private_key)` returns the same session API while requiring X25519 and
`psk_dhe_ke`. It does not fall back to `psk_ke`. Supply a separately generated
32-byte OS-CSPRNG private key, independent of the public ClientHello random.
Reusing the ClientHello random as the private key exposes the private key on
the wire. Null private keys, the same buffer, and byte-identical distinct buffers
are rejected before allocations or I/O. This equality check does not assess
entropy quality. X25519 copies and clamps the private input internally; caller
input remains unchanged. The caller owns and must dispose of its secret copy.
Server key shares must be unique, exactly 32 bytes, and in the offered X25519
group; missing shares, unsupported groups, and all-zero shared secrets fail
before application data. See RFC 8446 sections 4.2.8, 4.2.9, and 7.4.2.

The session owns two explicitly 8-byte-aligned allocations (180000 and 32768
bytes) and borrows the socket. Keep one owner and serialize operations; do not
copy it or use it from concurrent workers. `abort()` and automatic `Drop`
release buffers exactly once; neither closes the socket nor sends an alert.
Ordinary zero stores clear the buffers before freeing, but compiler-resistant
secure erasure and side-channel behavior have not been audited. The low-level
`adopt` constructor is an internal handshake handoff: it requires those exact
exclusive live allocations, initialized directional keys at bytes 34000–34087,
and the matching allocator. Arbitrary caller buffers are outside its contract.

- `write(bytes, count)` splits data into records of at most 16384 bytes. Zero
  count is a no-op. Success returns the full count; failure can follow a sent
  prefix, poisons the session, and must not be retried on the same connection.
- `read(output, capacity)` returns at most capacity bytes from one authenticated
  record, buffering any remainder. Capacity must be positive. Zero means an
  authenticated `close_notify`; raw EOF is `Truncated`, including partial
  headers and records. Output is unchanged on failure. At most 64 empty records
  are skipped per call before refusal.
- Independent sending and receiving sequences advance without reuse. An I/O,
  authentication, protocol, or record-limit failure releases session storage
  and makes subsequent operations return `Closed`. Invalid caller buffers are
  rejected before I/O and do not poison the session.
- `close_notify()` sends the encrypted notification once and permits reads
  until the peer closes its TLS direction. It is idempotent. Receiving the
  peer notification rejects later application writes. The caller closes the
  borrowed socket after completing shutdown or handling an error.
- `write_record` emits exactly one record, including an empty record for zero
  bytes. `read_record` refuses insufficient output capacity without exposing a
  prefix. These support the legacy `tls13_psk_round_trip` helper, which still
  sends one request record and returns one response record, then releases its
  session. A record need not contain a complete application message.

Certificate validation, HelloRetryRequest, session resumption,
early data, post-handshake authentication, KeyUpdate and a native TLS server
are outside this profile. EncryptedExtensions must be empty, so ALPN is not
negotiated. Tickets and other post-handshake messages are rejected. The client
supports authenticated close_notify as described above; the caller closes the socket.
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
OPENSSL=/path/to/openssl python3 scripts/check-tls13-session.py
OPENSSL=/path/to/openssl python3 scripts/check-tls13-dhe.py
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

The reusable session extension passes macOS arm64 UBSan tests with 50000-byte
multi-record transfers, 137-byte partial reads, and 100 OpenSSL request/response
exchanges consumed 3 bytes at a time. Independent peers exercise empty records,
replay, altered tags, truncated ciphertext, oversized record headers, unsupported
post-handshake messages, and close_notify with either legacy alert level.
Adversarial allocation tracks two aligned requests and exactly two frees after
normal Drop or repeated abort. Disconnected writes must return errors without
SIGPIPE termination; the borrowed descriptor must come from std `Socket`, which
sets the platform socket protections. The session tests inspect undefined
symbols for crypto backend calls. ASan instrumentation did not reach a peer
handshake within the local timeout; macOS ASan validation is not claimed.

The reusable session extension at `942bbc4` also passes the full
`scripts/check-tls13.sh` suite on Linux x86_64 with Clang 18.1.3 and OpenSSL
3.5.4. A separate session run passes with both ASan and UBSan enabled, including
all 11 independent peer cases and 100 OpenSSL exchanges. Instrumentation was
confirmed from the resulting executable symbols.
[Exact revisions, commands, coverage and limitations](../tests/validation/tls13-session-linux-2026-09-29.txt)
record this run; these results do not extend the supported protocol profile.

The PSK-DHE runner uses an OpenSSL server configured for X25519 and TLS 1.3,
without `-allow_no_dhe_kex`. Its independent Python peer validates the actual
ClientHello vectors, PSK-last extension order, binder, X25519 shared secret,
Finished messages and application records. Negative peers cover wrong, missing,
duplicate and short shares, low-order zero/one shares, forged Finished and
altered encrypted handshake records; rejected handshakes must emit no client
Finished or application data and leave caller output unchanged. Tests also
check that private input remains unchanged and aligned allocations are released.
Python cryptography and OpenSSL are test references only. These checks do not
add PKI, HRR, ALPN, HTTP/2 negotiation or a native TLS server.

On macOS arm64, the combined `scripts/check-tls13.sh` suite passes with the
PSK-DHE addition and the authenticated inner-plaintext length check. This includes
the PSK-only session regressions, nine independent DHE peer cases, OpenSSL
required-DHE success and wrong-PSK rejection, and allocation/input validation.
Linux session evidence above predates PSK-DHE; no Linux DHE result is claimed
until the published revision is tested there.
