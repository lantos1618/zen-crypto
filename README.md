# zen-crypto

Zen cryptography interfaces with a vetted libsodium backend, alongside
experimental pure Zen BLAKE2b hashing and byte-comparison candidates. Production encryption uses
libsodium; the candidate is not used for security decisions. No handwritten C
wrappers or compiler changes are needed for the libsodium API.

## TLS package boundary

`src/tls.zen` now contains the TLS client/transport implementation extracted from
the current Zen standard library. It exports `TlsConnection`, `TlsFault`,
`Transport`, and the transport operations used by the sibling `zen-http` package.
The client verifies certificate chains and hostnames. Private OpenSSL builds
need a configured CA bundle (`SSL_CERT_FILE`/`SSL_CERT_DIR`); they do not load the
macOS Keychain automatically. Existing `std.net.tls` callers are not migrated.

`src/zen_tls.h` supplies the shared OpenSSL headers and borrowed ABI accessors
and the small native adapter used by the experimental HTTP server:
session construction/cleanup and const-qualified ABI details. TLS policy,
client-context construction, context lifetime, ALPN selection/validation and
nonblocking retry decisions live in Zen. It never creates or closes an OS socket. Callers own sockets
and keep retry buffers stable across WANT_READ/WANT_WRITE. This adapter contains
no handwritten cipher, hash, key exchange, or other cryptographic primitive.
Graceful TLS shutdown, configurable TLS policies and client-context reuse are
follow-up work; this is not a production-completeness claim.

`sh scripts/build-openssl.sh` builds pinned OpenSSL 3.5.4 locally. An optional
absolute destination lets a consuming package keep its dependency cache under
its own ignored build directory. The HTTP/TLS integration tests live in
`../zen-http/tests/check.py`; the libsodium checks below remain independent.

## Native backend

`src/sodium.zen` binds `sodium.h` directly. Import `Sodium, initialize = sodium`.
It exposes XChaCha20-Poly1305 AEAD, `crypto_kx` directional X25519 session keys,
keyed BLAKE2b, HMAC-SHA512/256 authentication, OS-backed random bytes,
constant-time comparison and explicit zeroization. `initialize()` must succeed
before use. All buffers are borrowed synchronously and provided by the caller;
there is no allocation or ownership transfer in these binding functions.

Use 32-byte AEAD/session/auth keys, 24-byte XChaCha nonces, 16-byte AEAD tags,
and 32-byte `crypto_auth` tags. Never reuse a nonce with the same key. AEAD
output needs message length plus 16 bytes. Discard output when decryption fails.
`crypto_kx` alone does not authenticate peers: the calling protocol must verify
peer identity or authenticate its complete handshake with a securely provisioned
key. Do not use a human password directly as a PSK.

Build pinned libsodium 1.0.22 locally (no system installation):

```sh
scripts/build-sodium.sh macos
scripts/build-sodium.sh iphoneos
scripts/build-sodium.sh iphonesimulator
scripts/check-sodium.sh
```

All targets are arm64. Headers and static archives are under
`build/sodium/<platform>/include` and `build/sodium/<platform>/lib/libsodium.a`.
Pass the include directory to Clang and link that archive for the matching SDK.
The source archive is fetched from the official release host over HTTPS and
pinned with SHA-256; subsequent builds reject checksum differences. The script
runs the upstream test suite for macOS; cross-compiled iOS archives cannot run
those host tests. The Zen binding test checks an upstream AEAD known-answer
vector, all ciphertext/tag byte mutations, changed associated data, directional
key agreement, invalid peer rejection, and explicit buffer erasure with UBSan.
This is primitive/binding validation, not a security audit of an app protocol.

Native Zen BLAKE2b is now an opt-in implementation; SIMD and the remaining
algorithms are future work. Replacements must preserve the relevant interfaces and pass
known vectors, differential tests, malformed-input tests and architecture-specific
constant-time review before replacing libsodium. Source appearance alone is not
proof of constant-time behavior.

References: [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction),
[key exchange](https://doc.libsodium.org/key_exchange),
[helpers](https://doc.libsodium.org/helpers).

## Current API

- `equal_bytes_candidate(left, right, count)` compares a common public length,
  visits every byte at source level, and returns equality. The name deliberately
  does not promise constant-time execution.

Pointers are borrowed synchronously; callers must provide live storage covering
`count` bytes. Comparison permits overlapping
inputs and null pointers only at zero length. No operation allocates, transfers
ownership, or retains a pointer. Bounds and lifetimes are caller obligations.

## Run

From this directory:

```sh
scripts/check.sh
```

Defaults use `../zen/build/dev/actor-zen` and `../zen/src`. Override with
`ZEN_COMPILER` and `ZEN_STD`. Clang is needed for the generated-code inspection.
Build products are ignored under `build/`.

Verified on 2026-09-27, Apple arm64, Apple Clang 17.0.0
(clang-1700.6.4.2): project build and emitted-C `-O2` test both pass. Tests cover
empty/null input, aliasing, all 1,024 mismatch positions, lengths 0 through 65,
every byte value. These test functional correctness, not side-channel resistance.

## Constant-time status

The goal is data-independent control flow and memory access for a public fixed
length, not perfectly constant wall-clock time. Source code alone does not
establish that property. Comparison sums mismatch bits, using wrapping addition;
the sum is bounded by `count`, so it cannot actually wrap for valid inputs.
This spelling avoids a checked-overflow helper on the accumulated differences.

`scripts/check.sh` also emits an **inspection-only** C copy, adding
`noinline,used` to the comparison function alone. It changes no algorithm and
allows normal arithmetic-helper inlining. Its optimized arm64 function has:

- NEON `cmeq.16b` / `cmeq.8b` comparisons and vector reductions;
- scalar tail `cmp` / `cinc`, and final `cset`;
- branches for public length, vector tails and loop counts;
- no observed mismatch-dependent early exit, secret-indexed loads, calls to
  `memcmp`, or checked-add overflow branch in that inspected function.

Normal `-O2` output also contains auto-vectorized comparisons, but inlines them
into callers. The isolated inspection is **not a guarantee for all inlining
contexts, compilers, architectures, or future releases**. No timing-statistics
study, formal proof, whole-program side-channel audit, sanitizer run, or external
security review has been completed. Inspect `build/audit.s` and
`build/optimized.s`; do not use this candidate to protect production secrets.

Ordinary allocation, freeing, or actor delivery does not provide secure erasure.
Actors may copy payloads, leaving additional secret copies. No secure-buffer API
is claimed here. `std.core.rand` is explicitly non-cryptographic and must not be
used for keys or nonces.

## Next

See [the native implementation track](docs/NATIVE_CRYPTO.md) and
[the roadmap](docs/ROADMAP.md). BLAKE2b requires the companion compiler/stdlib
change providing native u64 XOR and rotate-right. SHA-256, AEAD and key exchange
remain separate implementation work; no arithmetic emulation of XOR is used.

References: [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
defines the planned SHA-256 algorithm;
[libsodium helpers](https://doc.libsodium.org/helpers) explains fixed-length
comparison expectations. No certification or equivalent assurance is implied.

`ServerContext` in `src/tls.zen` owns the TLS 1.3 server configuration and
OpenSSL context lifetime in Zen. Socket adapters borrow its handle and must
close sessions before its owner is dropped. Cryptographic operations continue
to use OpenSSL; nonblocking TLS retry decisions now live in `server_io` in Zen. Remaining C
TLS helpers handle session creation/cleanup and const-qualified ABI details.


`ServerContext.enable_h2()` installs native Zen ALPN selection for the experimental
HTTP/2 listener. OpenSSL still performs the handshake and cryptography. The
listener checks h2 was negotiated before sending protocol responses; omitting
ALPN is rejected at that application boundary, not during the TLS handshake.


On Linux, TLS uses a borrowed-socket BIO that sends with MSG_NOSIGNAL. This
prevents socket-write SIGPIPE without changing process-wide signal disposition.
The native adapter handles socket syscalls/BIO ownership; OpenSSL performs TLS
and cryptography, while Zen handles protocol policy and retries. The BIO does
not support kTLS, fast-open or transfer of descriptor ownership. Its immutable
method object is initialized once and retained for the process lifetime.


## Native BLAKE2b candidate

Import `blake2b_candidate = blake2b` from `src/blake2b.zen`. Hash compression,
key handling, counters, padding and digest encoding are Zen source. This module
does not call or link libsodium/OpenSSL; the differential test links libsodium
as an oracle. Existing sodium-backed callers are not silently switched.

```text
blake2b_candidate(output, output_capacity, output_count,
                  input, input_count, key, key_count,
                  scratch, scratch_words) -> bool
```

The digest is 16–64 bytes; the key is 0–64 bytes (zero means unkeyed). Supply
40 aligned `u64` scratch words, disjoint from all other buffers. Output may
overlap input/key. Null input/key is accepted only at zero length. Invalid
parameters return false without changing output or scratch. Valid memory spans
and pointer lifetimes are the caller's responsibility. Key-derived scratch must
be securely wiped by the caller; ordinary allocation/free does not erase it.

This is a one-shot sequential candidate, without streaming, salt, personalization
or tree mode. It is not an audited replacement for production keyed hashing.
See [the implementation and validation contract](docs/NATIVE_CRYPTO.md).

Compiler prerequisite: [Zen PR #6](https://github.com/lantos1618/zen/pull/6),
merged into compiler `main` as `27275e04`. Compiler main at `b107afe5`
includes both numeric primitives and std readiness. Build that revision (or a
later descendant) using the compiler's bootstrap
instructions and point both compiler and standard-library paths at that checkout:

```sh
ZEN_COMPILER=/path/to/zen/zen ZEN_STD=/path/to/zen/src scripts/check-blake2b.sh
ZEN_STD=/path/to/zen/src /path/to/zen/zen build test-blake2b
build/test-blake2b
```

The differential command requires the existing pinned libsodium build (or
`SODIUM_PREFIX`); the standalone build target needs no crypto dependency.
The tested compiler prerequisite passes focused checks and bootstrap fixpoint.
Both compiler PRs passed GitHub verification before merge. The earlier local
macOS aggregate hit a warning-budget mismatch; that historical limitation is
retained in the PR validation notes.
