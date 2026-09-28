# zen-crypto

Zen cryptography interfaces with a vetted libsodium backend, alongside an
experimental pure Zen byte-comparison candidate. Production encryption uses
libsodium; the candidate is not used for security decisions. No handwritten C
wrappers or compiler changes are needed.

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

Native Zen crypto/SIMD is future work. It must preserve this interface and pass
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

See [the roadmap](docs/ROADMAP.md). SHA-256 is deferred because the current
numeric floor lacks integer bitwise/shift operations. Arithmetic emulation would
hide that gap and produce an unnecessarily slow implementation.

References: [NIST FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
defines the planned SHA-256 algorithm;
[libsodium helpers](https://doc.libsodium.org/helpers) explains fixed-length
comparison expectations. No certification or equivalent assurance is implied.
