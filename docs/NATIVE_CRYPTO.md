# Native Zen cryptography implementation track

The first implemented algorithm is BLAKE2b, the primitive behind the
libsodium generic-hash binding. Its compression, key-block handling, counters,
finalization and digest encoding belong in Zen. libsodium is a test oracle and
continues to serve existing callers until replacement gates are met.

The language needs real integer XOR and rotate-right operations. Those belong
in the compiler and standard numeric module, with defined word-width behavior,
not in an algorithm-specific C shim. Generated C is the existing Zen backend;
that does not make a source-level Zen algorithm a handwritten C implementation.

## Order of work

1. BLAKE2b one-shot unkeyed/keyed hashing, independent vectors and differential
   tests, followed by a streaming API and performance measurements.
2. ChaCha20/HChaCha20, then Poly1305, then XChaCha20-Poly1305. Validate each
   component before composing AEAD. Authentication failure must not expose
   unauthenticated plaintext. Check counter exhaustion and overlap contracts.
3. SHA-512 and HMAC-SHA512/256 for the `crypto_auth` surface.
4. X25519 and the exact libsodium directional key-exchange construction.
5. Secure comparison/erasure and secret-buffer ownership contracts. Entropy
   still comes from OS cryptographic randomness; ordinary `std.core.rand` is
   not a substitute.

This order implements the existing algorithms rather than designing new ones.
The existing sodium bindings remain available throughout migration. A passing
vector suite demonstrates tested functional agreement, not side-channel safety.
Default replacement also needs optimized-code review per architecture/toolchain,
error/ownership cleanup, timing evidence and independent security review.

## BLAKE2b candidate contract

The one-shot low-level API uses borrowed input, key and output buffers plus
caller-owned, aligned scratch. It retains no pointers and performs no allocation.
All nonempty regions must be live and cover their declared lengths. Output may
alias input or key because it is written only after processing them; scratch must
not overlap any other region. Pointer validity and disjoint scratch cannot be
inferred from lengths alone.

Invalid public parameters must return failure before changing output or scratch.
Scratch contains key-derived state after success. Ordinary writes are not a
secure-erasure guarantee: callers must use the existing vetted wipe operation
when disposing of keyed state. This is not a complete secret-owner abstraction.

Initial scope is sequential one-shot BLAKE2b. It does not provide tree hashing,
salt/personalization, streaming, a TLS record implementation or an encryption API.
No constant-time, security-audit or speed claim follows from source language.

Algorithm reference: [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693).
Compatibility target: [libsodium generic hashing](https://doc.libsodium.org/hashing/generic_hashing).

## Functional validation

On macOS arm64 with Apple Clang 17, both optimized (`-O3`) and UBSan (`-O2`)
builds pass 35,035 comparisons against libsodium: all 49 digest lengths 16–64,
all 65 key lengths 0–64, and messages of 0,1,127,128,129,255,256,257,1024,4096,8193
bytes. Another 128 cases vary content with zero, all-ones and deterministic
pseudorandom patterns. Eight fixed Python hashlib vectors, 14 invalid-parameter
cases (output and scratch unchanged) and five permitted alias cases also pass.

A separate UBSan executable imports no sodium module and links no cryptographic
library. It passes eight fixed vectors and RFC 7693's BLAKE2b-512 `abc` vector.
Its unresolved symbols contain no libsodium/OpenSSL calls. An IV-bitflip in a
temporary generated-C copy makes this executable fail, confirming that the
known-answer checks detect a deliberately broken algorithm.

The optimized arm64 assembly contains native XOR and rotate instructions. This
spot check confirms native lowering; it is not a complete constant-time review.
No timing-statistics study, independent security audit or comparative performance
benchmark is claimed. Tests do not exercise the full 128-bit counter range with
physically enormous inputs. The first release uses a 64-bit compiler target.

The normal package target `zen build test-blake2b` also builds and passes the
standalone vectors, without crypto libraries. Use a compiler and `ZEN_STD` from
the same revision containing the numeric prerequisite. The differential runner
is `scripts/check-blake2b.sh`; it accepts `ZEN_COMPILER`, `ZEN_STD`, `CC` and
`SODIUM_PREFIX` overrides. Its IV mutation is applied only to an ignored generated
C copy, never to the maintained algorithm source.
