# Crypto foundation roadmap

## 1. Standard-library/compiler numeric boundary

First provide unsigned u32/u64 AND, OR, XOR, NOT, logical shifts and rotate.
Specify fixed-width results; NOT must remain within the word width. Specify
whether out-of-range shifts are rejected or trapped; do not inherit undefined C
behavior. A sensible strict shift contract is 0 <= count < width. Rotate may
reduce count modulo width, with a separate zero-count path to avoid shifting by
the full width. Wrapping arithmetic already exists in Zen. Generic endian byte/word helpers
belong in standard byte/numeric utilities, not a broad public crypto API.

Tests must cover zero/all-ones/high-bit/alternating values, shifts zero/one/width
minus one, rejected width and negative counts where representable, rotations
zero/width/multiples of width, and widening/narrowing behavior. Validate emitted
code on supported backends. Standard-library declarations alone cannot invent
primitive integer instructions absent from the language's compiler lowering.
Do not add handwritten C snippets to zen-crypto to bypass that design work.

`std.math.vector` currently contains f64 dot/squared-distance kernels whose
loops permit backend auto-vectorization. It does not expose integer vector
operations needed by crypto. The comparison candidate already auto-vectorizes
on this arm64 toolchain; no special SIMD API was needed for that operation.

## 2. Algorithms belong in zen-crypto

After integer primitives land, implement portable SHA-256 from FIPS 180-4 with
explicit state ownership and bounded reusable workspace. Validate known answers
for empty input, abc, multi-block data and one million a bytes; padding lengths
55, 56, 63, 64 and 65; streaming chunk equivalence; finalization and length
overflow. Compare against an independent established implementation. Hashing is
not encryption, authentication, or a password-storage scheme.

Only then benchmark. Distinguish generic SIMD from Apple/ARM SHA instructions.
Consider independent-message batching before complicated single-message SIMD.
Keep a portable reference and compare optimized outputs. Feature detection and
unsupported-target fallback must be explicit. Constant-time checks must cover
the exact optimized build, with no claim that a timing test proves security.

## 3. OS services and secret ownership

Entropy acquisition belongs behind OS adapters and a clear shared API; the
consumer-facing cryptographic RNG API can live in zen-crypto. Never silently
fall back to std.core.rand. Surface entropy-source failure, including partial
reads. Apple system RNG bindings are distinct from hashing or DSP math.

Design non-copying secret ownership before introducing keys: normal arenas and
actor payload copying can duplicate secrets. Secure erasure needs compiler/OS
semantics resistant to dead-store elimination; ordinary zero writes are not a
secure wipe. Locked pages, dumps, swapping and actor transport require separate
contracts. No secret-buffer implementation is included in this milestone.

## Acceptance gates

Functional tests first; defined numeric semantics; independent vectors;
allocation/lifetime tests; optimized assembly review per supported build;
reproducible benchmarks; then independent security review before production use.
Do not create new encryption protocols or advertise audited cryptography from a
small local test suite.
