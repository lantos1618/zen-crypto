# Crypto foundation roadmap

## Current implementation checkpoint

Native BLAKE2b is being added with compiler-backed u64 XOR and rotate-right.
See [the current implementation track](NATIVE_CRYPTO.md) for its contract and
validation evidence. The numeric audit below records the earlier baseline; the
companion compiler change addresses only those two u64 operations, not the full
u32/u64 bitwise, shift and rotate surface.


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

Workspace audit (2026-09-28): the primary `zen/src/std/math/vector.zen`
contains allocation-free f64 `dot` and `squared_distance`, using four independent
accumulators for backend SIMD. Its focused `tests/library/vector` harness covers
lengths 0..1024, tails, offset pointers and aliasing, includes a deliberately
broken-kernel control, ASan/UBSan compilation, and checks arm64 vector multiply
instructions. This is real existing work to preserve and upstream, but is an
untracked primary-checkout addition, absent from the merged socket/actor tree
`zen-actor-runtime` at 2a40b9ce. Do not describe it as already merged or a general
integer SIMD API. Its current numerical test inputs are exactly representable;
broader NaN/infinity/rounding-error contracts remain separate work.

Both trees contain scalar std math bindings for cos/sin/sqrt/log10/round.
`std/core/num.zen` defines bounds, widths and conversions; `ast_node.zen` and
`parse_expr.zen` enumerate arithmetic, comparisons and boolean operators, but
no integer bitwise/shift/rotate operations. Thus the narrow missing compiler
floor is evidenced in actual declarations/parser, not inferred from absent
crypto algorithms. Preserve the existing bulk math; add only the missing
integer semantics needed by crypto. The comparison candidate also already
auto-vectorizes on arm64 without a new vector language type.

The merged `std.mem.Pool`, `PoolAlloc`, `PoolPolicy`, and `PoolStats` provide
exact-size reuse, bounded retained cache and immutable telemetry. Focused gates
cover realloc preservation, native OOM/overflow, limits, teardown and negative
controls. Reuse this Alloc interface for scratch storage. It is externally
serialized, libc-backed, supports alignment through 16 bytes, and neither wipes
secrets nor locks pages. A pool therefore complements secret ownership rather
than replacing its erasure/copy contracts.

## 2. Algorithms belong in zen-crypto

Application encryption can use the separate `zen-sodium` backend package; native implementations here are opt-in
research until the gates below pass. Prioritize XChaCha20-Poly1305 compatibility
with that backend: a portable ChaCha20/HChaCha20 reference, Poly1305 arithmetic,
then the combined AEAD construction. Implement the specified construction rather
than designing a new cipher or handshake. Fixed-width integer operations and
endian helpers should come from std; algorithm state belongs here.

Acceptance requires independent known-answer vectors and differential tests
against libsodium for empty messages/AD, byte and block boundaries, long messages,
all tag-byte corruptions, altered AD/nonces/keys, malformed/truncated ciphertext,
nonce/counter exhaustion, and overlap contracts. Reject failed authentication
without releasing unauthenticated plaintext. Reusable caller-owned scratch and
secret cleanup must be tested across error paths as well as success.

Only then optimize using integer SIMD. Keep the portable implementation as a
reference, gate CPU features explicitly, and compare every optimized output.
Benchmark realistic voice packet sizes separately from large buffers; report
latency distributions, throughput and allocations. Do not turn faster arithmetic
into a claim that the whole app or network protocol is constant-time.

Constant-time review must inspect the exact optimized binaries on each supported
architecture/toolchain for secret-dependent branches, addresses, table lookups,
variable-time instructions and compiler-introduced helpers. Add timing-statistics
experiments (including negative controls), but treat them as evidence, not proof.
Require independent security review before replacing the vetted backend by
default. SIMD is a performance technique, not a side-channel guarantee.

SHA-256 remains a later independent library feature, using FIPS 180-4 and bounded
streaming state. Validate known answers, padding/length boundaries and chunk
equivalence; it is not a prerequisite for XChaCha20-Poly1305.

## 3. OS services and secret ownership

Entropy acquisition belongs behind OS adapters and a clear shared API; the
consumer-facing cryptographic RNG API can live in zen-crypto. Never silently
fall back to std.core.rand. Surface entropy-source failure, including partial
reads. Apple system RNG bindings are distinct from hashing or DSP math.

Design a non-copying secret-owner abstraction before broadening the low-level
caller-owned libsodium bindings: normal arenas and
actor payload copying can duplicate secrets. Secure erasure needs compiler/OS
semantics resistant to dead-store elimination; ordinary zero writes are not a
secure wipe. Locked pages, dumps, swapping and actor transport require separate
contracts. The separate `zen-sodium` binding supplies sodium_memzero, not a comprehensive locked-page or
non-copyable secret-buffer abstraction. Compile-time paired-build PSKs remain in
application artifacts; runtime erasure cannot erase those original copies.

## Acceptance gates

Functional tests first; defined numeric semantics; independent vectors;
allocation/lifetime tests; optimized assembly review per supported build;
reproducible benchmarks; then independent security review before production use.
Do not create new encryption protocols or advertise audited cryptography from a
small local test suite.

## Tooling split

Use [ASan](https://clang.llvm.org/docs/AddressSanitizer.html) for memory-access
errors and [UBSan](https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html)
for undefined operations in emitted code. Use separate
[TSan](https://clang.llvm.org/docs/ThreadSanitizer.html) builds for actor races;
LLVM lists Darwin arm64 support. Validate each sanitizer runtime with a known
failing control on the actual host, and report unavailable/timed-out runs as
unverified. Sanitizers are bug finders, not constant-time checks; prebuilt
uninstrumented library internals are outside full instrumentation coverage.

[dudect](https://github.com/oreparaz/dudect) supplies statistical timing tests,
but its upstream `cpucycles()` currently uses x86 `_mm_mfence`/`__rdtsc`.
Running that exact harness on Apple arm64 needs an explicitly validated timing
port; otherwise run its native x86 build in Linux CI and separately assess the
actual arm64 artifact. Do not claim portable dudect coverage merely because
emitted Zen code compiles as C.

[ctgrind](https://github.com/agl/ctgrind) checks secret-tainted control/address
flows through Valgrind. Upstream [Valgrind platforms](https://valgrind.org/info/platforms.html)
include ARM64 Linux, but no ARM64 Darwin. Plan a Linux check for this analysis;
it does not substitute for macOS arm64 optimized-assembly inspection. None of
these tools alone establishes side-channel safety.
