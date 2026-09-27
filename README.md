# zen-crypto

Experimental, pure Zen byte primitives for a future crypto library. **No hash,
encryption, signatures, key generation, or production-ready cryptography is
implemented yet.** There are no handwritten C algorithm wrappers and no compiler
or standard-library changes in this package.

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
