# zen-crypto

Native Zen cryptographic algorithms. Runtime source under `src/` contains Zen
implementations, not OpenSSL or libsodium wrappers. Zen currently generates C;
that generated backend output is distinct from calling an external crypto library.

## Implemented

- `blake2b_candidate = blake2b`: one-shot sequential BLAKE2b, keyed or unkeyed.
  Compression, counters, padding and digest encoding are Zen.
- `equal_bytes_candidate = crypto`: a byte-comparison candidate, without a
  constant-time guarantee across compiler versions, architectures or callers.

- `Sha256`, `sha256_candidate = sha256`: incremental and one-shot SHA-256.
- `hmac_sha256_candidate = hmac_sha256`, `hkdf_extract_candidate`,
  `hkdf_expand_candidate = hkdf`: SHA-256 HMAC and HKDF.
- `chacha20poly1305_seal`, `chacha20poly1305_open = chacha20poly1305`:
  IETF ChaCha20-Poly1305 with a 12-byte nonce and 16-byte tag.
- `tls13`: SHA-256 TLS 1.3 key schedule and ChaCha20-Poly1305 records.
- `x25519_public_key`, `x25519_shared_secret = x25519`: native RFC 7748
  scalar multiplication with caller-owned scratch. See [X25519](docs/X25519.md).
- `tls13_psk_connect`, `Tls13Session = tls13_client`: reusable external-PSK
  TLS 1.3 client with authenticated records and shutdown.
  `tls13_psk_round_trip` remains a convenience wrapper. See [TLS scope](docs/TLS13.md).

These are experimental implementations. XChaCha20-Poly1305 and
certificate-based native TLS are not implemented here yet. The TLS handshake
still uses `psk_ke`; standalone X25519 is not yet connected to its key exchange.
No independent security audit or production side-channel guarantee is claimed. See [the native implementation track](docs/NATIVE_CRYPTO.md).

## Backend packages and migration

Backend code formerly in this repository has moved:

| Previous path | New package/path |
|---|---|
| `src/sodium.zen` | [zen-sodium](https://github.com/lantos1618/zen-sodium), `src/sodium.zen` |
| `scripts/build-sodium.sh`, `scripts/check-sodium.sh`, `tests/sodium_test.zen` | `zen-sodium`, same relative paths |
| `src/tls.zen`, `src/zen_tls.h` | [zen-openssl](https://github.com/lantos1618/zen-openssl), same relative paths |
| `scripts/build-openssl.sh` | `zen-openssl/scripts/build-openssl.sh` |

Update explicit build dependencies and include paths to the new packages.
The module names `sodium` and `tls` are retained there. No compatibility forwarding
modules remain here: importing this package does not silently pull in a backend.
`zen-http` uses `zen-openssl` for working TLS. This separation does not implement
certificate-based native TLS or remove OpenSSL from HTTPS applications.

## Build and test without crypto backends

Use matching compiler and standard library builds with u32/u64 XOR, AND,
rotate-right and logical right shift, plus `std.bytes`. These additions are in
merged [Zen PR #8](https://github.com/lantos1618/zen/pull/8), main commit
`08ea4cbd`; older main `b107afe5` only supports the BLAKE2b subset. From this repo:

```sh
ZEN_COMPILER=/path/to/zen/zen ZEN_STD=/path/to/zen/src scripts/check.sh
ZEN_STD=/path/to/zen/src /path/to/zen/zen build test-blake2b
build/test-blake2b
```

The normal checks build comparison, BLAKE2b, SHA-256/HMAC/HKDF and
ChaCha20-Poly1305 and X25519 without external crypto headers or libraries.
The BLAKE2b standalone check runs nine known answers,
inspects unresolved symbols and rejects a deliberate IV-bitflip negative control.
`CC` and `PYTHON` can override the BLAKE2b test toolchain. Defaults use a sibling
`zen-actor-runtime` compiler checkout; build products are ignored under `build/`.

An optional differential test uses the separate `zen-sodium` package as an oracle:

```sh
# Build the reference backend in the sibling package first.
(cd ../zen-sodium && scripts/build-sodium.sh macos) # use linux on Linux
ZEN_COMPILER=/path/to/zen/zen ZEN_STD=/path/to/zen/src scripts/check-blake2b.sh
```

`SODIUM_PREFIX` selects its library installation; `SODIUM_SOURCE` selects the
oracle binding file (use an absolute path). Only an ignored test staging directory
imports that binding. Native source and the standalone checks remain independent.

## BLAKE2b API and evidence

```text
blake2b_candidate(output, output_capacity, output_count,
                  input, input_count, key, key_count,
                  scratch, scratch_words) -> bool
```

Digest length is 16–64 bytes, key length 0–64 (zero means unkeyed). Supply 40 aligned
`u64` scratch words, disjoint from other buffers. Output may overlap input/key.
Null input/key is accepted only at zero length. Invalid parameters return false
without modifying output or scratch. Live memory spans and lifetimes are caller
obligations. Scratch retains key-derived state; ordinary writes or freeing memory
do not guarantee secure erasure. The separate sodium package provides a vetted
wipe when needed; this API does not silently call it.

No streaming, salt, personalization or tree mode is provided yet. On macOS arm64
and Linux x86_64, optimized and UBSan builds passed 35,035 libsodium comparisons,
128 varying-content cases, eight hashlib vectors, 14 invalid cases and five alias
cases. The standalone suite adds RFC 7693's `abc` known answer, with no external
crypto symbols. Tests establish the documented functional agreement, not security
certification or a performance ranking. [Evidence and limits](docs/NATIVE_CRYPTO.md).

The comparison candidate has been inspected in optimized arm64 output, but it
has no portable constant-time guarantee. OS entropy, secure erasure and secret
ownership are separate requirements; `std.core.rand` is not a cryptographic RNG.

## Native TLS work

The TLS implementation and its supported profile are described in
[Native TLS 1.3](docs/TLS13.md). OpenSSL is a reference peer for interoperability
tests, not linked into the native client. Existing zen-http HTTPS still uses
zen-openssl. No native TLS performance advantage has been measured.
