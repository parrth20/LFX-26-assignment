# LFX Mentorship Coding Challenge Submission

Project: Advanced Threshold Key Management / Lockness coding challenge

Applicant: Parth Bandwal

College: IIIT Lucknow

Repository URL:

```text
https://github.com/parrth20/LFX-26-assignment
```

Repository visibility: Public

## Setup

Install a standard Rust toolchain with Cargo. The crate is platform independent and should
compile on Linux and macOS.

## Verification

Run the following commands from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

The submitted code has been checked with these commands locally. The test suite includes
the provided vectors for Ed25519, secp256k1, and secp384r1, plus round-trip tests for the
implemented encryption and decryption functions.

## Library API

The crate exports:

- `encrypt(pk, message, rng)`
- `decrypt(sk, ciphertext)`
- `Error`

Both functions are generic over curves supported by the `generic-ec` crate.
