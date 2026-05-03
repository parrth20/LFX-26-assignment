# LFX 2026 Lockness Coding Challenge

Minimal Rust library implementation of the encryption scheme from the Lockness mentorship
coding challenge.

## What is included

- Generic implementation over `generic-ec` curves.
- `encrypt(pk, message, rng)` for encryption.
- `decrypt(sk, ciphertext)` for decryption.
- Test coverage for the provided Ed25519, secp256k1, and secp384r1 vectors.

## Requirements

- Rust toolchain with Cargo.
- Linux or macOS.

## Check commands

Run these from the repository root:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Expected result: all commands pass, and `cargo test` reports all tests passing.

## Notes

The implementation follows the assignment scheme directly. Decryption derives the shared
point as `R * sk`, hashes the compressed encoding with SHA-256, repeats the digest to the
message length, and XORs it with the ciphertext body.
