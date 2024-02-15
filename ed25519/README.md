# Ed25519

Ed25519 signatures implementation

## Building

The executables are implemented in Rust. An up-to-date Rust toolchain is needed. To compile the `keygen`, `sign` and `verify` executables, run `cargo build --release`. The executables will be located under `target/release`.

Cargo will pull dependencies as specified in `Cargo.toml`, so an internet connection is required to build.

## Structure

The `src/lib.rs` file expose various functions to help the implementation. We reuse the Curve25519 implementation from the `x25519` crate to perform scalar multiplication in constant time, by converting to and from Montgomery form coordinates.

In `src/field.rs`, we define a new prime field, using the group order as modulus, to help in signing and verifying signatures.

In the `src/bin` folder, each files defines an executable. In `keygen.rs`, we use a cryptographically secure RNG, namely ChaCha12 in the current implementation of the `rand` library, to generate a private key and derive a public key from it. In `sign` and `verify`, we read command line arguments and feed the data to the `ed25519` functions.

## Testing

Functional tests are provided in the `tests` folder. They can be run with `cargo test`. They use the RFC test vectors, stored in `tests/vectors.rs`.
