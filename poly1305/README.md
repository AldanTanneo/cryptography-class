# Poly1305 

Poly1305 is a one-time authenticator designed by D. J. Bernstein. Poly1305 takes a 32-byte one-time key and a message and produces a 16-byte tag. This tag is used to authenticate the message.

## Building

The executables are implemented in Rust. An up-to-date Rust toolchain is needed. Cargo will pull dependencies as specified in `Cargo.toml`, so an internet connection is required to build.

Both `poly1305-gen` and `poly1305-check` can be built using `cargo build --release`, in which case they will be located in `target/release`. Alternatively, the provided `Makefile` builds and copies the binaries to the project's root folder.

## Structure

The actual Poly1305 code is located in `src/lib.rs`. In `src/gen.rs` and `src/check.rs`, we parse the command line arguments using the `argh` library, and run the tag generation/checking code.

## Testing

A unit test in `src/lib.rs` ensures implementation correctness. Further tests of Poly1305 are made in the `aead_chacha_poly` crate.
