# ChaCha/Poly

ChaCha/Poly AEAD implementation

## Building

The executables are implemented in Rust. An up-to-date Rust toolchain is needed. To compile them, run `cargo build --release` top level folder. The executables `chacha20`, `aead_wrap` and `aead_unwrap` will be located in the `target/release` folder.

Alternatively, the provided `Makefile` runs the build command.

Cargo will pull dependencies as specified in `Cargo.toml` files, so an internet connection is required to build.

## Structure

### ChaCha20 Cipher

The ChaCha20 stream cipher is implemented in the `chacha20` folder. The `src/lib.rs` file contains the cipher implementation, with a `State` struct that has methods for performing the quarter round, double round and the full block rounds. The free function `block` computes the block for a given key, counter, and nonce.

The `Cipher` struct is sort of a state machine that will pull bytes out of the reader as needed, and XOR them as it goes with the corresponding bytes from the stored ChaCha20 block. When it reaches the end of a block, it computes the next one. It takes the form of a wrapper around something with a `Read` interface. We can then "read" bytes out of it, and output them wherever we want.

The `src/main.rs` file performs these operations on the given command line arguments.

### ChaCha/Poly AEAD

The AEAD software is implemented in the `aead_chacha_poly` folder. The `src/lib.rs` file contains utilities for padding an object with a `Read` interface and feed them to the Poly1305 implementation (from the previous week) and the ChaCha20 cipher.

The `Pad16` struct pads the given reader to a multiple of 16 bytes by adding `0` bytes. The `ConcatLen` struct concatenates two readers, padded using `Pad16`, and adds their respective lengths (before padding) at the end of the stream, as little endian bytes.

The free function `compute_tag` computes the tag on an adfile and the ciphertext of a plaintext input, and outputs this ciphertext on-the-fly to a provided output interface. The free function `check_tag` computes the tag on a given ciphertext and adfile, and does not decipher the text.

The `src/wrap.rs` and `src/unwrap.rs` perform the AEAD operations on the given command line arguments.

## Testing

Functional tests are also provided, in the `tests` folder for each library. They can be run with `cargo test`.
