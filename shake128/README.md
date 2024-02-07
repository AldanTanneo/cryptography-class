# SHAKE128

Keccak's Shake128 extendable output hash function.

## Building

The executable is implemented in Rust. An up-to-date Rust toolchain is needed. To compile it, run `cargo build --release`. The executable will be located at `target/release/shake128`

Cargo will pull dependencies as specified in `Cargo.toml`, so an internet connection is required to build.

## Structure

The actual Keccak code in located in `src/lib.rs`. It is structured as small functions that implement each permutation, utilities to parse and process bit strings, and a `keccak` function that takes a byte iterator (the input data) and returns a byte iterator (the extendable output). Padding is applied on the fly in this function, so the input does not need preprocessing.

The function is generic on the `KeccakFlavour` used with it: a particular capacity and suffix. This model allows the library to define all SHA3 (fixed length hash) and Shake (XOF) functions in a concise and efficient way.

In `src/main.rs`, we parse the command line argument `N`, build an iterator adaptor from `stdin`, and then take `N` bytes from the iterator output, printing them as hex data.

## Testing

Functional tests are also provided, in the `tests` folder. They can be run with `cargo test`.

The `tests/permutations.rs` file contains test functions for the Keccak permutation building blocks and the resulting function. In `tests/shake128.rs`, we test the final Shake128 function.
