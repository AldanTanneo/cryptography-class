# x25519

x25519 Diffie-Hellman implementation

## Building

The executable is implemented in Rust. An up-to-date Rust toolchain is needed. To compile it, run `cargo build --release`. The executable will be located at `target/release/x25519`.

Cargo will pull dependencies as specified in `Cargo.toml`, so an internet connection is required to build.

## Structure

The underlying prime field is implemented using the `ark_ff` library, with a Montgomery representation, in `src/field.rs`. A generic curve implementation is given in `src/curve.rs`: one just has to specify the finite field and the `A` constant used, as seen in `tests/curve1009.rs`.

In `src/lib.rs`, we specify the curve(s) and the way coordinates and scalars are decoded. The helper functions `x25519` and `x448` run the ladder on the decoded values of the given scalar and coordinate.

Finally, `src/main.rs` parses command line arguments and runs the x25519 function on it.

The helper `io-utils` library is just used to parse hexadecimal strings.

## Testing

Functional tests are also provided, in the `tests` folder. They can be run with `cargo test`.

`tests/curve101.rs`, `tests/curve1009.rs` and `tests/curve25519.rs` run tests on the test vectors provided in the Moodle.
`tests/rfc1.rs`, `tests/rfc2.rs` and `tests/key_exchange.rs` run tests on the test vectors provided by the RFC.

To run the second RFC test, ignored by default because it takes a long time to run, use the following command:

```sh
cargo test --release x25519 -- --ignored
```

You can also run it for the `x448` curve by switching the curve name in the command.
