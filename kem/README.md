# Key Encapsulation Mechanism

Implementation of the Fujisaki–Okamoto Transforms on a custom Hash-ElGamal PKE scheme.

The Fujisaki–Okamoto (FO) Transform constructs IND-CCA2-secure PKE schemes from IND-CPA PKE schemes.

### PKE
Here, the PKE we implemented is:

Key format: X25519 Public/Private keys
Encrypt:
1. Use or generate a random ephemeral private key y and its public key c1
2. Derive a shared secret S = x25519(y, public_key)
3. Hash this shared secret into a ChaCha20 key using Shake128:
k = shake128(S)
4. Encrypt the message using ChaCha20(k, 0, msg) as c2;
   we use a fixed nonce 0, as the key is random
5. The ciphertext is c1 || c2

Decrypt:
1. Unpack the ciphertext into c1 || c2
2. Compute the shared secret S = x25519(private_key, c1)
3. Hash this shared secret into the ChaCha20 key, using Shake128:
k = shake128(S)
3. Decrypt the message using ChaCha20(k, 0, c2)

### KEM

For the KEM implementation, we chose the following parameters:
- Ls = 128 bits (the length of the extra randomness s in the secret key)
- the random message is 128 bits long, and the ciphertext is 256 + 128 = 384 bits long
- g1(data) = shake128(data || "g1", 128)
- g2(data) = shake256(data || "g2", 256)
- f(data) = shake128(data || "kdf", 128)

In g1, g2 and f, an ascii string is added to the input for domain separation.

## Building

The executables are implemented in Rust. An up-to-date Rust toolchain is needed. To compile the `keygen`, `encaps` and `decaps` executables, run `cargo build --release`. The executables will be located under `target/release`.

Cargo will pull dependencies as specified in `Cargo.toml`, so an internet connection is required to build.

## Structure

The main KEM implementation is in `kem/src/lib.rs`.

The code reuses the `x25519`, `chacha20`, and `shake128` implemented in the course.

We define a trait `Pke` to describe our basic ElGamal scheme and its parameters, as well as a `Kem` supertrait with more parameters to choose. The `Kem` trait only needs types and g1, g2 and f to be defined; it provides the `keygen`, `encaps` and `decaps` functions using those parameters.

We implement both of those traits on the `HashElGamal25519` dummy type.

The secret key type for the KEM, containing SK, s, PK and PKH, is serialized and deserialized using the `serialize` and `deserialize` functions, which simply write and read the raw bytes to/from the file. Since the key lengths are fixed, this can be done reliably. We also check that there is no extra data in the file, but we could write a parser to ignore comments specifying the name of the key, for instance.

Finally, we define the convenience functions `keygen`, `encaps` and `decaps`, that will be used by the binaries.

The actual binaries just parse their arguments, initialize cryptographically secure RNGs and call the library functions. Their code is contained in `kem/src/bin/*`.

## Testing

Run `./keygen private.key` to get a public key in stdout, and a private key stored in the `private.key` file.

Run `./encaps $PUBLIC_KEY` to get a ciphertext and a symmetric encryption key on two separate lines.

Finally, run `./decaps private.key $CIPHERTEXT` and check that the returned encryption key is the same one the sender obtained with `encaps`.
