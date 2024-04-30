use argh::FromArgs;
use rand::{rngs::StdRng, SeedableRng};

/// Ed25519 key generation
#[derive(FromArgs)]
struct Opts {
    /// key files prefix
    ///
    /// The generated files are prefix.pk, prefix.sk
    #[argh(positional)]
    prefix: String,
}

fn main() {
    let opts: Opts = argh::from_env();

    // StdRng is chosen to be a cryptographically secure RNG.
    let mut rng = StdRng::from_entropy();

    // The "CryptoRng" bound on the keygen() function ensures that we never
    // use an unsecure source of randomness.
    let keys = ed25519::keygen(&mut rng);

    std::fs::write(format!("{}.pk", opts.prefix), keys.public)
        .expect("Could not write public key file");
    std::fs::write(format!("{}.sk", opts.prefix), keys.private)
        .expect("Could not write private key file");
}
