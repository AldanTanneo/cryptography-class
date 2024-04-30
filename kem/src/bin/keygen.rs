use argh::FromArgs;
use io_utils::hexfmt;
use rand::{rngs::StdRng, SeedableRng};
use std::{fs::File, path::PathBuf};

/// Generate a public/private keypair in the Key Encapsulation Mechanism.
///
/// The public key is printed to stdout, the private key is serialized into
/// the given file name.
#[derive(FromArgs)]
struct Opts {
    /// file in which to store the private key
    #[argh(positional)]
    filename: PathBuf,
}

fn main() {
    let opts: Opts = argh::from_env();

    // the CryptoRng bound on keygen ensures that we use
    // a cryptographically secure Rng
    let mut rng = StdRng::from_entropy();
    let (public, private) = kem::keygen(&mut rng);

    let file = File::create(opts.filename).expect("Could not create private key file");
    private
        .serialize(file)
        .expect("Could not write private key to file");

    println!("{}", hexfmt(&public));
}
