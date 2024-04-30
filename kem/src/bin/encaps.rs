use argh::FromArgs;
use io_utils::{hexfmt, parse_hex};
use rand::{rngs::StdRng, SeedableRng};

fn parse_public_key(arg: &str) -> Result<[u8; 32], String> {
    parse_hex(arg).ok_or_else(|| "expected 32-bytes hexadecimal string".into())
}

/// Compute a symmetric encryption key and its ciphertext
/// from a given public key
///
/// The ciphertext will be printed first, and the symmetric
/// key on the next line.
#[derive(FromArgs)]
struct Opts {
    /// public key as a hexadecimal string
    #[argh(positional, from_str_fn(parse_public_key))]
    public_key: [u8; 32],
}

fn main() {
    let opts: Opts = argh::from_env();

    let mut rng = StdRng::from_entropy();
    let (ciphertext, key) = kem::encaps(&mut rng, &opts.public_key);

    println!("{}", hexfmt(&ciphertext));
    println!("{}", hexfmt(&key));
}
