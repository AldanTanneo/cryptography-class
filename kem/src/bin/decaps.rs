use argh::FromArgs;
use io_utils::{hexfmt, parse_hex};
use kem::SecretKey;
use std::{fs::File, path::PathBuf};

fn parse_ciphertext<const N: usize>(arg: &str) -> Result<[u8; N], String> {
    parse_hex(arg).ok_or_else(|| format!("expected {N}-bytes hexadecimal string"))
}

/// Extract the symmetric encryption key from a ciphertext, using
/// the given private key file.
#[derive(FromArgs)]
struct Opts {
    /// private key file
    #[argh(positional)]
    private_key: PathBuf,
    /// encapsulated key ciphertext
    #[argh(positional, from_str_fn(parse_ciphertext))]
    ciphertext: [u8; 48],
}

fn main() {
    let opts: Opts = argh::from_env();

    let file = File::open(opts.private_key).expect("Could not open private key file");
    let secret_key = SecretKey::deserialize(file).expect("Could not deserialize private key");
    let key = kem::decaps(&opts.ciphertext, &secret_key);

    println!("{}", hexfmt(&key));
}
