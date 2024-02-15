use std::{
    fs::File,
    io::{stdout, BufReader, Read, Write},
    path::PathBuf,
};

use argh::FromArgs;
use ed25519::Keys;

/// Generate Ed25519 signatures
#[derive(FromArgs)]
struct Opts {
    /// key file prefix. The executable expects to find the files
    /// <prefix>.pk and <prefix>.sk, containing the public and private keys.
    #[argh(positional)]
    prefix: String,
    /// data file to sign.
    #[argh(positional)]
    data: PathBuf,
    /// signature file. Leave empty for stdout.
    #[argh(positional)]
    signature: Option<PathBuf>,
}

fn main() {
    let opts: Opts = argh::from_env();

    let mut private_file =
        File::open(format!("{}.sk", opts.prefix)).expect("Could not open secret key file");
    let mut private = [0; 32];
    private_file
        .read_exact(&mut private)
        .expect("Could not read secret key");
    if !matches!(private_file.read(&mut [0]), Ok(0)) {
        panic!("Too much data for private key in {}.sk", opts.prefix);
    }

    let public_file = File::open(format!("{}.pk", opts.prefix));
    let mut public = [0; 32];
    if let Ok(mut public_file) = public_file {
        public_file
            .read_exact(&mut public)
            .expect("Could not read public key");
        if !matches!(public_file.read(&mut [0]), Ok(0)) {
            panic!("Too much data for public key in {}.pk", opts.prefix);
        }
    } else {
        public = ed25519::derive_key(private).public;
    }

    let keys = Keys { private, public };

    let file = File::open(opts.data).expect("Could not open data file");
    let data = BufReader::new(file);

    let signature = ed25519::sign(&keys, data).expect("Could not sign data");

    let mut output: Box<dyn Write> = match opts.signature {
        Some(path) => Box::new(File::create(path).expect("Could not create signature file")),
        None => Box::new(stdout().lock()),
    };
    output
        .write_all(&signature)
        .expect("Could not output signature");
    output.flush().expect("Could not output signature")
}
