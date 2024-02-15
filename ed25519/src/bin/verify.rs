use std::{
    fs::File,
    io::{BufReader, Read},
    path::PathBuf,
    process::ExitCode,
};

use argh::FromArgs;

/// Verify Ed25519 signatures
#[derive(FromArgs)]
struct Opts {
    /// public key file
    #[argh(positional)]
    key: PathBuf,
    /// signed data file
    #[argh(positional)]
    data: PathBuf,
    /// signature file
    #[argh(positional)]
    signature: PathBuf,
}

fn main() -> ExitCode {
    let opts: Opts = argh::from_env();

    let mut public_file = File::open(&opts.key).expect("Could not open public key file");
    let mut public = [0; 32];
    public_file
        .read_exact(&mut public)
        .expect("Could not read public key");
    if !matches!(public_file.read(&mut [0]), Ok(0)) {
        panic!("Too much data for public key in {:?}", opts.key);
    }

    let file = File::open(opts.data).expect("Could not open data file");
    let data = BufReader::new(file);

    let mut signature_file = File::open(&opts.signature).expect("Could not open signature file");
    let mut signature = [0; 64];
    signature_file
        .read_exact(&mut signature)
        .expect("Could not read signature");
    if !matches!(signature_file.read(&mut [0]), Ok(0)) {
        panic!("Too much data for signature in {:?}", opts.signature);
    }

    let verify = ed25519::verify(&public, &signature, data).expect("Could not verify signature");

    if verify {
        println!("ACCEPT");
        ExitCode::SUCCESS
    } else {
        println!("REJECT");
        ExitCode::FAILURE
    }
}
