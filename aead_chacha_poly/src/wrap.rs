use argh::FromArgs;
use chacha20::u96;
use io_utils::hexfmt;
use std::{
    fs::File,
    io::{stdin, BufReader, BufWriter, Read},
    path::PathBuf,
};

/// Wrap data in the ChaCha/Poly AEAD scheme. Outputs the tag to stdout.
#[derive(FromArgs)]
struct Opts {
    /// chacha20 key location
    #[argh(positional)]
    keyfile: PathBuf,
    /// message nonce
    #[argh(positional, from_str_fn(chacha20::parse_nonce))]
    nonce: u96,
    /// additional data location
    #[argh(positional)]
    adfile: PathBuf,
    /// plaintext location, or "_" for stdin
    #[argh(positional)]
    plaintext: String,
    /// ciphertext output location
    #[argh(positional)]
    ciphertext: PathBuf,
}

fn main() {
    let opts: Opts = argh::from_env();

    let mut keyfile = File::open(opts.keyfile).expect("Could not open key file");
    let mut key = [0; 32];
    keyfile
        .read_exact(key.as_mut_slice())
        .expect("Not enough data in keyfile");
    assert!(
        matches!(keyfile.read(&mut [0][..]), Ok(0)),
        "Too much data in keyfile"
    );

    let aad = File::open(opts.adfile).expect("Could not open additional data file");
    let aad = BufReader::new(aad);

    let plaintext: Box<dyn Read> = match opts.plaintext.as_str() {
        "_" => Box::new(stdin().lock()),
        path => Box::new(File::open(path).expect("Could not open plaintext file")),
    };
    let plaintext = BufReader::new(plaintext);

    let output = File::create(opts.ciphertext).expect("Could not create output file");
    let output = BufWriter::new(output);

    let tag =
        aead_chacha_poly::compute_tag(&key, opts.nonce, aad, plaintext, output).expect("IO error");

    println!("{}", hexfmt(&tag.to_le_bytes()));
}
