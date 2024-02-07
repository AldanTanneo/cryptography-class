use argh::FromArgs;
use chacha20::u96;
use std::{
    fs::File,
    io::{stdout, BufReader, BufWriter, Read, Write},
    path::PathBuf,
};

fn parse_tag(data: &str) -> Result<u128, String> {
    io_utils::parse_hex(data)
        .map(u128::from_le_bytes)
        .ok_or_else(|| "Invalid tag, must be a 16 bytes hex number".to_string())
}

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
    /// ciphertext input location
    #[argh(positional)]
    ciphertext: String,
    /// poly1305 tag
    #[argh(positional, from_str_fn(parse_tag))]
    tag: u128,
    /// plaintext output location, empty for stdout
    #[argh(positional)]
    plaintext: Option<PathBuf>,
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

    let ciphertext = File::open(&opts.ciphertext).expect("Could not open plaintext file");
    let ciphertext = BufReader::new(ciphertext);

    let tag = aead_chacha_poly::check_tag(&key, opts.nonce, aad, ciphertext).expect("IO error");

    if tag == opts.tag {
        let output: Box<dyn Write> = match opts.plaintext.as_deref() {
            None => Box::new(stdout().lock()),
            Some(path) => Box::new(File::create(path).expect("Could not create output file")),
        };
        let mut output = BufWriter::new(output);

        // reopen ciphertext (we consumed it! that's the issue with streaming data)
        // and besides we didn't want to output it while we weren't sure that it was authenticated
        let ciphertext = File::open(opts.ciphertext).expect("Could not open plaintext file");
        let ciphertext = BufReader::new(ciphertext);

        let mut decipher = chacha20::cipher(&key, opts.nonce, ciphertext);
        std::io::copy(&mut decipher, &mut output).expect("Could not copy plaintext to output");
    } else {
        drop(keyfile);
        std::process::exit(1);
    }
}
