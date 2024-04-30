use argh::FromArgs;
use chacha20::u96;
use std::{
    fs::File,
    io::{stdout, BufReader, BufWriter, Read, Seek, SeekFrom, Write},
    path::PathBuf,
    process::ExitCode,
};

fn parse_tag(data: &str) -> Result<u128, String> {
    io_utils::parse_hex(data)
        .map(u128::from_le_bytes)
        .ok_or_else(|| "Invalid tag, must be a 16 bytes hex number".to_string())
}

/// Unwrap data in the ChaCha/Poly AEAD scheme. Outputs the plaintext.
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

fn main() -> ExitCode {
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

    let mut ciphertext = File::open(&opts.ciphertext).expect("Could not open plaintext file");

    let tag = aead_chacha_poly::check_tag(&key, opts.nonce, aad, BufReader::new(&mut ciphertext))
        .expect("IO error");

    if tag != opts.tag {
        return ExitCode::FAILURE;
    }

    // restart ciphertext
    ciphertext
        .seek(SeekFrom::Start(0))
        .expect("Could not seek to start of cipher file");
    // output file or stdout
    let output: Box<dyn Write> = match opts.plaintext.as_deref() {
        None => Box::new(stdout().lock()),
        Some(path) => Box::new(File::create(path).expect("Could not create output file")),
    };
    let mut output = BufWriter::new(output);

    let mut decipher = chacha20::cipher(&key, opts.nonce, BufReader::new(ciphertext));
    std::io::copy(&mut decipher, &mut output).expect("Could not copy plaintext to output");

    ExitCode::SUCCESS
}
