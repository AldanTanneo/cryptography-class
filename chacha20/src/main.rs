use argh::FromArgs;
use chacha20::u96;
use std::io::{stdin, stdout, BufReader, BufWriter, Read, Write};
use std::{fs::File, path::PathBuf};

/// Encrypt data using the ChaCha20 cipher
#[derive(FromArgs)]
struct Opts {
    /// the chacha20 key
    #[argh(positional)]
    keyfile: PathBuf,
    /// the message nonce
    #[argh(positional, from_str_fn(chacha20::parse_nonce))]
    nonce: u96,
    /// input file, or "_" for stdin
    #[argh(positional)]
    infile: String,
    /// output file, empty for stdout
    #[argh(positional)]
    outfile: Option<String>,
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

    let input: Box<dyn Read> = match opts.infile.as_str() {
        "_" => Box::new(stdin().lock()),
        path => Box::new(File::open(path).expect("Could not open input file")),
    };
    let input = BufReader::new(input);

    let output: Box<dyn Write> = match opts.outfile.as_deref() {
        None => Box::new(stdout().lock()),
        Some(path) => Box::new(File::create(path).expect("Could not create output file")),
    };
    let mut output = BufWriter::new(output);

    let mut cipher = chacha20::cipher(&key, opts.nonce, input);

    std::io::copy(&mut cipher, &mut output).expect("Error while writing data to output");
    output.flush().expect("Error while writing data to output");
}
