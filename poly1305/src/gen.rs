use std::{fs::File, io::BufReader, path::PathBuf};

use argh::FromArgs;

/// Generate poly1305 tags
#[derive(FromArgs)]
pub struct Opts {
    /// a 64 character hexadecimal string
    #[argh(positional, from_str_fn(poly1305::parse_key))]
    key: [u8; 32],
    /// path to the file to compute the tag for
    #[argh(positional)]
    file: PathBuf,
}

fn main() {
    let opts: Opts = argh::from_env();

    let file = File::open(opts.file).expect("Could not open file");
    let file = BufReader::new(file);

    let poly1305 = poly1305::poly1305(file, &opts.key).expect("Error while reading from file");

    for byte in poly1305.to_le_bytes() {
        print!("{byte:02x}");
    }
    println!();
}
