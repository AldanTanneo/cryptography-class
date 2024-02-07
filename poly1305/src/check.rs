use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

use argh::FromArgs;

/// check poly1305 tags
#[derive(FromArgs)]
pub struct Opts {
    /// a 64 character hexadecimal string
    #[argh(positional, from_str_fn(poly1305::parse_key))]
    key: [u8; 32],
    /// path to the file to check the tag for
    #[argh(positional)]
    file: PathBuf,
    /// a 32 character hexadecimal string
    #[argh(positional, from_str_fn(poly1305::parse_tag))]
    tag: u128,
}

fn main() {
    let opts: Opts = argh::from_env();

    let file = File::open(opts.file).expect("Could not open file");
    let file = BufReader::new(file);

    let poly1305 = poly1305::poly1305(file, &opts.key).expect("Error while reading from file");

    if poly1305 == opts.tag {
        println!("ACCEPT");
    } else {
        println!("REJECT");
    }
}
