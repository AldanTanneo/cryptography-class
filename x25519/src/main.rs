use argh::FromArgs;
use x25519::{x25519, Curve25519};

fn parse_bytes(data: &str) -> Result<[u8; 32], String> {
    io_utils::parse_hex(data).ok_or_else(|| "must be a 32-bytes hex string".into())
}

/// x25519 cryptography
#[derive(FromArgs)]
struct Opts {
    /// key
    #[argh(positional, from_str_fn(parse_bytes))]
    m: [u8; 32],
    /// base point
    #[argh(positional, from_str_fn(parse_bytes))]
    u: Option<[u8; 32]>,
}

fn main() {
    let opts: Opts = argh::from_env();

    let x = x25519(
        &opts.m,
        opts.u.as_ref().unwrap_or(Curve25519::BASE_POINT_BYTES),
    );

    for byte in x {
        print!("{byte:02x}");
    }
    println!();
}
