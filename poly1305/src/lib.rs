use crypto_bigint::{impl_modulus, modular::constant_mod::Residue, Encoding, U192};
use io_utils::{parse_hex, ReadExt};
use std::io::{self, Read};

impl_modulus!(
    P1305,
    U192,
    "0000000000000003fffffffffffffffffffffffffffffffb"
);

type Fp = Residue<P1305, 3>;

fn clamp(r: u128) -> u128 {
    const MASK: u128 = 0xFFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF;
    r & MASK
}

pub fn poly1305(mut data: impl Read, key: &[u8; 32]) -> io::Result<u128> {
    let r = u128::from_le_bytes(key[..16].try_into().unwrap());
    let s = u128::from_le_bytes(key[16..].try_into().unwrap());

    let r = clamp(r);
    let r = Fp::new(&U192::from(r));

    let mut acc = Fp::ZERO;
    let mut buf;

    loop {
        buf = [0; 24];
        let x = data.read_all(&mut buf[..16])?;
        if x == 0 {
            break;
        }
        buf[x] = 1;
        let n = Fp::new(&U192::from_le_bytes(buf));
        acc = (acc + n) * r;
    }
    acc += Fp::new(&U192::from(s));

    let bytes = acc.retrieve().to_le_bytes()[..16].try_into().unwrap();
    Ok(u128::from_le_bytes(bytes))
}

pub fn parse_key(arg: &str) -> Result<[u8; 32], String> {
    parse_hex::<32>(arg).ok_or_else(|| "expected 32-bytes hex string".into())
}

pub fn parse_tag(arg: &str) -> Result<u128, String> {
    parse_hex::<16>(arg)
        .map(u128::from_le_bytes)
        .ok_or_else(|| "expected 16-bytes hex string".into())
}

#[cfg(test)]
#[test]
fn poly1305_tag() {
    const TEXT: &[u8] = b"Cryptographic Forum Research Group";

    let key = io_utils::hex!("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b");
    let tag = parse_tag("a8061dc1305136c6c22b8baf0c0127a9").unwrap();

    let computed_tag = poly1305(TEXT, &key).unwrap();

    assert_eq!(tag, computed_tag);
}
