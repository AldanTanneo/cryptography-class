use aead_chacha_poly::{check_tag, compute_tag};
use chacha20::u96;
use std::io::Read;

const SUNSCREEN: &[u8] = include_bytes!("sunscreen.txt");
const ADFILE: &[u8] = include_bytes!("adfile");
const KEYFILE: &[u8; 32] = include_bytes!("keyfile");
const NONCE: u96 = (
    u32::from_le_bytes([0x07, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x40, 0x41, 0x42, 0x43]),
    u32::from_le_bytes([0x44, 0x45, 0x46, 0x47]),
);
const CIPHERTEXT: &[u8] = include_bytes!("ciphertext.bin");
const TAG: u128 = u128::from_le_bytes([
    0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
]);

#[test]
fn wrap() {
    let mut output = Vec::with_capacity(CIPHERTEXT.len());

    let tag = compute_tag(KEYFILE, NONCE, ADFILE, SUNSCREEN, &mut output).unwrap();

    assert_eq!(tag, TAG);
    assert_eq!(output.as_slice(), CIPHERTEXT);
}

#[test]
fn unwrap() {
    let mut output = Vec::with_capacity(SUNSCREEN.len());

    let tag = check_tag(KEYFILE, NONCE, ADFILE, CIPHERTEXT).unwrap();

    let mut decipher = chacha20::cipher(KEYFILE, NONCE, CIPHERTEXT);
    decipher.read_to_end(&mut output).unwrap();

    assert_eq!(tag, TAG);
    assert_eq!(output.as_slice(), SUNSCREEN);
}
