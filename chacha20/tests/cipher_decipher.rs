use std::io::Read;

use chacha20::u96;

const SUNSCREEN: &[u8] = include_bytes!("sunscreen.txt");
const KEYFILE: &[u8; 32] = include_bytes!("keyfile");
const NONCE: u96 = (
    u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
    u32::from_le_bytes([0x00, 0x00, 0x00, 0x4a]),
    u32::from_le_bytes([0x00, 0x00, 0x00, 0x00]),
);
const CIPHERTEXT: &[u8] = include_bytes!("ciphertext.bin");

#[test]
fn cipher() {
    let mut output = Vec::with_capacity(CIPHERTEXT.len());

    let mut cipher = chacha20::cipher(KEYFILE, NONCE, SUNSCREEN);
    cipher.read_to_end(&mut output).unwrap();

    assert_eq!(&output, CIPHERTEXT);
}

#[test]
fn decipher() {
    let mut output = Vec::with_capacity(SUNSCREEN.len());

    let mut decipher = chacha20::cipher(KEYFILE, NONCE, CIPHERTEXT);
    decipher.read_to_end(&mut output).unwrap();

    assert_eq!(&output, SUNSCREEN);
}
