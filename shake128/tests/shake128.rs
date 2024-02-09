use io_utils::hex;
use shake128::shake128;

#[test]
fn empty_message() {
    let digest = hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");

    assert!(shake128(std::iter::empty())
        .take(32)
        .zip(digest)
        .all(|(a, b)| a == b));
}

#[test]
fn short_text() {
    let msg = include_bytes!("short-text.txt");

    let digest = hex!("ba27cc6a7a85887a1888c0678c05cd7fcf619ed791dce41b7e1a81c280bec8bb");

    assert!(shake128(msg.iter().copied())
        .take(32)
        .zip(digest)
        .all(|(a, b)| a == b));
}

#[test]
fn short_binary() {
    let msg = include_bytes!("short-binary.bin");

    let digest = hex!("9b171ccf7ff6b9478ce02a54a5a558dde55febc70e12f0ed402567639e404b74");

    assert!(shake128(msg.iter().copied())
        .take(32)
        .zip(digest)
        .all(|(a, b)| a == b));
}
