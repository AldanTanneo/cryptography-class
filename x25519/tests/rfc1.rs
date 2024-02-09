use io_utils::hex;
use x25519::{x25519, x448};

#[test]
fn x25519_1() {
    const K: [u8; 32] = hex!("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    const U: [u8; 32] = hex!("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");

    const OUTPUT: [u8; 32] =
        hex!("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");

    let ladder = x25519(&K, &U);
    assert_eq!(&ladder, &OUTPUT);
}

#[test]
fn x25519_2() {
    const K: [u8; 32] = hex!("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    const U: [u8; 32] = hex!("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");

    const OUTPUT: [u8; 32] =
        hex!("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");

    let ladder = x25519(&K, &U);
    assert_eq!(&ladder, &OUTPUT);
}

#[test]
fn x448_1() {
    const K: [u8; 56] = hex!(
        "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121\
         700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3"
    );
    const U: [u8; 56] = hex!(
        "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9\
         814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086"
    );

    const OUTPUT: [u8; 56] = hex!(
        "ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239f\
         e14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f"
    );

    let ladder = x448(&K, &U);
    assert_eq!(&ladder, &OUTPUT);
}

#[test]
fn x448_2() {
    const K: [u8; 56] = hex!(
        "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c5\
         38345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f"
    );
    const U: [u8; 56] = hex!(
        "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b\
         165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db"
    );

    const OUTPUT: [u8; 56] = hex!(
        "884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7\
         ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d"
    );

    let ladder = x448(&K, &U);
    assert_eq!(&ladder, &OUTPUT);
}
