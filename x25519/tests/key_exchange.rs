use io_utils::hex;
use x25519::{x25519, x448, Curve25519, Curve448};

#[test]
fn x25519_key_exchange() {
    const ALICE_PRIVATE: [u8; 32] =
        hex!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const ALICE_PUBLIC: [u8; 32] =
        hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    const BOB_PRIVATE: [u8; 32] =
        hex!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    const BOB_PUBLIC: [u8; 32] =
        hex!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const SHARED_KEY: [u8; 32] =
        hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let alice_public_computed = x25519(&ALICE_PRIVATE, Curve25519::BASE_POINT_BYTES);
    assert_eq!(&alice_public_computed, &ALICE_PUBLIC);

    let bob_public_computed = x25519(&BOB_PRIVATE, Curve25519::BASE_POINT_BYTES);
    assert_eq!(&bob_public_computed, &BOB_PUBLIC);

    let shared_key_computed_alice = x25519(&ALICE_PRIVATE, &bob_public_computed);
    let shared_key_computed_bob = x25519(&BOB_PRIVATE, &alice_public_computed);
    assert_eq!(&shared_key_computed_alice, &SHARED_KEY);
    assert_eq!(&shared_key_computed_bob, &SHARED_KEY);
}

#[test]
fn x448_key_exchange() {
    const ALICE_PRIVATE: [u8; 56] = hex!(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
         d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
    );
    const ALICE_PUBLIC: [u8; 56] = hex!(
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
         22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
    );
    const BOB_PRIVATE: [u8; 56] = hex!(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
         6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
    );
    const BOB_PUBLIC: [u8; 56] = hex!(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
         27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
    );
    const SHARED_KEY: [u8; 56] = hex!(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
         b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
    );

    let alice_public_computed = x448(&ALICE_PRIVATE, Curve448::BASE_POINT_BYTES);
    assert_eq!(&alice_public_computed, &ALICE_PUBLIC);

    let bob_public_computed = x448(&BOB_PRIVATE, Curve448::BASE_POINT_BYTES);
    assert_eq!(&bob_public_computed, &BOB_PUBLIC);

    let shared_key_computed_alice = x448(&ALICE_PRIVATE, &bob_public_computed);
    let shared_key_computed_bob = x448(&BOB_PRIVATE, &alice_public_computed);
    assert_eq!(&shared_key_computed_alice, &SHARED_KEY);
    assert_eq!(&shared_key_computed_bob, &SHARED_KEY);
}
