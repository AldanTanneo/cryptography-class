use x25519::{x25519, x448, Curve25519, Curve448};

macro_rules! hex32 {
    ($str:literal) => {
        io_utils::parse_hex::<32>($str).unwrap()
    };
}

macro_rules! hex56 {
    ($str:literal) => {
        io_utils::parse_hex::<56>($str).unwrap()
    };
}

#[test]
fn x25519_key_exchange() {
    let alice_private = hex32!("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let alice_public = hex32!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    let bob_private = hex32!("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let bob_public = hex32!("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    let shared_key = hex32!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    let alice_public_computed = x25519(&alice_private, Curve25519::BASE_POINT_BYTES);
    assert_eq!(&alice_public_computed, &alice_public);

    let bob_public_computed = x25519(&bob_private, Curve25519::BASE_POINT_BYTES);
    assert_eq!(&bob_public_computed, &bob_public);

    let shared_key_computed_alice = x25519(&alice_private, &bob_public_computed);
    let shared_key_computed_bob = x25519(&bob_private, &alice_public_computed);
    assert_eq!(&shared_key_computed_alice, &shared_key);
    assert_eq!(&shared_key_computed_bob, &shared_key);
}

#[test]
fn x448_key_exchange() {
    let alice_private = hex56!(
        "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28d\
         d9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b"
    );
    let alice_public = hex56!(
        "9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c\
         22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0"
    );
    let bob_private = hex56!(
        "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d\
         6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d"
    );
    let bob_public = hex56!(
        "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b430\
         27d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609"
    );
    let shared_key = hex56!(
        "07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282b\
         b60c0b56fd2464c335543936521c24403085d59a449a5037514a879d"
    );

    let alice_public_computed = x448(&alice_private, Curve448::BASE_POINT_BYTES);
    assert_eq!(&alice_public_computed, &alice_public);

    let bob_public_computed = x448(&bob_private, Curve448::BASE_POINT_BYTES);
    assert_eq!(&bob_public_computed, &bob_public);

    let shared_key_computed_alice = x448(&alice_private, &bob_public_computed);
    let shared_key_computed_bob = x448(&bob_private, &alice_public_computed);
    assert_eq!(&shared_key_computed_alice, &shared_key);
    assert_eq!(&shared_key_computed_bob, &shared_key);
}
