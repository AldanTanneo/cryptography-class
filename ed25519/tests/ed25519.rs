mod vectors;

use ark_ff::MontFp;
use ed25519::{Fp, BASE_POINT};
use std::io::Cursor;
use vectors::{ENCODING_25519, VECTORS_25519};

#[test]
fn birational_map() {
    let p: (Fp, Fp) = (
        MontFp!("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
        MontFp!("46316835694926478169428394003475163141307993866256225615783033603165251855960"),
    );
    let p1 = ed25519::to_montgomery(p.0, p.1);
    assert_eq!(p1, BASE_POINT, "base point (montgomery)");
    let p2 = ed25519::to_edwards(BASE_POINT.0, BASE_POINT.1);
    assert_eq!(p2, p, "base point (edwards)");

    for ((x, y), _) in ENCODING_25519.iter() {
        let (u, v) = ed25519::to_montgomery(*x, *y);
        let (x1, y1) = ed25519::to_edwards(u, v);

        assert_eq!(&x1, x, "wrong x");
        assert_eq!(&y1, y, "wrong y");
    }
}

#[test]
fn point_encoding() {
    for &((x, y), ref encoding) in ENCODING_25519 {
        let encoded = ed25519::encode_point(x, y);

        assert_eq!(&encoded, encoding);
    }
}

#[test]
fn point_decoding() {
    for &(ref point, encoding) in ENCODING_25519 {
        let decoded = ed25519::decode_point(encoding).unwrap();

        assert_eq!(&decoded, point);
    }
}

#[test]
fn public_key_generation() {
    for (keys, _, _) in VECTORS_25519 {
        let generated_public = ed25519::derive_key(keys.private);
        assert_eq!(&generated_public, keys)
    }
}

#[test]
fn message_signing() {
    for (keys, msg, sig) in VECTORS_25519 {
        let sig_computed = ed25519::sign(keys, Cursor::new(msg)).unwrap();

        assert_eq!(&sig_computed, sig);
    }
}

#[test]
fn add_edwards() {
    for &(p, _) in ENCODING_25519 {
        let p_p = ed25519::add_edwards(p, p);
        let p_2 = ed25519::mul_edwards([2], p);
        assert_eq!(p_p, p_2);

        let p_p_p = ed25519::add_edwards(p_p, p);
        let p_3 = ed25519::mul_edwards([3], p);
        assert_eq!(p_p_p, p_3)
    }
}

#[test]
fn signature_verification() {
    for (keys, msg, sig) in VECTORS_25519 {
        let verify = ed25519::verify(&keys.public, sig, *msg).unwrap();

        assert!(verify, "keys: {keys:?}");
    }
}
