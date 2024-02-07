use ark_ff::{BigInteger, Field, MontFp, PrimeField};

use curve::Curve;
use field::{BigInt25519, BigInt448, Field25519, Field448};

pub mod curve;
pub mod field;

pub struct Curve25519;

impl Curve for Curve25519 {
    type Field = Field25519;
    const A: u64 = 486662;
}

impl Curve25519 {
    pub const BASE_POINT: <Self as Curve>::Field = MontFp!("9");
    pub const BASE_POINT_BYTES: &'static [u8; 32] = &[
        0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ];

    pub fn clamp_scalar(mut scalar: BigInt25519) -> BigInt25519 {
        let slice = bytemuck::cast_slice_mut::<_, u8>(scalar.as_mut());

        // on big endian architectures, swap the bytes in each limb
        #[cfg(target_endian = "big")]
        res.as_mut().iter_mut().for_each(|s| *s = s.to_le());

        slice[0] &= 248;
        slice[31] &= 127;
        slice[31] |= 64;

        // on big endian architectures, swap the bytes in each limb (again)
        #[cfg(target_endian = "big")]
        res.as_mut().iter_mut().for_each(|s| *s = s.to_le());

        scalar
    }

    pub fn decode_scalar(data: &[u8]) -> BigInt25519 {
        let mut res = BigInt25519::default();

        let slice = bytemuck::cast_slice_mut::<_, u8>(res.as_mut());
        let n = slice.len();

        assert!(data.len() <= n, "Too much data to fit in scalar.");

        slice[..data.len()].copy_from_slice(data);

        slice[0] &= 248;
        slice[31] &= 127;
        slice[31] |= 64;

        // on big endian architectures, swap the bytes in each limb
        #[cfg(target_endian = "big")]
        res.as_mut().iter_mut().for_each(|s| *s = s.to_le());

        res
    }

    pub fn decode_point(data: &[u8]) -> Field25519 {
        assert!(data.len() <= 32, "Too much data to fit in point.");

        let bytes = &mut [0; 32];
        bytes[..data.len()].copy_from_slice(data);

        bytes[31] &= 0b0111_1111;

        Field25519::from_le_bytes_mod_order(bytes)
    }
}

pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let k = Curve25519::decode_scalar(k);
    let u = Curve25519::decode_point(u);

    let res = Curve25519::ladder(k, (u, Field25519::ONE));

    res.into_bigint().to_bytes_le().try_into().unwrap()
}

pub struct Curve448;

impl Curve for Curve448 {
    type Field = Field448;
    const A: u64 = 156326;
}

impl Curve448 {
    pub const BASE_POINT: <Self as Curve>::Field = MontFp!("5");
    pub const BASE_POINT_BYTES: &'static [u8; 56] = &[
        0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];

    pub fn clamp_scalar(mut scalar: BigInt448) -> BigInt448 {
        let slice = bytemuck::cast_slice_mut::<_, u8>(scalar.as_mut());

        // on big endian architectures, swap the bytes in each limb
        #[cfg(target_endian = "big")]
        res.as_mut().iter_mut().for_each(|s| *s = s.to_le());

        slice[0] &= 252;
        slice[55] |= 128;

        // on big endian architectures, swap the bytes in each limb
        #[cfg(target_endian = "big")]
        res.as_mut().iter_mut().for_each(|s| *s = s.to_le());

        scalar
    }

    pub fn decode_scalar(data: &[u8]) -> BigInt448 {
        let mut res = BigInt448::default();

        let slice = bytemuck::cast_slice_mut::<_, u8>(res.as_mut());
        let n = slice.len();

        assert!(data.len() <= n, "Too much data to fit in scalar.");

        slice[..data.len()].copy_from_slice(data);

        slice[0] &= 252;
        slice[55] |= 128;

        // on big endian architectures, swap the bytes in each limb
        #[cfg(target_endian = "big")]
        res.as_mut().iter_mut().for_each(|s| *s = s.to_le());

        res
    }

    pub fn decode_point(data: &[u8]) -> Field448 {
        assert!(data.len() <= 56, "Too much data to fit in point.");
        Field448::from_le_bytes_mod_order(data)
    }
}

pub fn x448(k: &[u8; 56], u: &[u8; 56]) -> [u8; 56] {
    let k = Curve448::decode_scalar(k);
    let u = Curve448::decode_point(u);

    let res = Curve448::ladder(k, (u, Field448::ONE));

    res.into_bigint().to_bytes_le().try_into().unwrap()
}
