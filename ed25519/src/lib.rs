pub mod field;

use ark_ff::{BigInt, BigInteger, Field, MontFp, PrimeField};
use io_utils::hexfmt;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha512};
use std::{
    fmt::Debug,
    io::{self, Read, Seek, SeekFrom},
};

use field::FieldOrder as Fr;
pub use x25519::field::Field25519 as Fp;
use x25519::{curve::Curve, field::BigInt25519 as Int, Curve25519};

/// (P - 5) / 8
const PM5D8: Int =
    BigInt!("7237005577332262213973186563042994240829374041602535252466099000494570602493");
/// 2^((P-1) / 4)
const TWO_POW_PM1D4: Fp =
    MontFp!("19681161376707505956807079304988542015446066515923890162744021073123829784752");
/// Square root of -486664 mod P
const SQRT: Fp =
    MontFp!("51042569399160536130206135233146329284152202253034631822681833788666877215207");
/// d of edwards25519 in RFC7748 (i.e., -121665/121666)
const D: Fp =
    MontFp!("37095705934669439343138083508754565189542113879843219016388785533085940283555");
/// Curve25519 base point (in Montgomery coordinates)
pub const BASE_POINT: (Fp, Fp) = (
    MontFp!("9"),
    MontFp!("14781619447589544791020593568409986887264606134616475288964881837755586237401"),
);

pub fn encode_point(x: Fp, y: Fp) -> [u8; 32] {
    let mut res: [u8; 32] = y.into_bigint().to_bytes_le().try_into().unwrap();

    let sign_bit = x.into_bigint().get_bit(0) as u8;
    res[31] |= sign_bit << 7;

    res
}

pub fn decode_point(mut data: [u8; 32]) -> Option<(Fp, Fp)> {
    let x_0 = (data[31] >> 7) != 0; // store MSB
    data[31] &= 0b0111_1111; // clear MSB
    let y = Fp::from_le_bytes_mod_order(&data);

    let y2 = y.square();
    let u = y2 - Fp::ONE;
    let v = D * y2 + Fp::ONE;
    let x = u * v.pow([3]) * (u * v.pow([7])).pow(PM5D8);

    let vx2: Fp = v * x.square();
    let x = if vx2 == u {
        x
    } else if vx2 == -u {
        x * TWO_POW_PM1D4
    } else {
        return None;
    };

    if x == Fp::ZERO && x_0 {
        return None;
    }

    let xmod2 = x.into_bigint().is_odd();

    if x_0 != xmod2 {
        Some((-x, y))
    } else {
        Some((x, y))
    }
}

pub fn to_montgomery(x: Fp, y: Fp) -> (Fp, Fp) {
    let u = (Fp::ONE + y) / (Fp::ONE - y);
    let v = SQRT * u / x;

    (u, v)
}

pub fn to_edwards(u: Fp, v: Fp) -> (Fp, Fp) {
    let x = SQRT * u / v;
    let y = (u - Fp::ONE) / (u + Fp::ONE);

    (x, y)
}

pub fn mul_base(k: impl AsRef<[u64]>) -> (Fp, Fp) {
    let [q, pq] = Curve25519::full_ladder(k, (BASE_POINT.0, Fp::ONE));
    let (u, v) = Curve25519::recover_y_coordinate(BASE_POINT, q, pq);
    to_edwards(u, v)
}

pub fn mul_edwards(k: impl AsRef<[u64]>, p: (Fp, Fp)) -> (Fp, Fp) {
    let montgomery = to_montgomery(p.0, p.1);
    let [q, pq] = Curve25519::full_ladder(k, (montgomery.0, Fp::ONE));
    let (u, v) = Curve25519::recover_y_coordinate(montgomery, q, pq);
    to_edwards(u, v)
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Keys {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_struct("Keys");
        dbg.field("public", &hexfmt(&self.public));

        if cfg!(debug_assertions) {
            dbg.field("private", &hexfmt(&self.private)).finish()
        } else {
            dbg.finish_non_exhaustive()
        }
    }
}

pub fn derive_key(private: [u8; 32]) -> Keys {
    let hash: [u8; 32] = Sha512::digest(&private)[..32].try_into().unwrap();
    let hash_num = Curve25519::decode_scalar(&hash);
    let (x, y) = mul_base(hash_num);
    let public = encode_point(x, y);

    Keys { private, public }
}

pub fn keygen(rng: &mut (impl CryptoRng + Rng)) -> Keys {
    let private = rng.gen();
    derive_key(private)
}

fn hash_reader<H: Digest>(hasher: &mut H, mut data: impl Read) -> io::Result<()> {
    loop {
        let mut buf = [0; 1024]; // process the data as 1kB chunks
        let n = data.read(&mut buf)?;
        if n == 0 {
            break Ok(());
        }
        hasher.update(&buf[..n]);
    }
}

pub fn sign(keys: &Keys, mut data: impl Read + Seek) -> io::Result<[u8; 64]> {
    // second half of private key hash as prefix
    let p_hash = Sha512::digest(&keys.private);
    let s = Curve25519::decode_scalar(&p_hash[..32]);
    let prefix: &[u8; 32] = p_hash[32..].try_into().unwrap();

    let mut r_hash = Sha512::new_with_prefix(prefix);
    hash_reader(&mut r_hash, &mut data)?;

    let r = Fr::from_le_bytes_mod_order(&r_hash.finalize());
    let rb = mul_base(r.into_bigint());
    let r_string = encode_point(rb.0, rb.1);

    let mut k_hash = Sha512::new_with_prefix(&r_string).chain_update(&keys.public);
    data.seek(SeekFrom::Start(0))?;
    hash_reader(&mut k_hash, data)?;
    let k = Fr::from_le_bytes_mod_order(&k_hash.finalize());

    let s_string: Fr = r + Fr::from_le_bytes_mod_order(&s.to_bytes_le()) * k;

    let mut signature = [0; 64];
    signature[..32].copy_from_slice(&r_string);
    signature[32..].copy_from_slice(&s_string.into_bigint().to_bytes_le());

    Ok(signature)
}

// not constant time, only used in the verification
pub fn add_edwards((x1, y1): (Fp, Fp), (x2, y2): (Fp, Fp)) -> (Fp, Fp) {
    let y1y2 = y1 * y2;
    let x1x2 = x1 * x2;
    let dx1x2y1y2 = D * x1x2 * y1y2;

    (
        (x1 * y2 + x2 * y1) / (Fp::ONE + dx1x2y1y2),
        (y1y2 + x1x2) / (Fp::ONE - dx1x2y1y2),
    )
}

pub fn verify(key: &[u8; 32], sig: &[u8; 64], data: impl Read) -> io::Result<bool> {
    let r_string: &[u8; 32] = sig[..32].try_into().unwrap();
    let s_string: &[u8; 32] = sig[32..].try_into().unwrap();

    let Some(a) = decode_point(*key) else {
        return Ok(false); // the key is invalid
    };
    let Some(r) = decode_point(*r_string) else {
        return Ok(false); // R is an invalid point
    };
    let Some(s) = Fr::from_random_bytes(s_string) else {
        return Ok(false); // s >= L (no malleability)
    };

    let mut hash = Sha512::new_with_prefix(r_string).chain_update(key);
    hash_reader(&mut hash, data)?;
    let k = Fr::from_le_bytes_mod_order(&hash.finalize());

    let s_b = mul_base(s.into_bigint());
    let mk_a = mul_edwards((-k).into_bigint(), a);
    let expected_r = add_edwards(s_b, mk_a);

    Ok(r == expected_r)
}
