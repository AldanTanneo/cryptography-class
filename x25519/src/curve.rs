use core::hint::black_box;

use ark_ff::{BigInteger, Field as _, PrimeField};

fn bigint_cswap<T: PrimeField>(swap: bool, a: &mut T::BigInt, b: &mut T::BigInt) {
    let mask = black_box(swap as u64).wrapping_neg();

    let mut dummy = T::BigInt::default();
    let n = T::BigInt::NUM_LIMBS;
    for i in 0..n {
        dummy.as_mut()[i] = mask & black_box(a.as_ref()[i] ^ b.as_ref()[i]);
    }

    for i in 0..n {
        a.as_mut()[i] ^= dummy.as_ref()[i];
        b.as_mut()[i] ^= dummy.as_ref()[i];
    }
}

fn field_cswap<T: PrimeField>(swap: bool, a: &mut T, b: &mut T)
where
    T: Copy,
    T::BigInt: Copy,
{
    assert_eq!(core::mem::size_of::<T>(), core::mem::size_of::<T::BigInt>());
    assert_eq!(T::BigInt::NUM_LIMBS * 8, core::mem::size_of::<T::BigInt>());

    // SAFETY: PrimeField is a wrapper around a specially handled BigInt.
    // BigInt derefs as [u64], BigInt and Field are Copy, and we assert that BigInt
    // and Field are the same size.
    // Thus the state is valid after swapping the [u64] composing the BigInt.
    let x = unsafe { core::mem::transmute::<&mut T, &mut T::BigInt>(a) };
    let y = unsafe { core::mem::transmute::<&mut T, &mut T::BigInt>(b) };

    bigint_cswap::<T>(swap, x, y);
}

fn cswap<T: PrimeField>(swap: bool, a: &mut (T, T), b: &mut (T, T)) {
    field_cswap(swap, &mut a.0, &mut b.0);
    field_cswap(swap, &mut a.1, &mut b.1);
}

pub trait Curve {
    type Field: PrimeField;

    const A: u64;

    #[doc(hidden)]
    const A24: u64 = (Self::A + 2) / 4;
    #[doc(hidden)]
    const NUM_LIMBS: usize = <Self::Field as PrimeField>::BigInt::NUM_LIMBS;
    #[doc(hidden)]
    const TOTAL_BITS: usize = Self::NUM_LIMBS * 64;

    fn xadd(
        (xp, zp): (Self::Field, Self::Field),
        (xq, zq): (Self::Field, Self::Field),
        (x_minus, z_minus): (Self::Field, Self::Field),
    ) -> (Self::Field, Self::Field) {
        let v0 = xp + zp;
        let mut v1 = xq - zq;
        v1 *= v0;

        let v0 = xp - zp;
        let mut v2 = xq + zq;
        v2 *= v0;

        let mut v3 = v1 + v2;
        v3.square_in_place();

        let mut v4 = v1 - v2;
        v4.square_in_place();

        let x_plus = z_minus * v3;
        let z_plus = x_minus * v4;

        (x_plus, z_plus)
    }

    fn xdbl((xp, zp): (Self::Field, Self::Field)) -> (Self::Field, Self::Field) {
        // hopefully this compiles down to a constant...
        let a24 = Self::Field::from(Self::A24);

        let mut v1 = xp + zp;
        v1.square_in_place();

        let mut v2 = xp - zp;
        v2.square_in_place();

        let x2p = v1 * v2;

        let v1 = v1 - v2;
        let v3 = a24 * v1;
        let v3 = v3 + v2;

        let z2p = v1 * v3;

        (x2p, z2p)
    }

    fn full_ladder(
        k: impl AsRef<[u64]>,
        p: (Self::Field, Self::Field),
    ) -> [(Self::Field, Self::Field); 2] {
        let mut x0 = (Self::Field::ONE, Self::Field::ZERO);
        let mut x1 = p;

        let mut ki1 = false;

        for ki in ark_ff::BitIteratorBE::new(k) {
            cswap(ki1 ^ ki, &mut x0, &mut x1);
            ki1 = ki;

            (x0, x1) = (Self::xdbl(x0), Self::xadd(x0, x1, p));
        }
        cswap(ki1, &mut x0, &mut x1);
        [x0, x1]
    }

    fn ladder(
        k: <Self::Field as PrimeField>::BigInt,
        p: (Self::Field, Self::Field),
    ) -> Self::Field {
        let [x0, _] = Self::full_ladder(k, p);
        x0.0 / x0.1
    }

    fn recover_y_coordinate(
        (x_p, y_p): (Self::Field, Self::Field),
        (x_q, z_q): (Self::Field, Self::Field),
        (x_pq, z_pq): (Self::Field, Self::Field),
    ) -> (Self::Field, Self::Field) {
        let v1 = x_p * z_q;
        let v2 = x_q + v1;
        let mut v3 = x_q - v1;

        v3.square_in_place();
        v3 *= x_pq;

        let v1 = Self::Field::from(Self::A * 2) * z_q;

        let v2 = v2 + v1;
        let v4 = x_p * x_q;
        let v4 = v4 + z_q;
        let v2 = v2 * v4;
        let v1 = v1 * z_q;
        let v2 = v2 - v1;
        let v2 = v2 * z_pq;

        let y = v2 - v3;

        let v1 = y_p.double(); // B = 1
        let v1 = v1 * z_q;
        let v1 = v1 * z_pq;

        let x = v1 * x_q;
        let z = v1 * z_q;

        (x / z, y / z)
    }
}
