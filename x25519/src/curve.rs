use core::hint::black_box;

use ark_ff::{BigInteger, Field as _, PrimeField};

#[allow(unused)]
#[inline(never)]
fn noop() {
    // function used to insert "noop" calls into generated assembly
    // useful to figure out where stuff is with `cargo asm`
    core::hint::black_box(())
}

// implement the swap on pointers, not values
fn bigint_cswap<T: PrimeField>(swap: bool, a: &mut T::BigInt, b: &mut T::BigInt) {
    let mask = black_box(swap as u64).wrapping_neg();

    let mut dummy = T::ZERO.into_bigint();
    let n = dummy.as_ref().len();
    for i in 0..n {
        dummy.as_mut()[i] = mask & black_box(a.as_ref()[i] ^ b.as_ref()[i]);
    }

    for i in 0..n {
        a.as_mut()[i] ^= dummy.as_ref()[i];
        b.as_mut()[i] ^= dummy.as_ref()[i];
    }
}

fn field_cswap<T: PrimeField>(swap: bool, a: &mut T, b: &mut T) {
    let mut x = a.into_bigint();
    let mut y = b.into_bigint();

    bigint_cswap::<T>(swap, &mut x, &mut y);

    // SAFETY: x and y are always field elements
    // (since they were obtained with "into_bigint")
    unsafe {
        *a = T::from_bigint(x).unwrap_unchecked();
        *b = T::from_bigint(y).unwrap_unchecked();
    }
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

    fn ladder(
        k: <Self::Field as PrimeField>::BigInt,
        p: (Self::Field, Self::Field),
    ) -> Self::Field {
        let mut x0 = (Self::Field::ONE, Self::Field::ZERO);
        let mut x1 = p;

        let mut ki1 = false;
        for i in (0..Self::TOTAL_BITS).rev() {
            let ki = k.get_bit(i);
            cswap(ki1 ^ ki, &mut x0, &mut x1);
            ki1 = ki;

            (x0, x1) = (Self::xdbl(x0), Self::xadd(x0, x1, p));
        }
        cswap(ki1, &mut x0, &mut x1);
        x0.0 / x0.1
    }
}
