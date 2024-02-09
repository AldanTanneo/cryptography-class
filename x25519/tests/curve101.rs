/*
prime: p = 101

curve constant: A = 49 in GF(p) (so (A+2)/4 = 38 mod 101)

curve: E: Y^2*Z = X*(X^2 + A*X*Z + Z^2)

base point: P = (X:Y:Z) = (2:2:1)

Check these (on (X,Z)-coordinates only):

- [2]P = (70:81:1)
- [3]P = (59:61:1)
- [77]P = (8:90:1)
*/

use ark_ff::{prelude::*, BigInt, Fp64, MontBackend, MontConfig, MontFp};
use x25519::curve::Curve;

#[derive(MontConfig)]
#[modulus = "101"]
#[generator = "2"]
struct FqConfig;
type Fq = Fp64<MontBackend<FqConfig, 1>>;

struct Curve101;

impl Curve for Curve101 {
    type Field = Fq;
    const A: u64 = 49;
    const A24: u64 = 38;
}

const BASE_POINT: Fq = MontFp!("2");

#[test]
fn p2() {
    println!("{}", Curve101::A24);
    let kp = Curve101::ladder(BigInt!("2"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("70"));
}

#[test]
fn p3() {
    println!("{}", Curve101::A24);
    let kp = Curve101::ladder(BigInt!("3"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("59"));
}

#[test]
fn p77() {
    println!("{}", Curve101::A24);
    let kp = Curve101::ladder(BigInt!("77"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("8"));
}
