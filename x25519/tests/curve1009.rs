/*
prime: p = 1009

curve constant: A = 682 in GF(p) (so (A+2)/4 = 171 mod 1009)

curve: E: Y^2*Z = X*(X^2 + A*X*Z + Z^2)

base point: P = (X:Y:Z) = (7:207:1)

Check these (on (X,Z)-coordinates only):

- [2]P = (284:3:1)
- [3]P = (759:824:1)
- [5]P = (1000:308:1)
- [34]P = (286:675:1)
- [104]P = (810:312:1)
- [947]P = (755:481:1)
*/

use ark_ff::{prelude::*, BigInt, Fp64, MontBackend, MontConfig, MontFp};
use x25519::curve::Curve;

#[derive(MontConfig)]
#[modulus = "1009"]
#[generator = "2"]
struct FqConfig;
type Fq = Fp64<MontBackend<FqConfig, 1>>;

struct Curve1009;

impl Curve for Curve1009 {
    type Field = Fq;
    const A: u64 = 682;
}

const BASE_POINT: Fq = MontFp!("7");

#[test]
fn p2() {
    println!("{}", Curve1009::A24);
    let kp = Curve1009::ladder(BigInt!("2"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("284"));
}

#[test]
fn p3() {
    println!("{}", Curve1009::A24);
    let kp = Curve1009::ladder(BigInt!("3"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("759"));
}

#[test]
fn p5() {
    println!("{}", Curve1009::A24);
    let kp = Curve1009::ladder(BigInt!("5"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("1000"));
}

#[test]
fn p34() {
    println!("{}", Curve1009::A24);
    let kp = Curve1009::ladder(BigInt!("34"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("286"));
}

#[test]
fn p104() {
    println!("{}", Curve1009::A24);
    let kp = Curve1009::ladder(BigInt!("104"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("810"));
}

#[test]
fn p947() {
    println!("{}", Curve1009::A24);
    let kp = Curve1009::ladder(BigInt!("947"), (BASE_POINT, Fq::ONE));

    assert_eq!(kp, MontFp!("755"));
}
