use ark_ff::{Fp256, Fp448, MontBackend, MontConfig, PrimeField};

#[derive(MontConfig)]
#[modulus = "57896044618658097711785492504343953926634992332820282019728792003956564819949"]
#[generator = "2"]
pub struct Field25519Config;
pub type Field25519 = Fp256<MontBackend<Field25519Config, 4>>;
pub type BigInt25519 = <Field25519 as PrimeField>::BigInt;

#[derive(MontConfig)]
#[modulus = "72683872429560689054932380788800453435364136068731806028149019918061232816673\
             0772686396383698676545930088884461843637361053498018365439"]
#[generator = "2"]
pub struct Field448Config;
pub type Field448 = Fp448<MontBackend<Field448Config, 7>>;
pub type BigInt448 = <Field448 as PrimeField>::BigInt;
