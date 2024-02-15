//! Prime field F\[p\] where p is the order of Curve25519

use ark_ff::{Fp256, MontBackend, MontConfig};

#[derive(MontConfig)]
#[modulus = "7237005577332262213973186563042994240857116359379907606001950938285454250989"]
#[generator = "2"]
pub struct FieldOrderConfig;
pub type FieldOrder = Fp256<MontBackend<FieldOrderConfig, 4>>;
