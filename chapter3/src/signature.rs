use std::fmt::Display;

use num_bigint::BigInt;

pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Signature {
    pub fn new(r: BigInt, s: BigInt) -> Self {
        Signature { r, s }
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({:x}, {:x})", self.r, self.s)
    }
}
