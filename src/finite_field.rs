use std::{
    fmt,
    ops::{Add, Div, Mul, Sub},
};

use anyhow::{bail, Result};
use num_bigint::BigInt;

#[derive(Debug, Clone, Eq)]
pub struct FiniteField {
    pub num: BigInt,
    pub prime: BigInt,
}

impl FiniteField {
    pub fn new(num: i32, prime: i32) -> Result<Self> {
        if num >= prime {
            bail!("Num {} not in field range 0 to {}", num, prime);
        }
        Ok(FiniteField {
            num: BigInt::from(num),
            prime: BigInt::from(prime),
        })
    }

    pub fn new_big_int(num: BigInt, prime: BigInt) -> Result<Self> {
        if num >= prime {
            bail!("Num {} not in field range 0 to {}", num, prime);
        }
        Ok(FiniteField { num, prime })
    }

    pub fn pow(&self, exponent: BigInt) -> Self {
        // forzing a negative expontent into positive using module arithmetic the exponent should be between {0, p-2}
        let positive_exponent =
            exponent.modpow(&BigInt::from(1), &(self.prime.clone() - BigInt::from(1)));
        let num = self.num.modpow(&positive_exponent, &self.prime);
        FiniteField {
            num,
            prime: self.prime.clone(),
        }
    }
}

impl PartialEq for FiniteField {
    fn eq(&self, other: &Self) -> bool {
        self.num == other.num && self.prime == other.prime
    }

    fn ne(&self, other: &Self) -> bool {
        !(self == other)
    }
}
impl fmt::Display for FiniteField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement_{}({})", self.prime, self.num)
    }
}

impl Add for FiniteField {
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot add two numbers is different Fields");
        }
        let num = (self.num + other.num).modpow(&BigInt::from(1), &self.prime);
        FiniteField {
            num,
            prime: self.prime,
        }
    }
}

impl Sub for FiniteField {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot sub two numbers is different Fields");
        }
        let num = (self.num - other.num).modpow(&BigInt::from(1), &self.prime);
        FiniteField {
            num,
            prime: self.prime,
        }
    }
}

impl Mul for FiniteField {
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot multiply two numbers is different Fields");
        }
        let num = (self.num * other.num).modpow(&BigInt::from(1), &self.prime);
        FiniteField {
            num,
            prime: self.prime,
        }
    }
}

impl Div for FiniteField {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot multiply two numbers is different Fields");
        }
        let exp = self.prime.clone() - BigInt::from(2);
        let num = (self.num * other.num.modpow(&exp, &self.prime.clone()))
            .modpow(&BigInt::from(1), &self.prime);
        FiniteField {
            num,
            prime: self.prime,
        }
    }
}
