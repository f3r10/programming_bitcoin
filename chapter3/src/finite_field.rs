use std::{fmt, ops::{Add, Sub, Mul, Div}};

use num_bigint::{ToBigInt, BigInt};


#[derive(Debug, Clone, Eq)]
pub struct FiniteField {
    num: BigInt,
    pub prime: BigInt,
    
}

impl FiniteField {
    pub fn new(num: i32, prime: i32) -> Self {
        if num >= prime {
            panic!("Num {} not in field range 0 to {}", num, prime);
        }
        FiniteField { num: num.to_bigint().unwrap(), prime: prime.to_bigint().unwrap()}
    }

    pub fn pow(&self, exponent: BigInt) -> Self {
        // forzing a negative expontent into positive using module arithmetic the exponent should be between {0, p-2}
        let positive_exponent = exponent.modpow(&1_i32.to_bigint().unwrap(), &(self.prime.clone() - 1.to_bigint().unwrap()));
        let num = self.num.modpow(&positive_exponent, &self.prime);
        FiniteField { num, prime: self.prime.clone()}

    }
    
}

impl PartialEq for FiniteField{
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

impl Add for FiniteField{
    type Output = Self;

    fn add(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot add two numbers is different Fields");
        }
        let num  = (self.num + other.num).modpow(&1_i32.to_bigint().unwrap(), &self.prime);
        FiniteField {num, prime : self.prime}
    }
}

impl Sub for FiniteField {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot sub two numbers is different Fields");
        }
        let num  = (self.num - other.num).modpow(&1_i32.to_bigint().unwrap(), &self.prime);
        FiniteField {num, prime : self.prime}

    }
}

impl Mul for FiniteField{
    type Output = Self;

    fn mul(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot multiply two numbers is different Fields");
        }
        let num = (self.num * other.num).modpow(&1_i32.to_bigint().unwrap(), &self.prime);
        FiniteField {num, prime : self.prime}
    }
}

impl Div for FiniteField {
    type Output = Self;

    fn div(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot multiply two numbers is different Fields");
        }
        let exp = self.prime.clone() - 2.to_bigint().unwrap(); 
        let num = (self.num * other.num.pow(exp.try_into().unwrap())).modpow(&1_i32.to_bigint().unwrap(), &self.prime);
        FiniteField {num, prime: self.prime}
    }
}
