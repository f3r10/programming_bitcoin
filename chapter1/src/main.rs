use std::{fmt, ops::{Add, Sub, Rem, Mul}};

use num_bigint::{ToBigInt, BigInt};


#[derive(Debug, Clone, Eq)]
struct FiniteField {
    num: BigInt,
    prime: BigInt,
    
}
impl FiniteField {
    pub fn new(num: BigInt, prime: BigInt) -> Self {
        if num >= prime {
            panic!("Num {} not in field range 0 to {}", num, prime);
        }
        FiniteField { num, prime}
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

fn main() {
    let a = FiniteField::new(7.to_bigint().unwrap(), 13.to_bigint().unwrap());
    let b = FiniteField::new(12.to_bigint().unwrap(), 13.to_bigint().unwrap());
    let c = FiniteField::new(6.to_bigint().unwrap(), 13.to_bigint().unwrap());
    let d = FiniteField::new(8.to_bigint().unwrap(), 13.to_bigint().unwrap());
    let e = FiniteField::new(6.to_bigint().unwrap(), 13.to_bigint().unwrap());

    println!("{}", a == b);
    println!("{}", a == a);
    println!("{}", a != b);
    println!("------Exercise 2----------");
    println!("{}", (44 + 33)%57);
    println!("{}", (((9 - 29) % 57) + 57) % 57);
    println!("{}", (((7 - 12) % 13) + 13) % 13);
    println!("{}", (17 + 42)%57);
    println!("{}", (((52 - 30 - 38) % 57) + 57 )%57);
    println!("------Exercise 3----------");
    println!("{}", a.clone() + b.clone() == c);
    println!("{}", a.clone() - b.clone() == d);
    println!("------Exercise 4----------");
    println!("{}", (95_i32 * 45_i32 * 32_i32).rem_euclid(97));
    println!("{}", (17_i32 * 13_i32 * 19_i32 * 44_i32).rem_euclid(97));
    // The result of the operation was so large that I got an "attempt to multiply with overflow" that it is 
    // why I had to use the num_bigint crate
    println!("{}", (12_i32.to_bigint().unwrap().pow(7) * 77_i32.to_bigint().unwrap().pow(49)).rem(97));
    println!("------Exercise 5----------");
    let k:Vec<i32> = [1, 3, 7, 13, 18].to_vec();
    let started_set: Vec<i32> = (0..19).collect();
    println!("{:?}", started_set);
    for i in k  {
        let mut res: Vec<i32> = Vec::new();
        for j in 0..19 {
            res.push((i * j).rem_euclid(19))
        }
        print!("{:?}", res);
        print!("->");
        res.sort();
        println!("{:?}", res);
        
    } 
    println!("------Exercise 6----------");
    println!("{}", a.clone() * b.clone() == e);

}
