use std::{fmt, ops::{Add, Sub}};


#[derive(Debug, Clone, Copy)]
struct FiniteField {
    num: i32,
    prime: i32,
    
}
impl FiniteField {
    pub fn new(num: i32, prime: i32) -> Self {
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
        let num = (((self.num + other.num) % self.prime.clone()) + self.prime) % self.prime;
        FiniteField {num, prime : self.prime}
    }
}

impl Sub for FiniteField {
    type Output = Self;

    fn sub(self, other: Self) -> Self::Output {
        if self.prime != other.prime {
            panic!("Cannot sub two numbers is different Fields");
        }
        // let num  = (self.num - other.num).rem_euclid(self.prime);
        let num = (((self.num - other.num) % self.prime) + self.prime) % self.prime;
        FiniteField {num, prime : self.prime}

    }
}

fn main() {
    let a = FiniteField::new(7, 13);
    let b = FiniteField::new(12, 13);
    let c = FiniteField::new(6, 13);
    let d = FiniteField::new(8, 13);

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
    println!("{}", a + b == c);
    println!("{}", a - b == d);

}
