use std::fmt;


#[derive(Debug)]
struct FiniteField {
    num: u32,
    prime: u32,
    
}
impl FiniteField {
    pub fn new(num: u32, prime: u32) -> Self {
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
}
impl fmt::Display for FiniteField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement_{}({})", self.num, self.prime)
    }
}
fn main() {
    let a = FiniteField::new(7, 13);
    let b = FiniteField::new(6, 13);
    println!("{}", a == b);
    println!("{}", a == a);
}
