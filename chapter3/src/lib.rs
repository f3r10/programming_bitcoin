use std::{ops::Mul, fmt::Display};

use finite_field::FiniteField;
use num_bigint::BigInt;

pub mod real_numbers_point;
pub mod finite_field;
pub mod finite_field_point;

#[derive(Debug, Clone, Copy)]
pub enum PointWrapper<A> {
    Inf,
    Point { x: A, y: A, a: A, b: A },
}


pub struct S256Point { point: PointWrapper<FiniteField> }
pub struct S256Field { field: FiniteField }

impl S256Field {
    pub fn new (num: BigInt) -> S256Field {
        let p: BigInt = BigInt::from(2).pow(256) - BigInt::from(2).pow(32) - BigInt::from(977);
        S256Field { field: FiniteField::new_big_int(num, p) }
    }
    
}

impl Display for S256Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.field.num)
    }
}

impl S256Point {
    pub fn new(x: S256Field, y: S256Field) -> S256Point {
        let a = FiniteField::new_big_int(BigInt::from(0), x.field.clone().prime);
        let b = FiniteField::new_big_int(BigInt::from(7), x.field.clone().prime);
        S256Point{point: PointWrapper::new(x.field, y.field, a, b)}
    }

}

impl Mul<S256Point> for BigInt{
    type Output = PointWrapper<FiniteField>;

    fn mul(self, rhs: S256Point) -> Self::Output {
        let n: BigInt = BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
        let coef = self.modpow(&BigInt::from(1), &n);
        coef * rhs.point
    }
}

#[cfg(test)]
mod secp256k1_tests {
    use num_bigint::BigInt;

    use crate::{PointWrapper, S256Point, S256Field};

    #[test]
    fn s256_point_test() {
        let n: BigInt = BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
        let x: BigInt = BigInt::parse_bytes(b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16).unwrap();
        let y: BigInt = BigInt::parse_bytes(b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16).unwrap();
        let g = S256Point::new(S256Field::new(x), S256Field::new(y));
        assert_eq!(PointWrapper::new_inf(), n*g)
    }
}

//TODO check if this abstraction approach would be better
// trait EllipticCurvePointOperations<A>: Add<PointWrapper<A>> + Sized{
//     type Output;
//     fn new(x: A, y: A) -> <Self as EllipticCurvePointOperations<A>>::Output;
// }
// impl<T> Add for dyn EllipticCurvePointOperations<T> {
//     type Output = FiniteField;
//
//     fn add(self, rhs: Self) -> Self::Output {
//         todo!()
//     }
// }

// impl EllipticCurvePointOperations<FiniteField> for PointWrapper<FiniteField> {
//     type Output = PointWrapper<FiniteField>;
//
//     fn new(x: FiniteField, y: FiniteField) -> <Self as EllipticCurvePointOperations<FiniteField>>::Output {
//         PointWrapper::Point { x: x.clone(), y: y.clone(), a: x.clone() + y.clone(), b: x.clone() + y.clone() }
//     }
// }

