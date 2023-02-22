use std::{ops::Mul, fmt::Display};

use finite_field::FiniteField;
use num_bigint::BigInt;
use once_cell::sync::Lazy;
use signature::Signature;

pub mod real_numbers_point;
pub mod finite_field;
pub mod finite_field_point;
pub mod signature;

#[derive(Debug, Clone, Copy)]
pub enum PointWrapper<A> {
    Inf,
    Point { x: A, y: A, a: A, b: A },
}


#[derive(Debug, Clone)]
pub struct S256Point { point: PointWrapper<FiniteField> }
#[derive(Debug, Clone)]
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

pub static N: Lazy<BigInt> = Lazy::new(|| {
    BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap()
});

pub static G: Lazy<S256Point> = Lazy::new(|| {
    let x: BigInt = BigInt::parse_bytes(b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16).unwrap();
    let y: BigInt = BigInt::parse_bytes(b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16).unwrap();
    S256Point::new(S256Field::new(x), S256Field::new(y))
});

impl S256Point {
    pub fn new(x: S256Field, y: S256Field) -> S256Point {
        let a = FiniteField::new_big_int(BigInt::from(0), x.field.clone().prime);
        let b = FiniteField::new_big_int(BigInt::from(7), x.field.clone().prime);
        S256Point{point: PointWrapper::new(x.field, y.field, a, b)}
    }

    pub fn verify(self, z: BigInt, sig: Signature) -> bool {
        let n_2: BigInt = N.to_owned() - 2;
        let s_inv = sig.s.modpow(&n_2, &N);
        let u = (z * s_inv.clone()).modpow(&BigInt::from(1), &N);
        let v = (sig.r.clone() * s_inv.clone()).modpow(&BigInt::from(1), &N);
        let total = u * G.to_owned() + v * self;
        match total {
            PointWrapper::Inf => false,
            PointWrapper::Point { x, y: _, a: _, b: _ } => x.num == sig.r,
        }
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

    use crate::{PointWrapper, N, G, signature::Signature, S256Point, S256Field};

    #[test]
    fn s256_point_test() {
        assert_eq!(PointWrapper::new_inf(), N.to_owned() * G.point.clone())
    }

    #[test]
    fn point_verification() {
        let z: BigInt = BigInt::parse_bytes(b"bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423", 16).unwrap();
        let r: BigInt = BigInt::parse_bytes(b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6", 16).unwrap();
        let s: BigInt = BigInt::parse_bytes(b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec", 16).unwrap();
        let px: BigInt = BigInt::parse_bytes(b"04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574", 16).unwrap();
        let py: BigInt = BigInt::parse_bytes(b"82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4", 16).unwrap();
        let point = S256Point::new(S256Field::new(px), S256Field::new(py));
        let sig = Signature::new(r, s);
        assert!(point.verify(z, sig))
    }
    //TODO Add a negative point verification
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

