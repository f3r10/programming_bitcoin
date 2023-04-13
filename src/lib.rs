#![feature(seek_stream_len)]
use num_bigint::BigInt;
use once_cell::sync::Lazy;
use s256_field::S256Field;
use s256_point::S256Point;

pub mod finite_field;
pub mod finite_field_point;
pub mod op;
pub mod private_key;
pub mod real_numbers_point;
pub mod s256_field;
pub mod s256_point;
pub mod script;
pub mod signature;
pub mod tx;
pub mod tx_fetcher;
pub mod utils;
pub mod block;

#[derive(Debug, Clone, Copy)]
pub enum PointWrapper<A> {
    Inf,
    Point { x: A, y: A, a: A, b: A },
}

pub static P: Lazy<BigInt> =
    Lazy::new(|| BigInt::from(2).pow(256) - BigInt::from(2).pow(32) - BigInt::from(977));

pub static N: Lazy<BigInt> = Lazy::new(|| {
    BigInt::parse_bytes(
        b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
        16,
    )
    .unwrap()
});

pub static G: Lazy<S256Point> = Lazy::new(|| {
    let x: BigInt = BigInt::parse_bytes(
        b"79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        16,
    )
    .unwrap();
    let y: BigInt = BigInt::parse_bytes(
        b"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
        16,
    )
    .unwrap();
    S256Point::new(S256Field::new(x), S256Field::new(y))
});

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
