use std::{fmt::Display, ops::Mul};

use finite_field::FiniteField;
use num_bigint::BigInt;
use once_cell::sync::Lazy;
use signature::Signature;

pub mod finite_field;
pub mod finite_field_point;
pub mod private_key;
pub mod real_numbers_point;
pub mod signature;
pub mod utils;

#[derive(Debug, Clone, Copy)]
pub enum PointWrapper<A> {
    Inf,
    Point { x: A, y: A, a: A, b: A },
}

#[derive(Debug, Clone)]
pub struct S256Point {
    point: PointWrapper<FiniteField>,
}
#[derive(Debug, Clone)]
pub struct S256Field {
    field: FiniteField,
}

impl S256Field {
    pub fn new(num: BigInt) -> S256Field {
        S256Field {
            field: FiniteField::new_big_int(num, P.to_owned()),
        }
    }

    pub fn sqrt(self) -> Self {
        let new_field = self.field.pow((P.to_owned() + 1) / 4);
        S256Field { field: new_field }
    }
}

impl Display for S256Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#064x}", self.field.num)
    }
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

impl S256Point {
    pub fn new(x: S256Field, y: S256Field) -> S256Point {
        let a = FiniteField::new_big_int(BigInt::from(0), x.field.clone().prime);
        let b = FiniteField::new_big_int(BigInt::from(7), x.field.clone().prime);
        S256Point {
            point: PointWrapper::new(x.field, y.field, a, b),
        }
    }
    pub fn parse(sec_bin: &[u8]) -> Self {
        if sec_bin[0] == 4 {
            let x_parsed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sec_bin[1..33]);
            let y_parsed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sec_bin[33..65]);
            let x = S256Field::new(x_parsed);
            let y = S256Field::new(y_parsed);
            S256Point::new(x, y)
        } else {
            let is_even = sec_bin[0] == 2;
            let x_parsed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sec_bin[1..]);
            let x = S256Field::new(x_parsed);
            let b = S256Field::new(BigInt::from(7));
            let alpha = x.field.pow(BigInt::from(3)) + b.field;
            let alpha = S256Field { field: alpha };
            let beta = alpha.sqrt();
            if beta.clone().field.num.pow(2) == BigInt::from(0) {
                let even_beta = beta.clone();
                let odd_beta = S256Field::new(P.to_owned() - beta.clone().field.num);
                if is_even {
                    S256Point::new(x, even_beta)
                } else {
                    S256Point::new(x, odd_beta)
                }
            } else {
                let even_beta = S256Field::new(P.to_owned() - beta.clone().field.num);
                let odd_beta = beta.clone();
                if is_even {
                    S256Point::new(x, even_beta)
                } else {
                    S256Point::new(x, odd_beta)
                }
            }
        }
    }

    pub fn verify(self, z: BigInt, sig: Signature) -> bool {
        let n_2: BigInt = N.to_owned() - 2;
        let s_inv = sig.s.modpow(&n_2, &N);
        let u = (z * s_inv.clone()).modpow(&BigInt::from(1), &N);
        let v = (sig.r.clone() * s_inv.clone()).modpow(&BigInt::from(1), &N);
        let total = u * G.to_owned() + v * self;
        match total {
            PointWrapper::Inf => false,
            PointWrapper::Point {
                x,
                y: _,
                a: _,
                b: _,
            } => x.num == sig.r,
        }
    }

    pub fn sec(self, compressed: Option<bool>) -> String {
        match self.point {
            PointWrapper::Inf => panic!("Public point can not be point to infinity"),
            PointWrapper::Point { x, y, a: _, b: _ } => {
                if compressed.unwrap_or(true) {
                    if y.num.modpow(&BigInt::from(1), &BigInt::from(2)) == BigInt::from(0) {
                        let marker = &b"\x02"[0..1];
                        let x = &x.num.to_bytes_be().1.to_vec()[0..32];
                        hex::encode(&([marker, x].concat()))
                    } else {
                        let marker = &b"\x03"[0..1];
                        let x = &x.num.to_bytes_be().1.to_vec()[0..32];
                        hex::encode(&([marker, x].concat()))
                    }
                } else {
                    let marker = &b"\x04"[0..1];
                    let x = &x.num.to_bytes_be().1.to_vec()[0..32];
                    let y = &y.num.to_bytes_be().1.to_vec()[0..32];
                    let res = [marker, x, y];
                    let res = res.concat();
                    hex::encode(&res)
                }
            }
        }
    }
}

impl Mul<S256Point> for BigInt {
    type Output = PointWrapper<FiniteField>;

    fn mul(self, rhs: S256Point) -> Self::Output {
        let n: BigInt = BigInt::parse_bytes(
            b"fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();
        let coef = self.modpow(&BigInt::from(1), &n);
        coef * rhs.point
    }
}

#[cfg(test)]
mod secp256k1_tests {

    use hex_literal::hex;
    use num_bigint::BigInt;
    use sha2::{Digest, Sha256};

    use crate::{
        private_key::PrivateKey, signature::Signature, PointWrapper, S256Field, S256Point, G, N,
    };

    #[test]
    fn s256_point_test() {
        assert_eq!(PointWrapper::new_inf(), N.to_owned() * G.point.clone())
    }

    #[test]
    fn point_verification_test() {
        let z: BigInt = BigInt::parse_bytes(
            b"bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423",
            16,
        )
        .unwrap();
        let r: BigInt = BigInt::parse_bytes(
            b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .unwrap();
        let s: BigInt = BigInt::parse_bytes(
            b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .unwrap();
        let px: BigInt = BigInt::parse_bytes(
            b"04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574",
            16,
        )
        .unwrap();
        let py: BigInt = BigInt::parse_bytes(
            b"82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4",
            16,
        )
        .unwrap();
        let point = S256Point::new(S256Field::new(px), S256Field::new(py));
        let sig = Signature::new(r, s);
        assert!(point.verify(z, sig))
    }
    //TODO Add a negative point verification

    #[test]
    fn point_sing_test() {
        let sha256_z = Sha256::digest(Sha256::digest(b"Programming Bitcoin!"));
        let e = BigInt::from(12345);
        let z = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sha256_z);
        let p = PrivateKey::new(e);
        let (public_x, public_y) = match p.point.clone().point {
            PointWrapper::Inf => panic!("public key should not be point to infinity"),
            PointWrapper::Point { x, y, a: _, b: _ } => (x, y),
        };
        let sig = p.sign(z.clone(), Some(BigInt::from(1234567890)));
        assert_eq!(
            public_x.num.to_bytes_be().1,
            hex!("f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")
        );
        assert_eq!(
            public_y.num.to_bytes_be().1,
            hex!("0eba29d0f0c5408ed681984dc525982abefccd9f7ff01dd26da4999cf3f6a295")
        );
        assert_eq!(
            z.to_bytes_be().1,
            hex!("969f6056aa26f7d2795fd013fe88868d09c9f6aed96965016e1936ae47060d48")
        );
        assert_eq!(
            sig.r.to_bytes_be().1,
            hex!("2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22")
        );
        assert_eq!(
            sig.s.to_bytes_be().1,
            hex!("1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a")
        );
        assert!(p.point.clone().verify(z, sig))
    }

    #[test]
    fn test_256point_uncompressed_sec() {
        assert_eq!(PrivateKey::new(BigInt::from(5000)).point.sec(Some(false)), "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10");
        assert_eq!(PrivateKey::new(BigInt::from(2018).pow(5)).point.sec(Some(false)), "04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06");
        assert_eq!(PrivateKey::new(BigInt::parse_bytes(b"deadbeef12345", 16).unwrap()).point.sec(Some(false)), "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121");
    }

    #[test]
    fn test_256point_compressed_sec() {
        assert_eq!(
            PrivateKey::new(BigInt::from(5001)).point.sec(Some(true)),
            "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1"
        );
        assert_eq!(
            PrivateKey::new(BigInt::from(2019).pow(5))
                .point
                .sec(Some(true)),
            "02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701"
        );
        assert_eq!(
            PrivateKey::new(BigInt::parse_bytes(b"deadbeef54321", 16).unwrap())
                .point
                .sec(Some(true)),
            "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690"
        );
    }

    #[test]
    fn test_s256point_parse_point_sec_bytes() {
        let p_uncompressed_bytes = hex!("04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10");
        assert_eq!(
            PrivateKey::new(BigInt::from(5000)).point.point,
            S256Point::parse(&p_uncompressed_bytes).point
        );
        let p_compressed_bytes =
            hex!("0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1");
        assert_eq!(
            PrivateKey::new(BigInt::from(5001)).point.point,
            S256Point::parse(&p_compressed_bytes).point
        );
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
