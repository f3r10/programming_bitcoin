use std::ops::Mul;

use num_bigint::BigInt;

use crate::{
    finite_field::FiniteField,
    s256_field::S256Field,
    signature::{Signature, SignatureHash},
    utils, PointWrapper, G, N, P,
};
use anyhow::{bail, Result};

#[derive(Debug, Clone)]
pub struct S256Point {
    pub point: PointWrapper<FiniteField>,
}

impl S256Point {
    pub fn new(x: S256Field, y: S256Field) -> Result<S256Point> {
        let a = FiniteField::new_big_int(BigInt::from(0), x.field.clone().prime)?;
        let b = FiniteField::new_big_int(BigInt::from(7), x.field.clone().prime)?;
        Ok(S256Point {
            point: PointWrapper::new(x.field, y.field, a, b),
        })
    }
    pub fn parse(sec_bin: &[u8]) -> Result<Self> {
        if sec_bin[0] == 4 {
            let x_parsed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sec_bin[1..33]);
            let y_parsed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sec_bin[33..65]);
            let x = S256Field::new(x_parsed)?;
            let y = S256Field::new(y_parsed)?;
            S256Point::new(x, y)
        } else {
            let is_even = sec_bin[0] == 2;
            let x_parsed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &sec_bin[1..]);
            let x = S256Field::new(x_parsed)?;
            let b = S256Field::new(BigInt::from(7))?;
            let alpha = x.field.pow(BigInt::from(3)) + b.field;
            let alpha = S256Field { field: alpha };
            let beta = alpha.sqrt();
            if beta
                .clone()
                .field
                .num
                .modpow(&BigInt::from(1), &BigInt::from(2))
                == BigInt::from(0)
            {
                let even_beta = beta.clone();
                let odd_beta = S256Field::new(P.to_owned() - beta.clone().field.num)?;
                if is_even {
                    S256Point::new(x, even_beta)
                } else {
                    S256Point::new(x, odd_beta)
                }
            } else {
                let even_beta = S256Field::new(P.to_owned() - beta.clone().field.num)?;
                let odd_beta = beta.clone();
                if is_even {
                    S256Point::new(x, even_beta)
                } else {
                    S256Point::new(x, odd_beta)
                }
            }
        }
    }

    pub fn verify(&self, z: &SignatureHash, sig: Signature) -> Result<bool> {
        let n = match N.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get N"),
        };
        let g = match G.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get G"),
        };
        let n_2: BigInt = n - 2;
        let s_inv = sig.s.modpow(&n_2, &n);
        let u = (z.as_ref() * s_inv.clone()).modpow(&BigInt::from(1), &n);
        let v = (sig.r.clone() * s_inv.clone()).modpow(&BigInt::from(1), &n);
        let total = u * g + v * self;
        match total {
            PointWrapper::Inf => Ok(false),
            PointWrapper::Point {
                x,
                y: _,
                a: _,
                b: _,
            } => Ok(x.num == sig.r),
        }
    }

    pub fn sec(&self, compressed: Option<bool>) -> Result<Vec<u8>> {
        match &self.point {
            PointWrapper::Inf => bail!("Public point can not be point to infinity"),
            PointWrapper::Point { x, y, a: _, b: _ } => {
                if compressed.unwrap_or(true) {
                    if y.num.modpow(&BigInt::from(1), &BigInt::from(2)) == BigInt::from(0) {
                        let marker = &b"\x02"[0..1];
                        let x = &x.num.to_bytes_be().1.to_vec()[0..32];
                        Ok([marker, x].concat())
                    } else {
                        let marker = &b"\x03"[0..1];
                        let x = &x.num.to_bytes_be().1.to_vec()[0..32];
                        Ok([marker, x].concat())
                    }
                } else {
                    let marker = &b"\x04"[0..1];
                    let x = &x.num.to_bytes_be().1.to_vec()[0..32];
                    let y = &y.num.to_bytes_be().1.to_vec()[0..32];
                    let res = [marker, x, y];
                    let res = res.concat();
                    Ok(res)
                }
            }
        }
    }

    pub fn hash160(self, compressed: Option<bool>) -> Result<Vec<u8>> {
        let a = self.sec(compressed)?;
        Ok(utils::hash160(&a))
    }

    pub fn address(self, compressed: Option<bool>, testnet: Option<bool>) -> Result<String> {
        let h160 = self.hash160(compressed)?;
        if testnet.unwrap_or(false) {
            let prefix = &b"\x6f"[0..1];
            let ad = &[prefix, &h160].concat()[..];
            utils::encode_base58_checksum(ad)
        } else {
            let prefix = &b"\x00"[0..1];
            let ad = &[prefix, &h160].concat()[..];
            utils::encode_base58_checksum(ad)
        }
    }
}

impl Mul<&S256Point> for BigInt {
    type Output = PointWrapper<FiniteField>;

    fn mul(self, rhs: &S256Point) -> Self::Output {
        let coef = self.modpow(&BigInt::from(1), &N.as_ref().unwrap());
        coef * rhs.point.clone()
    }
}

impl Mul<&S256Point> for &BigInt {
    type Output = PointWrapper<FiniteField>;

    fn mul(self, rhs: &S256Point) -> Self::Output {
        let coef = self.modpow(&BigInt::from(1), &N.as_ref().unwrap());
        coef * rhs.point.clone()
    }
}

#[cfg(test)]
mod secp256k1_point_tests {

    use hex_literal::hex;
    use num_bigint::BigInt;

    use crate::{
        private_key::PrivateKey, signature::Signature, PointWrapper, S256Field, S256Point, G, N,
    };
    use anyhow::{bail, Context, Result};

    #[test]
    fn s256_point_test() -> Result<()> {
        let n = match N.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get N"),
        };
        let g = match G.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get G"),
        };
        assert_eq!(PointWrapper::new_inf(), n.clone() * g.point.clone());
        Ok(())
    }

    #[test]
    fn point_verification_test() -> Result<()> {
        let z = Signature::signature_hash_from_hex(
            "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423",
        )?;
        let r: BigInt = BigInt::parse_bytes(
            b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .context("unable to parse hex to bigint")?;
        let s: BigInt = BigInt::parse_bytes(
            b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .context("unable to parse hex to bigint")?;
        let px: BigInt = BigInt::parse_bytes(
            b"04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574",
            16,
        )
        .context("unable to parse hex to bigint")?;
        let py: BigInt = BigInt::parse_bytes(
            b"82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4",
            16,
        )
        .context("unable to parse hex to bigint")?;
        let point = S256Point::new(S256Field::new(px)?, S256Field::new(py)?)?;
        let sig = Signature::new(r, s);
        assert!(point.verify(&z, sig)?);
        Ok(())
    }
    //TODO Add a negative point verification

    #[test]
    fn point_sing_test() -> Result<()> {
        let passphrase = "Programming Bitcoin!";
        let e = PrivateKey::generate_simple_secret(BigInt::from(12345));
        let z = Signature::signature_hash(passphrase);
        let p = PrivateKey::new(&e)?;
        let (public_x, public_y) = match p.point.clone().point {
            PointWrapper::Inf => bail!("public key should not be point to infinity"),
            PointWrapper::Point { x, y, a: _, b: _ } => (x, y),
        };
        let sig = p.sign(&z, Some(BigInt::from(1234567890)))?;
        assert_eq!(
            public_x.num.to_bytes_be().1,
            hex!("f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f")
        );
        assert_eq!(
            public_y.num.to_bytes_be().1,
            hex!("0eba29d0f0c5408ed681984dc525982abefccd9f7ff01dd26da4999cf3f6a295")
        );
        assert_eq!(
            z.as_ref().to_bytes_be().1,
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
        assert!(p.point.verify(&z, sig)?);
        Ok(())
    }

    #[test]
    fn test_256point_uncompressed_sec() -> Result<()> {
        assert_eq!(hex::encode(PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(5000)))?.point.sec(Some(false))?), "04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10");
        assert_eq!(hex::encode(PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(2018).pow(5)))?.point.sec(Some(false))?), "04027f3da1918455e03c46f659266a1bb5204e959db7364d2f473bdf8f0a13cc9dff87647fd023c13b4a4994f17691895806e1b40b57f4fd22581a4f46851f3b06");
        assert_eq!(hex::encode(PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::parse_bytes(b"deadbeef12345", 16).context("unable parse hex to bigint")?))?.point.sec(Some(false))?), "04d90cd625ee87dd38656dd95cf79f65f60f7273b67d3096e68bd81e4f5342691f842efa762fd59961d0e99803c61edba8b3e3f7dc3a341836f97733aebf987121");
        Ok(())
    }

    #[test]
    fn test_256point_compressed_sec() -> Result<()> {
        assert_eq!(
            hex::encode(
                PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(5001)))?
                    .point
                    .sec(Some(true))?
            ),
            "0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1"
        );
        assert_eq!(
            PrivateKey::new(&PrivateKey::generate_simple_secret(
                BigInt::from(2019).pow(5)
            ))?
            .point
            .sec(Some(true))?,
            hex!("02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701")
        );
        assert_eq!(
            hex::encode(
                PrivateKey::new(&PrivateKey::generate_simple_secret(
                    BigInt::parse_bytes(b"deadbeef54321", 16)
                        .context("unable to parse hex to bigint")?
                ))?
                .point
                .sec(Some(true))?
            ),
            "0296be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690"
        );
        Ok(())
    }

    #[test]
    fn test_s256point_parse_point_sec_bytes() -> Result<()> {
        let p_uncompressed_bytes = hex!("04ffe558e388852f0120e46af2d1b370f85854a8eb0841811ece0e3e03d282d57c315dc72890a4f10a1481c031b03b351b0dc79901ca18a00cf009dbdb157a1d10");
        assert_eq!(
            PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(5000)))?
                .point
                .point,
            S256Point::parse(&p_uncompressed_bytes)?.point
        );
        let p_compressed_bytes =
            hex!("0357a4f368868a8a6d572991e484e664810ff14c05c0fa023275251151fe0e53d1");
        assert_eq!(
            PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(5001)))?
                .point
                .point,
            S256Point::parse(&p_compressed_bytes)?.point
        );
        Ok(())
    }

    #[test]
    fn test_256point_address() -> Result<()> {
        assert_eq!(
            PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(5002)))?
                .point
                .address(Some(false), Some(true))?,
            "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA"
        );
        assert_eq!(
            PrivateKey::new(&PrivateKey::generate_simple_secret(
                BigInt::from(2020).pow(5)
            ))?
            .point
            .address(Some(true), Some(true))?,
            "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH"
        );
        assert_eq!(
            PrivateKey::new(&PrivateKey::generate_simple_secret(
                BigInt::parse_bytes(b"12345deadbeef", 16)
                    .context("unable to parse hex to bigint")?
            ))?
            .point
            .address(Some(true), Some(false))?,
            "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1"
        );
        let passphrase = "jimmy@programmingblockchain.com my secret";
        let priva = PrivateKey::new(&PrivateKey::generate_secret(passphrase))?;
        assert_eq!(
            "mft9LRNtaBNtpkknB8xgm17UvPedZ4ecYL",
            priva.point.address(Some(true), Some(true))?
        );
        Ok(())
    }
}
