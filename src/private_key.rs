use crypto::{hmac, mac::Mac, sha2::Sha256};
use num_bigint::BigInt;

use crate::{
    signature::{Signature, SignatureHash},
    utils, PointWrapper, S256Point, G, N,
};

#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub secret: BigInt,
    pub point: S256Point,
}

use anyhow::{bail, Result};
pub struct PrivateKeySecret(BigInt);

impl AsRef<BigInt> for PrivateKeySecret {
    fn as_ref(&self) -> &BigInt {
        &self.0
    }
}

impl PrivateKey {
    pub fn new(secret: &PrivateKeySecret) -> Result<Self> {
        let g = match G.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get G"),
        };
        let point = secret.as_ref() * g;
        let point = S256Point { point };
        Ok(PrivateKey {
            secret: secret.as_ref().clone(),
            point,
        })
    }

    pub fn hex(&self) -> String {
        format!("{:#064x}", self.secret)
    }

    pub fn sign(&self, z: &SignatureHash, ks: Option<BigInt>) -> Result<Signature> {
        //TODO DANGER Some(ks) it just for test purposes
        let k = match ks {
            Some(v) => v,
            None => self.deterministic_k(z)?,
        };
        let n = match N.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get N"),
        };
        let g = match G.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get G"),
        };
        let r = match k.clone() * g {
            PointWrapper::Point {
                x,
                y: _,
                a: _,
                b: _,
            } => x.num,
            PointWrapper::Inf => bail!("R point should not be point to infity"),
        };
        let k_inv = k.modpow(&(n.clone() - 2), &n);
        let mut s =
            ((z.as_ref() + r.clone() * self.secret.clone()) * k_inv).modpow(&BigInt::from(1), &n);
        if s > n.clone() / 2 {
            s = n - s
        }
        Ok(Signature::new(r, s))
    }

    pub fn deterministic_k(&self, z: &SignatureHash) -> Result<BigInt> {
        let mut k = vec![0_u8; 32];
        let mut v = vec![1_u8; 32];
        let mut z = z.as_ref().clone();
        let n = match N.as_ref() {
            Ok(it) => it,
            Err(_) => bail!("unable to get N"),
        };
        if z > n.clone() {
            z -= n.clone()
        }
        let z_bytes = utils::int_to_big_endian(&z, 32)?;
        let secret_bytes = utils::int_to_big_endian(&self.secret, 32)?;
        let s256 = Sha256::new();
        let mut kmac = hmac::Hmac::new(s256, &k[..]);
        kmac.input(&[&v[..], &[0_u8], &secret_bytes, &z_bytes].concat());
        kmac.raw_result(&mut k);
        let mut vmac = hmac::Hmac::new(s256, &k[..]);
        vmac.input(&v);
        vmac.raw_result(&mut v);
        let mut kmac = hmac::Hmac::new(s256, &k[..]);
        kmac.input(&[&v[..], &[1_u8], &secret_bytes, &z_bytes].concat());
        kmac.raw_result(&mut k);
        let mut vmac = hmac::Hmac::new(s256, &k[..]);
        vmac.input(&v);
        vmac.raw_result(&mut v);
        let mut candidate: BigInt;
        loop {
            let mut vmac = hmac::Hmac::new(s256, &k[..]);
            vmac.input(&v);
            vmac.raw_result(&mut v);
            candidate = BigInt::from_bytes_be(num_bigint::Sign::Plus, &v);
            if candidate >= BigInt::from(1) && candidate < n.clone() {
                break;
            }
            let mut kmac = hmac::Hmac::new(s256, &k[..]);
            kmac.input(&[&v[..], &[0_u8]].concat());
            kmac.raw_result(&mut k);
            let mut vmac = hmac::Hmac::new(s256, &k[..]);
            vmac.input(&v);
            vmac.raw_result(&mut v);
        }
        return Ok(candidate);
    }

    pub fn wif(self, compressed: Option<bool>, testnet: Option<bool>) -> Result<String> {
        let secret_bytes = self.secret.to_bytes_be().1.to_vec();
        let len = secret_bytes.len();
        let to_fill = 32 - len;
        let z = vec![0x0; to_fill]; // Vec::with_capacity(to_fill);
        let final_bytes = &[z, secret_bytes].concat()[0..32];
        let prefix: &[u8];
        let suffix: &[u8];
        if testnet.unwrap_or(false) {
            prefix = b"\xef";
        } else {
            prefix = b"\x80";
        }
        if compressed.unwrap_or(true) {
            suffix = b"\x01";
        } else {
            suffix = b"";
        }
        let ad = [prefix, final_bytes, suffix].concat();
        utils::encode_base58_checksum(&ad)
    }

    pub fn generate_secret(passphrase: &str) -> PrivateKeySecret {
        PrivateKeySecret(utils::little_endian_to_int(&utils::hash256(
            passphrase.as_bytes(),
        )))
    }

    pub fn generate_simple_secret(num: BigInt) -> PrivateKeySecret {
        PrivateKeySecret(num)
    }
}

#[cfg(test)]
mod secp256k1_private_key_tests {
    use num_bigint::BigInt;

    use crate::private_key::{PrivateKey, PrivateKeySecret};
    use anyhow::{Context, Result};

    #[test]
    fn s256_private_key_wif() -> Result<()> {
        assert_eq!(
            PrivateKey::new(&PrivateKeySecret(BigInt::from(5003)))?.wif(Some(true), Some(true))?,
            "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK"
        );
        assert_eq!(
            PrivateKey::new(&PrivateKeySecret(BigInt::from(2021).pow(5)))?
                .wif(Some(false), Some(true))?,
            "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic"
        );
        assert_eq!(
            PrivateKey::new(&PrivateKeySecret(
                BigInt::parse_bytes(b"54321deadbeef", 16)
                    .context("unable to parse hex to bigint")?
            ))?
            .wif(Some(true), Some(false))?,
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a"
        );
        Ok(())
    }
}
