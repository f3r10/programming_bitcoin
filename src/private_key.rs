use num_bigint::{BigInt, RandBigInt};

use crate::{signature::Signature, utils, PointWrapper, S256Point, G, N};

#[derive(Debug)]
pub struct PrivateKey {
    pub secret: BigInt,
    pub point: S256Point,
}

impl PrivateKey {
    pub fn new(secret: BigInt) -> Self {
        let point = secret.clone() * G.to_owned();
        let point = S256Point { point };
        PrivateKey { secret, point }
    }

    pub fn hex(self) -> String {
        format!("{:#064x}", self.secret)
    }

    pub fn sign(&self, z: BigInt, ks: Option<BigInt>) -> Signature {
        let mut rng = rand::thread_rng();
        //TODO DANGER this is just for now, it has to be changed later
        let k = match ks {
            Some(v) => v,
            None => rng.gen_bigint_range(&BigInt::from(0), &N),
        };
        let r = match k.clone() * G.to_owned() {
            PointWrapper::Point {
                x,
                y: _,
                a: _,
                b: _,
            } => x.num,
            PointWrapper::Inf => panic!("R point should not be point to infity"),
        };
        let k_inv = k.modpow(&(N.to_owned() - 2), &N);
        let mut s = ((z + r.clone() * self.secret.clone()) * k_inv).modpow(&BigInt::from(1), &N);
        if s > N.to_owned() / 2 {
            s = N.to_owned() - s
        }
        Signature::new(r, s)
    }

    pub fn wif(self, compressed: Option<bool>, testnet: Option<bool>) -> String {
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
}

#[cfg(test)]
mod secp256k1_private_key_tests {
    use num_bigint::BigInt;

    use crate::private_key::PrivateKey;

    #[test]
    fn s256_private_key_wif() {
        assert_eq!(
            PrivateKey::new(BigInt::from(5003)).wif(Some(true), Some(true)),
            "cMahea7zqjxrtgAbB7LSGbcQUr1uX1ojuat9jZodMN8rFTv2sfUK"
        );
        assert_eq!(
            PrivateKey::new(BigInt::from(2021).pow(5)).wif(Some(false), Some(true)),
            "91avARGdfge8E4tZfYLoxeJ5sGBdNJQH4kvjpWAxgzczjbCwxic"
        );
        assert_eq!(
            PrivateKey::new(BigInt::parse_bytes(b"54321deadbeef", 16).unwrap())
                .wif(Some(true), Some(false)),
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgiuQJv1h8Ytr2S53a"
        );
    }
}
