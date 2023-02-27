use num_bigint::{BigInt, RandBigInt};

use crate::{signature::Signature, PointWrapper, S256Point, G, N};

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
}
