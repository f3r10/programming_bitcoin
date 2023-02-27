use std::fmt::Display;

use num_bigint::BigInt;

pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Signature {
    pub fn new(r: BigInt, s: BigInt) -> Self {
        Signature { r, s }
    }

    pub fn der(&self) -> Vec<u8> {
        let mut result: Vec<u8>= Vec::new();
        {
            let mut rbin = &self.r.to_bytes_be().1.to_vec()[0..32];
            let mut v = Vec::new();
            v.extend_from_slice(rbin.strip_prefix(b"\x00").unwrap_or(rbin));
            if rbin[0] & 0x80 == 1{
                let marker = &b"\x00"[0..1];
                v.clear();
                v.extend_from_slice(&[marker, rbin.clone()].concat()[..]);
            }
            rbin = v.as_slice();
            result.push(0x2);
            //extend_from_slice(&vec![&b"\x02"[0..1], rbin.len().to_be_bytes().last().unwrap(), rbin].concat());
            result.push(*rbin.len().to_be_bytes().last().unwrap());
            result.extend_from_slice(rbin);
        }
        {
            let mut sbin  = &self.s.to_bytes_be().1.to_vec()[0..32];
            let mut v = Vec::new();
            v.extend_from_slice(sbin.strip_prefix(b"\x00").unwrap_or(sbin));
            println!("--------{}", sbin[0]);
            if sbin[0] & 0x80 != 0{
                println!("-------------");
                let marker = &b"\x00"[0..1];
                v.clear();
                v.extend_from_slice(&[marker, sbin.clone()].concat()[..]);
            }
            sbin = v.as_slice();
            result.push(2);//.extend_from_slice(&vec![&b"\x02"[0..1], &sbin.len().to_be_bytes(), sbin].concat());
            result.push(*sbin.len().to_be_bytes().last().unwrap());
            result.extend_from_slice(sbin)
        }
        let mut final_r: Vec<u8> = Vec::new();
        final_r.push(0x30);
        final_r.push(*result.len().to_be_bytes().last().unwrap());
        final_r.extend_from_slice(&result);
        final_r
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({:x}, {:x})", self.r, self.s)
    }
}

#[cfg(test)]
mod signature_tests {
    use num_bigint::BigInt;

    use super::Signature;

    #[test]

    fn der_test() {
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
        let sig = Signature::new(r, s);
        assert_eq!(hex::encode(sig.der()), "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec")
    }

}
