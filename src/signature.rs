use std::{
    fmt::Display,
    io::{Read, Seek},
};

use byteorder::{BigEndian, ByteOrder};
use num_bigint::BigInt;

use crate::utils;

pub struct SignatureHash(BigInt);

impl AsRef<BigInt> for SignatureHash {
    fn as_ref(&self) -> &BigInt {
        &self.0
    }
}

pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Signature {
    pub fn new(r: BigInt, s: BigInt) -> Self {
        Signature { r, s }
    }

    pub fn parse<R: Read + Seek>(stream: &mut R) -> Self {
        let mut compound_buffer = [0; 1];
        stream.read_exact(&mut compound_buffer).unwrap();
        let compound = compound_buffer[0];
        if compound != 0x30 {
            panic!("Bad signature")
        }
        let mut length_buffer = [0; 1];
        stream.read_exact(&mut length_buffer).unwrap();
        let length = (BigEndian::read_u32(&[0, 0, 0, length_buffer[0]]) + 2) as u32;
        // let len = stream.stream_len().unwrap();
        let mut marker_buffer = [0; 1];
        stream.read_exact(&mut marker_buffer).unwrap();
        if marker_buffer[0] != 0x02 {
            panic!("Bad signature")
        }
        let mut rlength_buffer = [0; 1];
        stream.read_exact(&mut rlength_buffer).unwrap();
        let rlenght = BigEndian::read_u32(&[0, 0, 0, rlength_buffer[0]]);
        let mut r_buffer = vec![0; rlenght.try_into().unwrap()];
        stream.read_exact(&mut r_buffer).unwrap();
        let r = BigInt::from_signed_bytes_be(&r_buffer);
        let mut marker_buffer = [0; 1];
        stream.read_exact(&mut marker_buffer).unwrap();
        if marker_buffer[0] != 0x02 {
            panic!("Bad signature")
        }
        let mut slength_buffer = [0; 1];
        stream.read_exact(&mut slength_buffer).unwrap();
        let slenght = BigEndian::read_u32(&[0, 0, 0, slength_buffer[0]]);

        // 4 -> marker + len
        // 2 -> compound and total len
        if slenght + rlenght + 4 + 2 != length {
            panic!("Bad signature length")
        }

        let mut s_buffer = vec![0; slenght.try_into().unwrap()];
        stream.read_exact(&mut s_buffer).unwrap();
        let s = BigInt::from_signed_bytes_be(&s_buffer);
        Signature { r, s }
    }

    pub fn der(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        {
            let mut rbin = &self.r.to_bytes_be().1.to_vec()[0..32];
            let mut v = Vec::new();
            v.extend_from_slice(rbin.strip_prefix(b"\x00").unwrap_or(rbin));
            if rbin[0] & 0x80 == 1 {
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
            let mut sbin = &self.s.to_bytes_be().1.to_vec()[0..32];
            let mut v = Vec::new();
            v.extend_from_slice(sbin.strip_prefix(b"\x00").unwrap_or(sbin));
            if sbin[0] & 0x80 != 0 {
                let marker = &b"\x00"[0..1];
                v.clear();
                v.extend_from_slice(&[marker, sbin.clone()].concat()[..]);
            }
            sbin = v.as_slice();
            result.push(2); //.extend_from_slice(&vec![&b"\x02"[0..1], &sbin.len().to_be_bytes(), sbin].concat());
            result.push(*sbin.len().to_be_bytes().last().unwrap());
            result.extend_from_slice(sbin)
        }
        let mut final_r: Vec<u8> = Vec::new();
        final_r.push(0x30);
        final_r.push(*result.len().to_be_bytes().last().unwrap());
        final_r.extend_from_slice(&result);
        final_r
    }

    pub fn signature_hash(passphrase: &str) -> SignatureHash {
        SignatureHash(BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &utils::hash256(passphrase.as_bytes()),
        ))
    }

    pub fn signature_hash_from_hex(passphrase: &str) -> SignatureHash {
        SignatureHash(BigInt::parse_bytes(passphrase.as_bytes(), 16).unwrap())
    }

    pub fn signature_hash_from_vec(passphrase: Vec<u8>) -> SignatureHash {
        SignatureHash(BigInt::from_signed_bytes_be(&passphrase))
    }
}

impl Display for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Signature({:x}, {:x})", self.r, self.s)
    }
}

#[cfg(test)]
mod signature_tests {
    use std::io::Cursor;

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

    #[test]
    fn test_parse_signature() {
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
        let sig = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let sig_encode = hex::decode(sig).unwrap();
        let mut cursor_sig = Cursor::new(sig_encode);
        let sig_parsed = Signature::parse(&mut cursor_sig);
        assert_eq!(sig_parsed.r, r);
        assert_eq!(sig_parsed.s, s);
    }
}
