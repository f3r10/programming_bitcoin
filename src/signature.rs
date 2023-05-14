use std::{
    fmt::Display,
    io::{Read, Seek},
};

use byteorder::{BigEndian, ByteOrder};
use num_bigint::BigInt;

use crate::utils;
use anyhow::{Context, Result};

pub struct SignatureHash(BigInt);

impl AsRef<BigInt> for SignatureHash {
    fn as_ref(&self) -> &BigInt {
        &self.0
    }
}

#[derive(Clone)]
pub struct Signature {
    pub r: BigInt,
    pub s: BigInt,
}

impl Signature {
    pub fn new(r: BigInt, s: BigInt) -> Self {
        Signature { r, s }
    }

    pub fn parse<R: Read + Seek>(stream: &mut R) -> Result<Self> {
        let mut compound_buffer = [0; 1];
        stream.read_exact(&mut compound_buffer)?;
        let compound = compound_buffer[0];
        if compound != 0x30 {
            panic!("Bad signature")
        }
        let mut length_buffer = [0; 1];
        stream.read_exact(&mut length_buffer)?;
        let length = (BigEndian::read_u32(&[0, 0, 0, length_buffer[0]]) + 2) as u32;
        let mut marker_buffer = [0; 1];
        stream.read_exact(&mut marker_buffer)?;
        if marker_buffer[0] != 0x02 {
            panic!("Bad signature")
        }
        let mut rlength_buffer = [0; 1];
        stream.read_exact(&mut rlength_buffer)?;
        let rlenght = BigEndian::read_u32(&[0, 0, 0, rlength_buffer[0]]);
        let mut r_buffer = vec![0; rlenght.try_into()?];
        stream.read_exact(&mut r_buffer)?;
        let r = BigInt::from_bytes_be(num_bigint::Sign::Plus, &r_buffer);
        let mut marker_buffer = [0; 1];
        stream.read_exact(&mut marker_buffer)?;
        if marker_buffer[0] != 0x02 {
            panic!("Bad signature")
        }
        let mut slength_buffer = [0; 1];
        stream.read_exact(&mut slength_buffer)?;
        let slenght = BigEndian::read_u32(&[0, 0, 0, slength_buffer[0]]);

        // 4 -> marker + len
        // 2 -> compound and total len
        if slenght + rlenght + 4 + 2 != length {
            panic!("Bad signature length")
        }

        let mut s_buffer = vec![0; slenght.try_into()?];
        stream.read_exact(&mut s_buffer)?;
        let s = BigInt::from_bytes_be(num_bigint::Sign::Plus, &s_buffer);
        Ok(Signature { r, s })
    }

    pub fn der(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        {
            // let mut rbin = &self.r.to_bytes_be().1.to_vec()[0..32];
            let mut rbin = &utils::int_to_big_endian(&self.r, 32)?[..];
            let mut v = Vec::new();
            v.extend_from_slice(
                rbin.strip_prefix(b"\x00")
                    .or(Some(rbin))
                    .context("rbin not present")?,
            );
            if rbin[0] & 0x80 != 0 {
                let marker = &b"\x00"[0..1];
                v.clear();
                v.extend_from_slice(&[marker, rbin.clone()].concat()[..]);
            }
            rbin = v.as_slice();
            result.push(0x2);
            result.push(
                *(rbin.len())
                    .to_be_bytes()
                    .last()
                    .context("rbin len last byte not present")?,
            );
            result.extend_from_slice(rbin);
        }
        {
            // let mut sbin = &self.s.to_bytes_be().1.to_vec()[0..32];
            let mut sbin = &utils::int_to_big_endian(&self.s, 32)?[..];
            let mut v = Vec::new();
            v.extend_from_slice(
                sbin.strip_prefix(b"\x00")
                    .or(Some(sbin))
                    .context("sbin not present")?,
            );
            if sbin[0] & 0x80 != 0 {
                let marker = &b"\x00"[0..1];
                v.clear();
                v.extend_from_slice(&[marker, sbin.clone()].concat()[..]);
            }
            sbin = v.as_slice();
            result.push(2); //.extend_from_slice(&vec![&b"\x02"[0..1], &sbin.len().to_be_bytes(), sbin].concat());
            result.push(
                *sbin
                    .len()
                    .to_be_bytes()
                    .last()
                    .context("sbin len last byte not present")?,
            );
            result.extend_from_slice(sbin)
        }
        let mut final_r: Vec<u8> = Vec::new();
        final_r.push(0x30);
        final_r.push(
            *result
                .len()
                .to_be_bytes()
                .last()
                .context("final len byte not present")?,
        );
        final_r.extend_from_slice(&result);
        Ok(final_r)
    }

    pub fn signature_hash(passphrase: &str) -> SignatureHash {
        SignatureHash(BigInt::from_bytes_be(
            num_bigint::Sign::Plus,
            &utils::hash256(passphrase.as_bytes()),
        ))
    }

    pub fn signature_hash_from_hex(passphrase: &str) -> Result<SignatureHash> {
        Ok(SignatureHash(
            BigInt::parse_bytes(passphrase.as_bytes(), 16)
                .context("unable to parse hex bytes to bigint")?,
        ))
    }

    pub fn signature_hash_from_vec(passphrase: Vec<u8>) -> SignatureHash {
        SignatureHash(BigInt::from_bytes_be(num_bigint::Sign::Plus, &passphrase))
    }

    pub fn signature_hash_from_int(passphrase: BigInt) -> SignatureHash {
        SignatureHash(passphrase)
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

    use anyhow::Ok;
    use num_bigint::BigInt;

    use super::Signature;
    use anyhow::{Context, Result};

    #[test]

    fn der_test() -> Result<()> {
        let r: BigInt = BigInt::parse_bytes(
            b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .context("unable to parse hex bytes to bigint")?;
        let s: BigInt = BigInt::parse_bytes(
            b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .context("unable to parseh hex bytes to bigint")?;
        let sig = Signature::new(r, s);
        assert_eq!(hex::encode(sig.der()?), "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec");
        Ok(())
    }

    #[test]
    fn test_parse_signature() -> Result<()> {
        let r: BigInt = BigInt::parse_bytes(
            b"37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6",
            16,
        )
        .context("unable parse hex bytes to bigint")?;
        let s: BigInt = BigInt::parse_bytes(
            b"8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec",
            16,
        )
        .context("unable parse hex bytes to bigint")?;
        let sig = "3045022037206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c60221008ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec";
        let sig_encode = hex::decode(sig)?;
        let mut cursor_sig = Cursor::new(sig_encode);
        let sig_parsed = Signature::parse(&mut cursor_sig)?;
        assert_eq!(sig_parsed.r, r);
        assert_eq!(sig_parsed.s, s);
        Ok(())
    }
}
