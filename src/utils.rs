use core::panic;
use std::io::Read;

use byteorder::{ByteOrder, LittleEndian};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::{
    block::Block,
    op,
    script::{Command, Script},
    utils,
};
use anyhow::{Context, Result};

const BASE58_ALPHABET: &'static [u8] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const TWO_WEEKS: i32 = 60 * 60 * 24 * 14;

// A better alternative would be to use this external create: https://docs.rs/base58/latest/src/base58/lib.rs.html#37-40
// div_rem only works until this crate was added: https://docs.rs/num-integer/0.1.45/num_integer/trait.Integer.html
pub fn encode_base58(s: &[u8]) -> Result<String> {
    let leading_zeros = s.iter().take_while(|x| **x == 0).count();
    // .fold(0, |acc, x| if x == &0 { acc + 1 } else { acc });
    let mut num = BigInt::from_bytes_be(num_bigint::Sign::Plus, s);
    let mut result = String::new();
    let mut prefix = String::new();
    for _ in 0..leading_zeros {
        prefix.push('1')
    }
    while num > BigInt::from(0) {
        let (l_num, l_mod) = num.div_rem(&BigInt::from(58));
        (num) = l_num;
        let (sign, mut mod1) = (l_mod).to_u32_digits();
        let modd = match sign {
            num_bigint::Sign::Minus => panic!("should not be negative"),
            num_bigint::Sign::NoSign => 0,
            num_bigint::Sign::Plus => mod1.pop().context("unable to pop element")?,
        };

        let ch = BASE58_ALPHABET[modd as usize];
        result.push(ch as char);
    }
    Ok(prefix + (&result.chars().rev().collect::<String>()[..]))
}

pub fn p2pkh_script(h160: Vec<u8>) -> Script {
    Script::new(Some(vec![
        Command::Operation(op::parse_raw_op_codes(0x76)),
        Command::Operation(op::parse_raw_op_codes(0xa9)),
        Command::Element(h160),
        Command::Operation(op::parse_raw_op_codes(0x88)),
        Command::Operation(op::parse_raw_op_codes(0xac)),
    ]))
}

pub fn hash256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(Sha256::digest(b)).to_vec()
}

pub fn encode_base58_checksum(b: &[u8]) -> Result<String> {
    let h = &hash256(b)[0..4];
    encode_base58(&[b, h].concat())
}

// this is a special case based on encode_base58_checksum
pub fn decode_base58(s: &str) -> Result<Vec<u8>> {
    let mut num = BigUint::from(0_u32);
    for c in s.bytes() {
        num *= 58_u32;
        let el = BASE58_ALPHABET
            .iter()
            .position(|x| c == *x)
            .context("unable to get position from filter")?;
        num += el
    }
    let combined = num.to_bytes_be();
    let checksum: Vec<u8> = combined.clone().into_iter().rev().take(4).collect();
    let head: Vec<u8> = combined
        .clone()
        .into_iter()
        .take(combined.len() - 4)
        .to_owned()
        .collect();
    let hash256: Vec<u8> = utils::hash256(head.as_slice())
        .into_iter()
        .take(4)
        .rev()
        .collect();
    if hash256 != checksum {
        panic!(
            "bad address: {} {}",
            hex::encode(checksum),
            hex::encode(hash256)
        )
    }
    Ok(combined[1..(combined.len() - 4)].to_vec())
}

pub fn hash160(s: &[u8]) -> Vec<u8> {
    Ripemd160::digest(Sha256::digest(s)).to_vec()
}

pub fn little_endian_to_int(s: &[u8]) -> BigInt {
    BigInt::from_bytes_le(num_bigint::Sign::Plus, s)
}

pub fn little_endian_unit_to_int(s: &[u8]) -> BigUint {
    BigUint::from_bytes_le(s)
}

pub fn int_to_little_endian(s: &BigInt, limit: u64) -> Result<Vec<u8>> {
    let i = s.to_signed_bytes_le();
    let mut buffer = vec![0; limit.try_into()?];
    let mut handle = i.take(limit);
    handle.read(&mut buffer)?;
    Ok(buffer.to_vec())
}

pub fn int_to_big_endian(s: &BigInt, limit: u64) -> Result<Vec<u8>> {
    let i = s.to_signed_bytes_be();
    if i.len() as u64 > limit {
        let i = s.to_signed_bytes_le();
        let mut buffer = vec![0; limit.try_into()?];
        let mut handle = i.take(limit);
        handle.read(&mut buffer)?;
        buffer.reverse();
        Ok(buffer.to_vec())
    } else {
        let diff = limit - (i.len() as u64);
        Ok([vec![0; diff.try_into()?], i].concat())
    }
}

pub fn usize_to_little_endian(s: usize, limit: u64) -> Result<Vec<u8>> {
    let i = s.to_le_bytes();
    let mut buffer = vec![0; limit.try_into()?];
    let mut handle = i.take(limit);
    handle.read(&mut buffer)?;
    Ok(buffer.to_vec())
}

pub fn u32_to_little_endian(s: u32, limit: u64) -> Result<Vec<u8>> {
    let i = s.to_le_bytes();
    let mut buffer = vec![0; limit.try_into()?];
    let mut handle = i.take(limit);
    handle.read(&mut buffer)?;
    Ok(buffer.to_vec())
}

pub fn i32_to_little_endian(s: i32, limit: u64) -> Result<Vec<u8>> {
    let i = s.to_le_bytes();
    let mut buffer = vec![0; limit.try_into()?];
    let mut handle = i.take(limit);
    handle.read(&mut buffer)?;
    Ok(buffer.to_vec())
}

pub fn read_varint<R: Read>(stream: &mut R) -> Result<BigInt> {
    let mut buffer = [0; 1];
    stream.read_exact(&mut buffer)?;
    if buffer[0] == 0xfd {
        let mut buffer = [0; 2];
        stream.read_exact(&mut buffer)?;
        Ok(little_endian_to_int(&buffer))
    } else if buffer[0] == 0xfe {
        let mut buffer = [0; 4];
        stream.read_exact(&mut buffer)?;
        Ok(little_endian_to_int(&buffer))
    } else if buffer[0] == 0xff {
        let mut buffer = [0; 8];
        stream.read_exact(&mut buffer)?;
        Ok(little_endian_to_int(&buffer))
    } else {
        Ok(little_endian_to_int(&buffer))
    }
}

pub fn encode_varint(i: usize) -> Result<Vec<u8>> {
    if i < 0xfd {
        usize_to_little_endian(i, 1)
    } else if i < 0x10000 {
        let mut res = vec![b'\xfd'];
        res.append(&mut usize_to_little_endian(i, 2)?);
        Ok(res)
    } else if i < 0x100000000 {
        let mut res = vec![b'\xfe'];
        res.append(&mut usize_to_little_endian(i, 4)?);
        Ok(res)
    } else if BigInt::from(i) < BigInt::from(0x10000000000000000_i128) {
        let mut res = vec![b'\xff'];
        res.append(&mut usize_to_little_endian(i, 8)?);
        Ok(res)
    } else {
        panic!("integer too large: {}", i)
    }
}

pub fn h160_to_p2pkh_address(h160: &Vec<u8>, testnet: bool) -> Result<String> {
    let prefix: u8;
    if testnet {
        prefix = 0x6f
    } else {
        prefix = 0x00
    }
    encode_base58_checksum(&[[prefix].to_vec(), h160.to_vec()].concat())
}

pub fn h160_to_p2psh_address(h160: &Vec<u8>, testnet: bool) -> Result<String> {
    let prefix: u8;
    if testnet {
        prefix = 0xc4
    } else {
        prefix = 0x05
    }
    encode_base58_checksum(&[[prefix].to_vec(), h160.to_vec()].concat())
}

pub fn bits_to_target(bits: [u8; 4]) -> Result<BigUint> {
    let exponent = bits.last().context("unable to get the last from bits")?;
    let mut coeff_buffer = [0; 3];
    let mut handle = bits.take(3);
    handle.read(&mut coeff_buffer)?;
    let coefficient = LittleEndian::read_u24(&coeff_buffer);
    let target = coefficient * (BigUint::from(256_u32).pow((exponent - 3).into()));
    Ok(target)
}

pub fn target_to_bits(target: BigUint) -> [u8; 4] {
    let mut raw_bytes = target.to_bytes_be();
    raw_bytes = raw_bytes.into_iter().skip_while(|x| *x == 0).collect();
    let exponent: usize;
    let mut coefficient: Vec<u8>;
    if raw_bytes[0] > 0x7f {
        exponent = raw_bytes.len() + 1;
        coefficient = [[b'\x00'].to_vec(), raw_bytes[0..2].to_vec()].concat();
    } else {
        exponent = raw_bytes.len();
        coefficient = raw_bytes[0..3].to_vec();
    }
    coefficient.reverse();
    let exponent: Vec<u8> = exponent
        .to_be_bytes()
        .into_iter()
        .skip_while(|x| *x == 0)
        .collect();
    let new_bits = [coefficient, exponent].concat();
    new_bits.try_into().unwrap()
}

pub fn calculate_new_bits(last_block: &Block, first_block: &Block) -> Result<[u8; 4]> {
    let mut time_differential = (last_block.timestamp as i32) - (first_block.timestamp as i32);
    if time_differential > TWO_WEEKS * 4 {
        time_differential = TWO_WEEKS * 4
    }
    if time_differential < TWO_WEEKS / 4 {
        time_differential = TWO_WEEKS / 4
    }
    let new_target = last_block.target()? * (time_differential as u32) / (TWO_WEEKS as u32);
    Ok(target_to_bits(new_target))
}

pub fn strip_zero_end(slice: &[u8]) -> Vec<u8> {
    let mut bytes = slice;
    while let [rest @ .., last] = bytes {
        if last == &0_u8 {
            bytes = rest;
        } else {
            break;
        }
    }
    bytes.to_vec()
}

#[cfg(test)]
mod utils_tests {
    use crate::utils::{decode_base58, encode_base58_checksum, h160_to_p2psh_address};

    use super::{bits_to_target, encode_base58, encode_varint, h160_to_p2pkh_address};
    use anyhow::Result;

    #[test]
    fn base58_test() -> Result<()> {
        let hex =
            &hex::decode("7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d")?[..];
        let base58 = encode_base58(hex)?;
        assert_eq!(base58, "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6");
        let hex =
            &hex::decode("eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c")?[..];
        let base58 = encode_base58(hex)?;
        assert_eq!(base58, "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd");
        let hex =
            &hex::decode("c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6")?[..];
        let base58 = encode_base58(hex)?;
        assert_eq!(base58, "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7");
        let hex = &b"\0\0\0\0abc"[..];
        let base58 = encode_base58(hex)?;
        assert_eq!(base58, "1111ZiCa");

        let addr = "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf";
        let h160 = hex::encode(decode_base58(addr)?);
        let want = "507b27411ccf7f16f10297de6cef3f291623eddf";
        assert_eq!(h160, want);
        let got = encode_base58_checksum(&[b"\x6f"[..].to_vec(), hex::decode(h160)?].concat())?;
        assert_eq!(got, addr);
        Ok(())
    }

    #[test]
    fn encode_varint_test() -> Result<()> {
        let res = encode_varint(107)?;
        assert_eq!(hex::encode(res), "6b");
        Ok(())
    }

    #[test]
    fn test_p2pkh_address() -> Result<()> {
        let h160 = hex::decode("74d691da1574e6b3c192ecfb52cc8984ee7b6c56")?;
        let want = "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa";
        assert_eq!(h160_to_p2pkh_address(&h160, false)?, want);
        let want = "mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q";
        assert_eq!(h160_to_p2pkh_address(&h160, true)?, want);
        Ok(())
    }

    #[test]
    fn test_p2sh_address() -> Result<()> {
        let h160 = hex::decode("74d691da1574e6b3c192ecfb52cc8984ee7b6c56")?;
        let want = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh";
        assert_eq!(h160_to_p2psh_address(&h160, false)?, want);
        let want = "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B";
        assert_eq!(h160_to_p2psh_address(&h160, true)?, want);
        Ok(())
    }

    #[test]
    fn test_bits_to_target() -> Result<()> {
        let bits: [u8; 4] = hex::decode("e93c0118")?.try_into().unwrap();
        let target = bits_to_target(bits)?;
        let target_fmt = format!("{:#064x}", target);
        assert_eq!(
            target_fmt,
            "0x00000000000000013ce9000000000000000000000000000000000000000000"
        );
        Ok(())
    }
}
