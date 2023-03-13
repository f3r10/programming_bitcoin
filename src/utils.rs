use core::panic;
use std::io::Read;

use num_bigint::BigInt;
use num_integer::Integer;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

const BASE58_ALPHABET: &'static [u8] =
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// A better alternative would be to use this external create: https://docs.rs/base58/latest/src/base58/lib.rs.html#37-40
// div_rem only works until this crate was added: https://docs.rs/num-integer/0.1.45/num_integer/trait.Integer.html
pub fn encode_base58(s: &[u8]) -> String {
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
            num_bigint::Sign::Plus => mod1.pop().unwrap(),
        };

        let ch = BASE58_ALPHABET[modd as usize];
        result.push(ch as char);
    }
    prefix + (&result.chars().rev().collect::<String>()[..])
}

pub fn hash256(b: &[u8]) -> Vec<u8> {
    Sha256::digest(Sha256::digest(b)).to_vec()
}

pub fn encode_base58_checksum(b: &[u8]) -> String {
    let h = &hash256(b)[0..4];
    encode_base58(&[b, h].concat())
}

pub fn hash160(s: &[u8]) -> Vec<u8> {
    Ripemd160::digest(Sha256::digest(s)).to_vec()
}

pub fn little_endian_to_int(s: &[u8]) -> BigInt {
    BigInt::from_bytes_le(num_bigint::Sign::Plus, s)
}

pub fn int_to_little_endian(s: BigInt, limit: u64) -> Vec<u8> {
    let i = s.to_signed_bytes_le();
    let mut buffer = vec![0; limit.try_into().unwrap()];
    let mut handle = i.take(limit);
    handle.read(&mut buffer).unwrap();
    buffer.to_vec()
}

pub fn usize_to_little_endian(s: usize, limit: u64) -> Vec<u8> {
    let i = s.to_le_bytes();
    let mut buffer = vec![0; limit.try_into().unwrap()];
    let mut handle = i.take(limit);
    handle.read(&mut buffer).unwrap();
    buffer.to_vec()
}

pub fn u32_to_little_endian(s: u32, limit: u64) -> Vec<u8> {
    let i = s.to_le_bytes();
    let mut buffer = vec![0; limit.try_into().unwrap()];
    let mut handle = i.take(limit);
    handle.read(&mut buffer).unwrap();
    buffer.to_vec()
}

pub fn i32_to_little_endian(s: i32, limit: u64) -> Vec<u8> {
    let i = s.to_le_bytes();
    let mut buffer = vec![0; limit.try_into().unwrap()];
    let mut handle = i.take(limit);
    handle.read(&mut buffer).unwrap();
    buffer.to_vec()
}

pub fn read_varint<R: Read>(stream: &mut R) -> BigInt {
    let mut buffer = [0; 1];
    stream.read_exact(&mut buffer).unwrap();
    if buffer[0] == 0xfd {
        let mut buffer = [0; 2];
        stream.read_exact(&mut buffer).unwrap();
        little_endian_to_int(&buffer)
    } else if buffer[0] == 0xfe {
        let mut buffer = [0; 4];
        stream.read_exact(&mut buffer).unwrap();
        little_endian_to_int(&buffer)
    } else if buffer[0] == 0xff {
        let mut buffer = [0; 8];
        stream.read_exact(&mut buffer).unwrap();
        little_endian_to_int(&buffer)
    } else {
        little_endian_to_int(&buffer)
    }
}

pub fn encode_varint(i: usize) -> Vec<u8> {
    if i < 0xfd {
        usize_to_little_endian(i, 1)
    } else if i < 0x10000 {
        let mut res = vec![b'\xfd'];
        res.append(&mut usize_to_little_endian(i, 2));
        res
    } else if i < 0x100000000 {
        let mut res = vec![b'\xfe'];
        res.append(&mut usize_to_little_endian(i, 4));
        res
    } else if BigInt::from(i) < BigInt::from(0x10000000000000000_i128) {
        let mut res = vec![b'\xff'];
        res.append(&mut usize_to_little_endian(i, 8));
        res
    } else {
        panic!("integer too large: {}", i)
    }
}

#[cfg(test)]
mod utils_tests {
    use super::{encode_base58, encode_varint};

    #[test]
    fn base58_test() {
        let hex = &hex::decode("7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d")
            .unwrap()[..];
        let base58 = encode_base58(hex);
        assert_eq!(base58, "9MA8fRQrT4u8Zj8ZRd6MAiiyaxb2Y1CMpvVkHQu5hVM6");
        let hex = &hex::decode("eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c")
            .unwrap()[..];
        let base58 = encode_base58(hex);
        assert_eq!(base58, "4fE3H2E6XMp4SsxtwinF7w9a34ooUrwWe4WsW1458Pd");
        let hex = &hex::decode("c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6")
            .unwrap()[..];
        let base58 = encode_base58(hex);
        assert_eq!(base58, "EQJsjkd6JaGwxrjEhfeqPenqHwrBmPQZjJGNSCHBkcF7");
        let hex = &b"\0\0\0\0abc"[..];
        let base58 = encode_base58(hex);
        assert_eq!(base58, "1111ZiCa");
    }

    #[test]
    fn encode_varint_test() {
        let res = encode_varint(107);
        assert_eq!(hex::encode(res), "6b")
    }
}
