use std::io::Cursor;

use byteorder::{BigEndian, ByteOrder};
use num_bigint::BigInt;

use crate::{s256_point::S256Point, script::Command, signature::Signature, utils};

#[derive(Debug, Clone)]
pub enum OpCodeFunctions {
    Op0(u32),
    OpChecksig(u32),
    OpDup(u32),
    OpHash160(u32),
    OpHash256(u32),
    OpEqualverify(u32),
    OpEqual(u32),
}

impl AsRef<u32> for OpCodeFunctions {
    fn as_ref(&self) -> &u32 {
        match &self {
            OpCodeFunctions::Op0(op) => op,
            OpCodeFunctions::OpChecksig(op) => op,
            OpCodeFunctions::OpDup(op) => op,
            OpCodeFunctions::OpHash160(op) => op,
            OpCodeFunctions::OpEqualverify(op) => op,
            OpCodeFunctions::OpEqual(op) => op,
            OpCodeFunctions::OpHash256(op) => op,
        }
    }
}

pub fn parse_op_codes(op_code: u32) -> OpCodeFunctions {
    match op_code {
        0 => OpCodeFunctions::Op0(op_code),
        172 => OpCodeFunctions::OpChecksig(op_code),
        118 => OpCodeFunctions::OpDup(op_code),
        169 => OpCodeFunctions::OpHash160(op_code),
        136 => OpCodeFunctions::OpEqualverify(op_code),
        135 => OpCodeFunctions::OpEqual(op_code),
        170 => OpCodeFunctions::OpHash256(op_code),
        unknow => panic!("unknown opCode: {}", unknow),
    }
}

pub fn operation(
    op_code: OpCodeFunctions,
    stack: &mut Vec<Vec<u8>>,
    _cmds: &mut Vec<Command>,
    _altstack: &mut Vec<Vec<u8>>,
    z: BigInt,
) -> bool {
    match op_code {
        OpCodeFunctions::Op0(_) => {
            stack.push(encode_num(0));
            true
        }
        OpCodeFunctions::OpChecksig(_) => {
            if stack.len() < 2 {
                return false;
            } else {
                let sec_pubkey = stack.pop().unwrap();
                let der_signature = stack.pop().unwrap();
                let mut der_signature_cursor = Cursor::new(der_signature);
                let point = S256Point::parse(&sec_pubkey);
                let sig = Signature::parse(&mut der_signature_cursor);
                if point.verify(z, sig) {
                    stack.push(encode_num(1))
                } else {
                    stack.push(encode_num(0))
                }
            }
            true
        }
        OpCodeFunctions::OpDup(_) => {
            if stack.len() < 1 {
                return false
            } 
            stack.push(stack.last().unwrap().to_vec());
            true
        },
        OpCodeFunctions::OpHash160(_) => {
            if stack.len() < 1 {
                return false
            }
            let element = stack.pop().unwrap();
            stack.push(utils::hash160(&element));
            return true
        },
        OpCodeFunctions::OpEqualverify(_) => todo!(),
        OpCodeFunctions::OpEqual(_) => todo!(),
        OpCodeFunctions::OpHash256(_) => {
            if stack.len() < 1 {
                return false
            }
            let element = stack.pop().unwrap();
            stack.push(utils::hash256(&element));
            return true
        },
    }
}

fn encode_num(num: i32) -> Vec<u8> {
    if num == 0 {
        return b"".to_vec();
    }
    let mut abs_num = num.abs();
    let negative = num < 0;
    let mut result: Vec<u8> = Vec::new();
    while abs_num > 0 {
        result.append(&mut utils::i32_to_little_endian(abs_num & 0xff, 1));
        abs_num >>= 8
    }
    match result.last() {
        Some(last) => {
            let last_c = last.clone();
            if (last_c & 0x80) == 1 {
                if negative {
                    result.push(0x80)
                } else {
                    result.push(0x0)
                }
            } else if negative {
                result.pop();
                result.push(last_c | 0x80)
            }
        }
        None => panic!("unable to get last element of encoded num"),
    }
    result
}

fn decode_num(element: Vec<u8>) -> i32 {
    if element == b"".to_vec() {
        return 0;
    }
    let mut result: i32;
    let mut big_endian = element.clone();
    big_endian.reverse();
    let negative: bool;
    if (big_endian[0] & 0x80) == 1 {
        negative = true;
        result = BigEndian::read_i32(&[0, 0, 0, big_endian[0] & 0x7f]) as i32;
    } else {
        negative = false;
        result = BigEndian::read_i32(&[0, 0, 0, big_endian[0]]) as i32;
    }
    for c in &big_endian[1..] {
        result <<= 8;
        result += BigEndian::read_i32(&[0, 0, 0, c.clone()]) as i32;
    }
    if negative {
        return -result;
    } else {
        return result;
    }
}

#[cfg(test)]
mod op_tests {
    use crate::op::decode_num;

    use super::encode_num;

    #[test]
    fn test_encode_num() {
        assert_eq!("e703", hex::encode(encode_num(999)));
        assert_eq!("01", hex::encode(encode_num(1)));
        assert_eq!("02", hex::encode(encode_num(2)));
        assert_eq!("", hex::encode(encode_num(0)));
    }

    #[test]
    fn test_decode_num() {
        assert_eq!(1, decode_num(hex::decode("01").unwrap()));
        assert_eq!(2, decode_num(hex::decode("02").unwrap()));
        assert_eq!(999, decode_num(hex::decode("e703").unwrap()));
        assert_eq!(0, decode_num(hex::decode("").unwrap()));
    }
}
