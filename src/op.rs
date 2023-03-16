use std::io::Cursor;

use byteorder::{BigEndian, ByteOrder};
use crypto::{digest::Digest, sha1::Sha1};
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
    OpVerify(u32),
    Op6(u32),
    OpAdd(u32),
    OpMul(u32),
    Op2(u32),
    Op2dup(u32),
    OpSwap(u32),
    OpNot(u32),
    OpSha1(u32),
}

impl OpCodeFunctions {
    pub fn op0() -> Self {
        OpCodeFunctions::Op0(0)
    }

    pub fn op_checksig() -> Self {
        OpCodeFunctions::OpChecksig(172)
    }

    pub fn op_dup() -> Self {
        OpCodeFunctions::OpDup(118)
    }

    pub fn op_hash160() -> Self {
        OpCodeFunctions::OpHash160(169)
    }

    pub fn op_hash256() -> Self {
        OpCodeFunctions::OpHash256(170)
    }

    pub fn op_equalverify() -> Self {
        OpCodeFunctions::OpEqualverify(136)
    }

    pub fn op_equal() -> Self {
        OpCodeFunctions::OpEqual(135)
    }

    pub fn op_verify() -> Self {
        OpCodeFunctions::OpVerify(105)
    }
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
            OpCodeFunctions::OpVerify(op) => op,
            OpCodeFunctions::Op6(op) => op,
            OpCodeFunctions::OpAdd(op) => op,
            OpCodeFunctions::OpMul(op) => op,
            OpCodeFunctions::Op2(op) => op,
            OpCodeFunctions::Op2dup(op) => op,
            OpCodeFunctions::OpSwap(op) => op,
            OpCodeFunctions::OpNot(op) => op,
            OpCodeFunctions::OpSha1(op) => op,
        }
    }
}

pub fn parse_raw_op_codes(op_code: u32) -> OpCodeFunctions {
    match op_code {
        0 => OpCodeFunctions::Op0(op_code),
        172 => OpCodeFunctions::OpChecksig(op_code),
        118 => OpCodeFunctions::OpDup(op_code),
        169 => OpCodeFunctions::OpHash160(op_code),
        136 => OpCodeFunctions::OpEqualverify(op_code),
        135 => OpCodeFunctions::OpEqual(op_code),
        170 => OpCodeFunctions::OpHash256(op_code),
        105 => OpCodeFunctions::OpVerify(op_code),
        86 => OpCodeFunctions::Op6(86),
        147 => OpCodeFunctions::OpAdd(147),
        149 => OpCodeFunctions::OpMul(149),
        0x52 => OpCodeFunctions::Op2(2),
        0x6e => OpCodeFunctions::Op2dup(0x6e),
        0x7c => OpCodeFunctions::OpSwap(0x7c),
        0x91 => OpCodeFunctions::OpNot(0x91),
        0xa7 => OpCodeFunctions::OpSha1(0xa7),
        unknow => panic!("unknown opCode: {}", unknow),
    }
}

pub fn operation(
    op_code: OpCodeFunctions,
    stack: &mut Vec<Vec<u8>>,
    cmds: &mut Vec<Command>,
    altstack: &mut Vec<Vec<u8>>,
    z: &BigInt,
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
                return false;
            }
            stack.push(stack.last().unwrap().to_vec());
            true
        }
        OpCodeFunctions::OpHash160(_) => {
            if stack.len() < 1 {
                return false;
            }
            let element = stack.pop().unwrap();
            stack.push(utils::hash160(&element));
            return true;
        }
        OpCodeFunctions::OpEqualverify(_) => {
            operation(OpCodeFunctions::op_equal(), stack, cmds, altstack, z)
                && operation(OpCodeFunctions::op_verify(), stack, cmds, altstack, z)
        }
        OpCodeFunctions::OpEqual(_) => {
            if stack.len() < 2 {
                return false;
            }
            let element1 = stack.pop().unwrap();
            let element2 = stack.pop().unwrap();
            if element1 == element2 {
                stack.push(encode_num(1))
            } else {
                stack.push(encode_num(0))
            }
            return true;
        }
        OpCodeFunctions::OpHash256(_) => {
            if stack.len() < 1 {
                return false;
            }
            let element = stack.pop().unwrap();
            stack.push(utils::hash256(&element));
            return true;
        }
        OpCodeFunctions::OpVerify(_) => {
            if stack.len() < 1 {
                return false;
            }
            let element = stack.pop().unwrap();
            if decode_num(element) == 0 {
                return false;
            }
            return true;
        }
        OpCodeFunctions::Op6(_) => {
            stack.push(encode_num(6));
            true
        }
        OpCodeFunctions::OpAdd(_) => {
            if stack.len() < 2 {
                return false;
            }
            let element1 = decode_num(stack.pop().unwrap());
            let element2 = decode_num(stack.pop().unwrap()); //BigEndian::read_i32(&[0, 0, 0, stack.pop().unwrap()[0]]);
            stack.push(encode_num(element1 + element2));
            return true;
        }
        OpCodeFunctions::OpMul(_) => {
            if stack.len() < 2 {
                return false;
            }
            let element1 = decode_num(stack.pop().unwrap());
            let element2 = decode_num(stack.pop().unwrap()); //BigEndian::read_i32(&[0, 0, 0, stack.pop().unwrap()[0]]);
            stack.push(encode_num(element1 * element2));
            return true;
        }
        OpCodeFunctions::Op2(_) => {
            stack.push(encode_num(2));
            true
        }
        OpCodeFunctions::Op2dup(_) => {
            if stack.len() < 2 {
                return false;
            }
            stack.append(&mut stack[stack.len() - 2..].to_vec());
            return true;
        }
        OpCodeFunctions::OpSwap(_) => {
            if stack.len() < 2 {
                return false;
            }
            let len = stack.len();
            stack.swap(len - 1, len - 2);
            return true;
        }
        OpCodeFunctions::OpNot(_) => {
            if stack.len() < 2 {
                return false;
            }
            if decode_num(stack.pop().unwrap()) == 0 {
                stack.push(encode_num(1))
            } else {
                stack.push(encode_num(0))
            }
            return true;
        }
        OpCodeFunctions::OpSha1(_) => {
            if stack.len() < 1 {
                return false;
            }
            let mut out = [0u8; 20];
            let element = stack.pop().unwrap();
            let mut hasher = Sha1::new();
            hasher.input(element.as_slice());
            hasher.result(&mut out);
            stack.push(out.to_vec());
            return true;
        }
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
