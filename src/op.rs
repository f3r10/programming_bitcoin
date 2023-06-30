use std::io::Cursor;

use byteorder::{BigEndian, ByteOrder};
use crypto::{digest::Digest, sha1::Sha1};

use crate::{
    s256_point::S256Point,
    script::Command,
    signature::{Signature, SignatureHash},
    utils,
};
use anyhow::{Context, Result};

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
    OpSigHashAll(u32),
    OpCheckMultisig(u32),
    OpNop(u32),
    OpUnknown(u32),
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

    pub fn op_sig_hash_all() -> Self {
        OpCodeFunctions::OpSigHashAll(1)
    }

    pub fn op_checkmultisig() -> Self {
        OpCodeFunctions::OpCheckMultisig(0xae)
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
            OpCodeFunctions::OpSigHashAll(op) => op,
            OpCodeFunctions::OpCheckMultisig(op) => op,
            OpCodeFunctions::OpNop(op) => op,
            OpCodeFunctions::OpUnknown(op) => op,
        }
    }
}

pub fn parse_raw_op_codes(op_code: u32) -> OpCodeFunctions {
    match op_code {
        0 => OpCodeFunctions::Op0(op_code),
        0xac => OpCodeFunctions::OpChecksig(op_code),
        0x76 => OpCodeFunctions::OpDup(op_code),
        0xa9 => OpCodeFunctions::OpHash160(op_code),
        0x88 => OpCodeFunctions::OpEqualverify(op_code),
        0x87 => OpCodeFunctions::OpEqual(op_code),
        0xaa => OpCodeFunctions::OpHash256(op_code),
        0x69 => OpCodeFunctions::OpVerify(op_code),
        0x56 => OpCodeFunctions::Op6(op_code),
        0x93 => OpCodeFunctions::OpAdd(op_code),
        0x95 => OpCodeFunctions::OpMul(op_code),
        0x52 => OpCodeFunctions::Op2(op_code),
        0x6e => OpCodeFunctions::Op2dup(op_code),
        0x7c => OpCodeFunctions::OpSwap(op_code),
        0x91 => OpCodeFunctions::OpNot(op_code),
        0xa7 => OpCodeFunctions::OpSha1(op_code),
        0xae => OpCodeFunctions::OpCheckMultisig(op_code),
        unknow => OpCodeFunctions::OpUnknown(unknow),
    }
}

pub fn get_op_names(op_code: &OpCodeFunctions) -> String {
    match op_code {
        OpCodeFunctions::Op0(_) => "OP_0".to_string(),
        OpCodeFunctions::OpChecksig(_) => "OP_CHECK_SIG".to_string(),
        OpCodeFunctions::OpDup(_) => "OP_DUP".to_string(),
        OpCodeFunctions::OpHash160(_) => "OP_HASH_160".to_string(),
        OpCodeFunctions::OpHash256(_) => "OP_HASH_256".to_string(),
        OpCodeFunctions::OpEqualverify(_) => "OP_EQUAL_VERIFY".to_string(),
        OpCodeFunctions::OpEqual(_) => "OP_EQUAL".to_string(),
        OpCodeFunctions::OpVerify(_) => "OP_VERIFY".to_string(),
        OpCodeFunctions::Op6(_) => "OP_6".to_string(),
        OpCodeFunctions::OpAdd(_) => "OP_ADD".to_string(),
        OpCodeFunctions::OpMul(_) => "OP_MUL".to_string(),
        OpCodeFunctions::Op2(_) => "OP_2".to_string(),
        OpCodeFunctions::Op2dup(_) => "OP_2_DUP".to_string(),
        OpCodeFunctions::OpSwap(_) => "OP_SWAP".to_string(),
        OpCodeFunctions::OpNot(_) => "OP_NOT".to_string(),
        OpCodeFunctions::OpSha1(_) => "OP_SHA1".to_string(),
        OpCodeFunctions::OpSigHashAll(_) => "OP_SIG_HASH_ALL".to_string(),
        OpCodeFunctions::OpCheckMultisig(_) => "OP_CHECKMULTISIG".to_string(),
        OpCodeFunctions::OpNop(_) => "OP_NOP".to_string(),
        OpCodeFunctions::OpUnknown(op) => op.to_string(),
    }
}

pub fn op_hash160(stack: &mut Vec<Vec<u8>>) -> Result<bool> {
    if stack.len() < 1 {
        return Ok(false);
    }
    let element = stack
        .pop()
        .context("unable to get element from the stack")?;
    stack.push(utils::hash160(&element));
    return Ok(true);
}

pub fn op_equal(stack: &mut Vec<Vec<u8>>) -> Result<bool> {
    if stack.len() < 2 {
        return Ok(false);
    }
    let element1 = stack
        .pop()
        .context("unable to get element from the stack")?;
    let element2 = stack
        .pop()
        .context("unable to get element from the stack")?;
    if element1 == element2 {
        stack.push(encode_num(1)?)
    } else {
        stack.push(encode_num(0)?)
    }
    return Ok(true);
}

pub fn op_verify(stack: &mut Vec<Vec<u8>>) -> Result<bool> {
    if stack.len() < 1 {
        return Ok(false);
    }
    let element = stack
        .pop()
        .context("unable to get element from the stack")?;
    if decode_num(element) == 0 {
        return Ok(false);
    }
    return Ok(true);
}

pub fn operation(
    op_code: OpCodeFunctions,
    stack: &mut Vec<Vec<u8>>,
    cmds: &mut Vec<Command>,
    altstack: &mut Vec<Vec<u8>>,
    z: &SignatureHash,
) -> Result<bool> {
    match op_code {
        OpCodeFunctions::Op0(_) => {
            stack.push(encode_num(0)?);
            Ok(true)
        }
        OpCodeFunctions::OpChecksig(_) => {
            if stack.len() < 2 {
                return Ok(false);
            } else {
                let sec_pubkey = stack
                    .pop()
                    .context("unable to get element from the stack")?;
                let der_signature = stack
                    .pop()
                    .context("unable to get element from the stack")?;
                let mut der_signature_cursor = Cursor::new(der_signature);
                let point = S256Point::parse(&sec_pubkey)?;
                let sig = Signature::parse(&mut der_signature_cursor)?;
                if point.verify(z, sig)? {
                    stack.push(encode_num(1)?)
                } else {
                    stack.push(encode_num(0)?)
                }
            }
            Ok(true)
        }
        OpCodeFunctions::OpDup(_) => {
            if stack.len() < 1 {
                return Ok(false);
            }
            stack.push(
                stack
                    .last()
                    .context("unable to get last element from the stack")?
                    .to_vec(),
            );
            Ok(true)
        }
        OpCodeFunctions::OpHash160(_) => op_hash160(stack),
        OpCodeFunctions::OpEqualverify(_) => {
            let ans = operation(OpCodeFunctions::op_equal(), stack, cmds, altstack, z)?
                && operation(OpCodeFunctions::op_verify(), stack, cmds, altstack, z)?;
            Ok(ans)
        }
        OpCodeFunctions::OpEqual(_) => op_equal(stack),
        OpCodeFunctions::OpHash256(_) => {
            if stack.len() < 1 {
                return Ok(false);
            }
            let element = stack
                .pop()
                .context("unable to pop element from the stack")?;
            stack.push(utils::hash256(&element));
            return Ok(true);
        }
        OpCodeFunctions::OpVerify(_) => op_verify(stack),
        OpCodeFunctions::Op6(_) => {
            stack.push(encode_num(6)?);
            Ok(true)
        }
        OpCodeFunctions::OpAdd(_) => {
            if stack.len() < 2 {
                return Ok(false);
            }
            let element1 = decode_num(
                stack
                    .pop()
                    .context("unable to pop element from the stack")?,
            );
            let element2 = decode_num(
                stack
                    .pop()
                    .context("unable to pop element from the stack")?,
            );
            stack.push(encode_num(element1 + element2)?);
            return Ok(true);
        }
        OpCodeFunctions::OpMul(_) => {
            if stack.len() < 2 {
                return Ok(false);
            }
            let element1 = decode_num(
                stack
                    .pop()
                    .context("unable to pop element from the stack")?,
            );
            let element2 = decode_num(
                stack
                    .pop()
                    .context("unable to pop element from the stack")?,
            );
            stack.push(encode_num(element1 * element2)?);
            return Ok(true);
        }
        OpCodeFunctions::Op2(_) => {
            stack.push(encode_num(2)?);
            Ok(true)
        }
        OpCodeFunctions::Op2dup(_) => {
            if stack.len() < 2 {
                return Ok(false);
            }
            stack.append(&mut stack[stack.len() - 2..].to_vec());
            return Ok(true);
        }
        OpCodeFunctions::OpSwap(_) => {
            if stack.len() < 2 {
                return Ok(false);
            }
            let len = stack.len();
            stack.swap(len - 1, len - 2);
            return Ok(true);
        }
        OpCodeFunctions::OpNot(_) => {
            if stack.len() < 2 {
                return Ok(false);
            }
            if decode_num(
                stack
                    .pop()
                    .context("unable to pop element from the stack")?,
            ) == 0
            {
                stack.push(encode_num(1)?)
            } else {
                stack.push(encode_num(0)?)
            }
            return Ok(true);
        }
        OpCodeFunctions::OpSha1(_) => {
            if stack.len() < 1 {
                return Ok(false);
            }
            let mut out = [0u8; 20];
            let element = stack
                .pop()
                .context("unable to pop element from the stack")?;
            let mut hasher = Sha1::new();
            hasher.input(element.as_slice());
            hasher.result(&mut out);
            stack.push(out.to_vec());
            return Ok(true);
        }
        OpCodeFunctions::OpSigHashAll(_) => todo!(),
        OpCodeFunctions::OpCheckMultisig(_) => {
            if stack.len() < 1 {
                return Ok(false);
            }
            let n = decode_num(
                stack
                    .pop()
                    .context("unable to pop element from the stack")?,
            ) as usize;
            if stack.len() < n + 1 {
                return Ok(false);
            }
            let mut sec_pubkeys: Vec<S256Point> = Vec::with_capacity(n);
            for _ in 0..n {
                let sec_pubkey = stack
                    .pop()
                    .context("unable to pop element from the stack")?;
                let point = S256Point::parse(&sec_pubkey)?;
                sec_pubkeys.push(point);
            }
            let m = decode_num(
                stack
                    .pop()
                    .context("unable to pop element from the stack")?,
            ) as usize;
            if stack.len() < m + 1 {
                return Ok(false);
            }
            let mut der_signatures: Vec<Signature> = Vec::with_capacity(n);
            for _ in 0..m {
                // each DER signature is assumed to be signed with SIGHASH_ALL
                let mut der_signature = stack
                    .pop()
                    .context("unable to pop element from the stack")?;
                der_signature
                    .pop()
                    .context("unable to pop element from the stack")?;
                let mut der_signature_cursor = Cursor::new(der_signature);
                let sig = Signature::parse(&mut der_signature_cursor)?;
                der_signatures.push(sig);
            }

            // off-by-one error
            stack
                .pop()
                .context("unable to pop element from the stack")?;

            sec_pubkeys.reverse();
            for sig in der_signatures {
                if sec_pubkeys.len() == 0 {
                    return Ok(false);
                }
                while sec_pubkeys.len() > 0 {
                    let point = sec_pubkeys
                        .pop()
                        .context("unable to pop element from the stack")?;
                    let check = point.verify(z, sig.clone())?;
                    if check {
                        break;
                    }
                }
            }
            stack.push(encode_num(1)?);
            return Ok(true);
        }
        OpCodeFunctions::OpNop(_) => return Ok(true),
        OpCodeFunctions::OpUnknown(_) => return Ok(false),
    }
}

pub fn encode_num(num: i32) -> Result<Vec<u8>> {
    if num == 0 {
        return Ok(b"".to_vec());
    }
    let mut abs_num = num.abs();
    let negative = num < 0;
    let mut result: Vec<u8> = Vec::new();
    while abs_num > 0 {
        result.append(&mut utils::i32_to_little_endian(abs_num & 0xff, 1)?);
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
    Ok(result)
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
    use anyhow::Ok;

    use crate::{op::decode_num, signature::Signature};

    use super::{encode_num, operation, OpCodeFunctions};
    use anyhow::Result;

    #[test]
    fn test_encode_num() -> Result<()> {
        assert_eq!("e703", hex::encode(encode_num(999)?));
        assert_eq!("01", hex::encode(encode_num(1)?));
        assert_eq!("02", hex::encode(encode_num(2)?));
        assert_eq!("", hex::encode(encode_num(0)?));
        Ok(())
    }

    #[test]
    fn test_decode_num() -> Result<()> {
        assert_eq!(1, decode_num(hex::decode("01")?));
        assert_eq!(2, decode_num(hex::decode("02")?));
        assert_eq!(999, decode_num(hex::decode("e703")?));
        assert_eq!(0, decode_num(hex::decode("")?));
        Ok(())
    }

    #[test]
    fn test_op_checkmultisig() -> Result<()> {
        let op_code = OpCodeFunctions::op_checkmultisig();
        let z_raw =
            hex::decode("e71bfa115715d6fd33796948126f40a8cdd39f187e4afb03896795189fe1423c")?;
        let z = Signature::signature_hash_from_vec(z_raw);
        let sig1 = hex::decode("3045022100dc92655fe37036f47756db8102e0d7d5e28b3beb83a8fef4f5dc0559bddfb94e02205a36d4e4e6c7fcd16658c50783e00c341609977aed3ad00937bf4ee942a8993701")?;
        let sig2 = hex::decode("3045022100da6bee3c93766232079a01639d07fa869598749729ae323eab8eef53577d611b02207bef15429dcadce2121ea07f233115c6f09034c0be68db99980b9a6c5e75402201")?;
        let sec1 =
            hex::decode("022626e955ea6ea6d98850c994f9107b036b1334f18ca8830bfff1295d21cfdb70")?;
        let sec2 =
            hex::decode("03b287eaf122eea69030a0e9feed096bed8045c8b98bec453e1ffac7fbdbd4bb71")?;
        let mut stack = vec![
            [0_u8].to_vec(),
            sig1,
            sig2,
            [2_u8].to_vec(),
            sec1,
            sec2,
            [2_u8].to_vec(),
        ];
        let mut cmds = Vec::new();
        let mut altstack = Vec::new();
        let res = operation(op_code, &mut stack, &mut cmds, &mut altstack, &z)?;
        assert!(res);
        let stack_elm = &stack[0];
        assert_eq!(decode_num(stack_elm.clone()), 1);
        Ok(())
    }
}
