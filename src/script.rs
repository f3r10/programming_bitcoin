use core::panic;
use std::{io::Read, ops::Add, vec};

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use num_bigint::BigInt;

use crate::{
    op::{self, OpCodeFunctions},
    utils,
};

#[derive(Debug, Clone)]
pub enum Command {
    Element(Vec<u8>),
    Operation(OpCodeFunctions),
}

#[derive(Debug, Clone)]
pub struct Script {
    pub cmds: Vec<Command>,
}

impl Script {
    pub fn new(cmds: Option<Vec<Command>>) -> Self {
        match cmds {
            None => Script { cmds: Vec::new() },
            Some(cmds) => Script { cmds },
        }
    }

    pub fn parse<R: Read>(stream: &mut R) -> Self {
        let length = utils::read_varint(stream);
        let mut cmds: Vec<Command> = Vec::new();
        let mut count = 0_u32;
        let length_buf = length.to_signed_bytes_be();
        let length = BigEndian::read_int(&length_buf, length_buf.len()) as u32;
        while count < length {
            let mut current = vec![0; 1];
            stream.read_exact(&mut current).unwrap();
            count += 1;
            let current_byte = BigEndian::read_int(&current, 1) as u32;
            if current_byte >= 1 && current_byte <= 75 {
                let mut temp = vec![0; current_byte.try_into().unwrap()];
                stream.read_exact(&mut temp).unwrap();
                let elem = Command::Element(temp);
                cmds.push(elem);
                count += current_byte;
            } else if current_byte == 76 {
                let mut temp = vec![0; 1];
                stream.read_exact(&mut temp).unwrap();
                let data_length = LittleEndian::read_int(&temp, temp.len()) as u32;
                let mut temp = vec![0; data_length.try_into().unwrap()];
                stream.read_exact(&mut temp).unwrap();
                let elem = Command::Element(temp);
                cmds.push(elem);
                count += data_length + 1;
            } else if current_byte == 77 {
                let mut temp = vec![0; 2];
                stream.read_exact(&mut temp).unwrap();
                let data_length = LittleEndian::read_int(&temp, temp.len()) as u32;
                let mut temp = vec![0; data_length.clone().try_into().unwrap()];
                stream.read_exact(&mut temp).unwrap();
                let elem = Command::Element(temp);
                cmds.push(elem);
                count += data_length + 2;
            } else {
                let mut num = vec![0, 0, 0];
                num.append(&mut current.clone());
                let op_code = op::parse_op_codes(BigEndian::read_u32(&num));
                let op = Command::Operation(op_code);
                cmds.push(op);
            }
        }
        if count != length {
            panic!("parsing script failed")
        }

        Script { cmds }
    }

    pub fn evaluate(self, z: BigInt) -> bool {
        let mut cmds_copy = self.cmds.clone();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();
        while cmds_copy.len() > 0 {
            let cmd = cmds_copy.remove(0);
            match cmd {
                Command::Element(elem) => stack.push(elem.to_vec()),
                Command::Operation(op_code) => {
                    let result = op::operation(
                        op_code.clone(),
                        &mut stack,
                        &mut cmds_copy,
                        &mut altstack,
                        z.clone(),
                    );
                    if !result {
                        panic!("bad op")
                    }
                }
            }
        }
        if stack.len() == 0 {
            return false;
        }
        if stack.pop().unwrap() == b"" {
            return false;
        }

        return true;
    }

    fn raw_serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();
        for cmd in &self.cmds {
            match cmd {
                Command::Element(element) => {
                    let length = element.len();
                    if length < 75 {
                        result.append(&mut utils::usize_to_little_endian(length, 1))
                    } else if length > 75 && length < 0x100 {
                        result.append(&mut utils::usize_to_little_endian(76, 1));
                        result.append(&mut utils::usize_to_little_endian(length, 1))
                    } else if length >= 0x100 && length <= 520 {
                        result.append(&mut utils::usize_to_little_endian(77, 1));
                        result.append(&mut utils::usize_to_little_endian(length, 2))
                    } else {
                        panic!("too long an cmd")
                    }
                    result.append(&mut element.clone())
                }
                Command::Operation(op) => {
                    result.append(&mut utils::u32_to_little_endian(op.as_ref().clone(), 1))
                }
            };
        }
        result
    }

    pub fn serialize(&self) -> Vec<u8> {
        let result = self.raw_serialize();
        let total = result.len();
        [utils::encode_varint(total), result].concat()
    }
}

impl Add for Script {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Script {
            cmds: [self.cmds, rhs.cmds].concat(),
        }
    }
}

#[cfg(test)]
mod script_tests {
    use std::io::Cursor;

    use num_bigint::BigInt;

    use crate::op;

    use super::{Command, Script};

    #[test]
    fn test_parse_script() {
        let s = hex::decode("6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937").unwrap();
        let mut cursor = Cursor::new(s);
        let s = Script::parse(&mut cursor);
        match &s.cmds[0] {
            super::Command::Element(elm) => assert_eq!(hex::encode(elm), "304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601"),
            super::Command::Operation(_) => assert!(false),
        }
        match &s.cmds[1] {
            super::Command::Element(elem) => assert_eq!(
                hex::encode(elem),
                "035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937"
            ),
            super::Command::Operation(_) => assert!(false),
        }
    }
    #[test]
    fn test_evaluate_script() {
        let z: BigInt = BigInt::parse_bytes(
            b"7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
            16,
        )
        .unwrap();
        let sec = "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34";
        let sec_encode = hex::decode(sec).unwrap();
        let sig = "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        let sig_encode = hex::decode(sig).unwrap();
        let cmd = vec![
            Command::Element(sec_encode),
            Command::Operation(op::parse_op_codes(0xac)),
        ];
        let script_pubkey = Script::new(Some(cmd));
        let script_sig = Script::new(Some(vec![Command::Element(sig_encode)]));
        let combined_script = script_sig + script_pubkey;
        assert!(combined_script.evaluate(z))
    }
}
