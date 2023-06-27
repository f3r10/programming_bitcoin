use core::panic;
use std::{
    fmt::Display,
    io::Cursor,
    ops::Add,
    vec,
};

use crate::{
    op::{self, OpCodeFunctions},
    signature::SignatureHash,
    utils::{self, encode_varint},
};
use anyhow::{bail, Context, Result};
use tokio::io::AsyncReadExt;

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

    pub async fn parse<R: tokio::io::AsyncBufRead + Unpin>(stream: &mut R) -> Result<Self> {
        let length = utils::read_varint_async(stream).await?;
        let mut cmds: Vec<Command> = Vec::new();
        let mut count = 0_u64;
        while count < length {
            let mut current_buf = vec![0; 1];
            stream.read_exact(&mut current_buf).await?;
            count += 1;
            let current_byte = current_buf[0] as u32;
            if current_byte >= 1 && current_byte <= 75 {
                let mut temp = vec![0; current_byte.try_into()?];
                stream.read_exact(&mut temp).await?;
                let elem = Command::Element(temp);
                cmds.push(elem);
                count += u8::from_le_bytes(current_buf.try_into().unwrap()) as u64;
            } else if current_byte == 76 {
                let mut temp = vec![0; 1];
                stream.read_exact(&mut temp).await?;
                let data_length = u8::from_le_bytes(temp.try_into().unwrap()) as u64;
                let mut temp = vec![0; data_length.try_into()?];
                stream.read_exact(&mut temp).await?;
                let elem = Command::Element(temp);
                cmds.push(elem);
                count += data_length + 1;
            } else if current_byte == 77 {
                let mut temp = vec![0; 2];
                stream.read_exact(&mut temp).await?;
                let data_length = u16::from_le_bytes(temp.try_into().unwrap()) as u64;
                let mut temp = vec![0; data_length.clone().try_into()?];
                stream.read_exact(&mut temp).await?;
                let elem = Command::Element(temp);
                cmds.push(elem);
                count += data_length + 2;
            } else {
                let op_code = op::parse_raw_op_codes(current_byte);
                let op = Command::Operation(op_code);
                cmds.push(op);
            }
        }
        if count != length {
            bail!("parsing script failed")
        }

        Ok(Script { cmds })
    }

    pub fn is_p2sh_script_pubkey(&self) -> bool {
        let cmds_copy = self.cmds.clone();
        let pattern1 = cmds_copy.len() == 3;
        let pattern2 = match &cmds_copy[0] {
            Command::Element(_) => false,
            Command::Operation(cmd) => cmd.as_ref() == OpCodeFunctions::op_hash160().as_ref(),
        };
        let pattern3_4 = match &cmds_copy[1] {
            Command::Element(bytes) => bytes.len() == 20,
            Command::Operation(_) => false,
        };
        let pattern5 = match &cmds_copy[2] {
            Command::Element(_) => false,
            Command::Operation(cmd) => cmd.as_ref() == OpCodeFunctions::op_equal().as_ref(),
        };

        pattern1 && pattern2 && pattern3_4 & pattern5
    }

    pub fn is_p2pkh_script_pubkey(&self) -> bool {
        let cmds_copy = self.cmds.clone();
        let pattern1 = cmds_copy.len() == 5;
        let pattern2 = match &cmds_copy[0] {
            Command::Element(_) => false,
            Command::Operation(cmd) => cmd.as_ref() == OpCodeFunctions::op_dup().as_ref(),
        };
        let pattern3 = match &cmds_copy[1] {
            Command::Element(_) => false,
            Command::Operation(cmd) => cmd.as_ref() == OpCodeFunctions::op_hash160().as_ref() ,
        };
        let pattern4_5 = match &cmds_copy[2] {
            Command::Element(bytes) => bytes.len() == 20,
            Command::Operation(_) => false,
        };

        let pattern6 = match &cmds_copy[3] {
            Command::Element(_) => false,
            Command::Operation(cmd) => cmd.as_ref() == OpCodeFunctions::op_equalverify().as_ref(),
        };

        let pattern7 = match &cmds_copy[4] {
            Command::Element(_) => false,
            Command::Operation(cmd) => cmd.as_ref() == OpCodeFunctions::op_checksig().as_ref(),
        };

        pattern1 && pattern2 && pattern3 && pattern4_5 && pattern6 && pattern7
    }

    pub async fn evaluate(self, z: SignatureHash) -> Result<bool> {
        let mut cmds_copy = self.cmds.clone();
        let mut stack: Vec<Vec<u8>> = Vec::new();
        let mut altstack: Vec<Vec<u8>> = Vec::new();
        while cmds_copy.len() > 0 {
            let cmd = cmds_copy.remove(0);
            match cmd {
                Command::Element(elem) => {
                    stack.push(elem.to_vec());
                    if self.is_p2sh_script_pubkey() {
                        cmds_copy.pop().context("unable to pop cmd")?; //this is op_hash160
                        let h160 = match cmds_copy.pop().context("unable to pop cmd")? {
                            Command::Element(elem) => elem,
                            Command::Operation(_) => {
                                panic!("invalid state after checking for redeemscript")
                            }
                        };
                        cmds_copy.pop().context("unable to pop cmd")?; //this is op_equal
                        if !op::op_hash160(&mut stack)? {
                            return Ok(false);
                        }
                        stack.push(h160);
                        if !op::op_equal(&mut stack)? {
                            return Ok(false);
                        }

                        if !op::op_verify(&mut stack)? {
                            return Ok(false);
                        }
                        let redeem_script = vec![encode_varint(elem.len())?, elem].concat();
                        let mut stream = Cursor::new(redeem_script);
                        let mut checkmultisigcmds = Script::parse(&mut stream).await?.cmds;
                        cmds_copy.append(&mut checkmultisigcmds)
                    }
                }
                Command::Operation(op_code) => {
                    let result = op::operation(
                        op_code.clone(),
                        &mut stack,
                        &mut cmds_copy,
                        &mut altstack,
                        &z,
                    )?;
                    if !result {
                        panic!("bad op")
                    }
                }
            }
        }
        if stack.len() == 0 {
            return Ok(false);
        }
        if stack
            .pop()
            .context("unable to pop element from the stack")?
            == b""
        {
            return Ok(false);
        }

        return Ok(true);
    }

    fn raw_serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<u8> = Vec::new();
        for cmd in &self.cmds {
            match cmd {
                Command::Element(element) => {
                    let length = element.len();
                    if length < 75 {
                        result.append(&mut utils::usize_to_little_endian(length, 1)?)
                    } else if length > 75 && length < 0x100 {
                        result.append(&mut utils::usize_to_little_endian(76, 1)?);
                        result.append(&mut utils::usize_to_little_endian(length, 1)?)
                    } else if length >= 0x100 && length <= 520 {
                        result.append(&mut utils::usize_to_little_endian(77, 1)?);
                        result.append(&mut utils::usize_to_little_endian(length, 2)?)
                    } else {
                        panic!("too long an cmd")
                    }
                    result.append(&mut element.clone())
                }
                Command::Operation(op) => {
                    result.append(&mut utils::u32_to_little_endian(op.as_ref().clone(), 1)?)
                }
            };
        }
        Ok(result)
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let result = self.raw_serialize()?;
        let total = result.len();
        Ok([utils::encode_varint(total)?, result].concat())
    }

    pub fn address(&self, testnet: bool) -> Result<String> {
        if self.is_p2pkh_script_pubkey() {
            match &self.cmds[2] {
                Command::Element(h160) => {
                    return utils::h160_to_p2pkh_address(&h160, testnet)
                },
                Command::Operation(_) => bail!("invalid cmd"),
            }
        } else if self.is_p2sh_script_pubkey() {
            match &self.cmds[1] {
                Command::Element(h160) => {
                    return utils::h160_to_p2psh_address(&h160, testnet)
                },
                Command::Operation(_) => bail!("invalid cmd"),
            }
        } else {
            bail!("unable to identify script_pubkey type")
        }
    }
}

impl Display for Script {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result: Vec<String> = Vec::new();
        for cmd in &self.cmds {
            match cmd {
                Command::Element(elm) => {
                    let name = hex::encode(elm);
                    result.push(name);
                }
                Command::Operation(op) => {
                    let name = op::get_op_names(op);
                    result.push(name.to_string())
                }
            }
        }
        let fmt_opcodes = result.join(" ");
        writeln!(f, "{}", fmt_opcodes)
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

    use crate::{op, signature::Signature, utils};

    use super::{Command, Script};
    use anyhow::Result;

    #[tokio::test]
    async fn test_parse_script() -> Result<()> {
        let s = hex::decode("6a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937")?;
        let mut cursor = Cursor::new(s);
        let s = Script::parse(&mut cursor).await?;
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
        };
        Ok(())
    }
    #[tokio::test]
    async fn test_evaluate_script() -> Result<()> {
        let z = Signature::signature_hash_from_hex(
            "7c076ff316692a3d7eb3c3bb0f8b1488cf72e1afcd929e29307032997a838a3d",
        )?;
        let sec = "04887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34";
        let sec_encode = hex::decode(sec)?;
        let sig = "3045022000eff69ef2b1bd93a66ed5219add4fb51e11a840f404876325a1e8ffe0529a2c022100c7207fee197d27c618aea621406f6bf5ef6fca38681d82b2f06fddbdce6feab6";
        let sig_encode = hex::decode(sig)?;
        let cmd = vec![
            Command::Element(sec_encode),
            Command::Operation(op::parse_raw_op_codes(0xac)), //OpVerify
        ];
        let script_pubkey = Script::new(Some(cmd));
        let script_sig = Script::new(Some(vec![Command::Element(sig_encode)]));
        let combined_script = script_sig + script_pubkey;
        assert!(combined_script.evaluate(z).await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_scriptsig_genesis_coinbase_tx() -> Result<()> {
        let raw_scriptsig = hex::decode("4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73")?;
        let mut stream = Cursor::new(raw_scriptsig);
        let s = Script::parse(&mut stream).await?;
        let a = match &s.cmds[2] {
            Command::Element(r) => String::from_utf8(r.to_vec())?,
            Command::Operation(_) => "Op".to_string(),
        };
        assert_eq!(
            "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks",
            a
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_scriptsig_coinbase_tx() -> Result<()> {
        let raw_scriptsig = hex::decode("5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00")?;
        let mut stream = Cursor::new(raw_scriptsig);
        let s = Script::parse(&mut stream).await?;
        match &s.cmds[0] {
            Command::Element(v) => assert_eq!(BigInt::from(465879), utils::little_endian_to_int(v)),
            Command::Operation(_) => assert!(false),
        };
        Ok(())
    }
}
