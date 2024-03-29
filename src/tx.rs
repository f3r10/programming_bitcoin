use std::{fmt::Display, io::Cursor};

use anyhow::{bail, Context, Result};
use byteorder::{ByteOrder, LittleEndian};
use num_bigint::BigInt;
use tokio::io::{AsyncReadExt, AsyncSeek, AsyncSeekExt};

use crate::{
    op::OpCodeFunctions,
    private_key::PrivateKey,
    script::{Command, Script},
    signature::Signature,
    tx_fetcher::TxFetcher,
    utils,
};

#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: u64, // TODO change u64
    pub script_pubkey: Script,
}

#[derive(Debug, Clone)]
pub enum TxInWitness {
    SimpleNumber(u32),
    ComplexElem(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_tx: Vec<u8>,
    pub prev_index: u32,
    pub script_sig: Option<Script>,
    pub sequence: Option<u32>,
    pub witness: Option<Vec<TxInWitness>>,
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub version: u32,
    pub tx_ins: Vec<TxIn>,
    pub tx_outs: Vec<TxOut>,
    pub locktime: u32,
    pub testnet: bool,
    pub segwit: bool,
    pub _hash_prevouts: Vec<u8>,
    pub _hash_sequence: Vec<u8>,
    pub _hash_outputs: Vec<u8>,
}

impl Tx {
    pub fn new(
        version: u32,
        tx_ins: Vec<TxIn>,
        tx_outs: Vec<TxOut>,
        locktime: u32,
        testnet: bool,
        segwit: bool,
    ) -> Self {
        Tx {
            version,
            tx_ins,
            tx_outs,
            locktime,
            testnet,
            segwit,
            _hash_prevouts: Vec::new(),
            _hash_sequence: Vec::new(),
            _hash_outputs: Vec::new(),
        }
    }

    pub async fn parse<R: tokio::io::AsyncBufRead + Unpin + AsyncSeek>(
        stream: &mut R,
        testnet: bool,
    ) -> Result<Self> {
        let mut buffer = [0; 4];

        let mut handle = stream.take(4);
        handle.read_exact(&mut buffer).await?;
        let version = LittleEndian::read_u32(&buffer); // utils::little_endian_to_int(&amount_buffer);
        let pos = stream.stream_position().await?;

        // The next two bytes represents if the TX is segwit
        // Not all TX's have this mark so if not, it is necessary to restart the position.
        let mut segwit = false;
        let mut marker = [0; 2];
        let mut handle = stream.take(2);
        handle.read_exact(&mut marker).await?;
        if marker == [0_u8, 1_u8] {
            segwit = true
        } else {
            stream.seek(std::io::SeekFrom::Start(pos)).await?;
        }
        let num_inputs = utils::read_varint_async(stream).await?;
        let mut inputs: Vec<TxIn> = Vec::new();
        for _ in 0..num_inputs {
            inputs.push(TxIn::parse(stream).await?)
        }
        let num_outputs = utils::read_varint_async(stream).await?;
        let mut outputs: Vec<TxOut> = Vec::new();
        for _ in 0..num_outputs {
            outputs.push(TxOut::parse(stream).await?)
        }
        if segwit {
            for mut tx_in in inputs.iter_mut() {
                let num_items = utils::read_varint_async(stream).await?;
                let mut items = Vec::new();
                for _ in 0..num_items {
                    let item_len = utils::read_varint_async(stream).await?;
                    if item_len == 0 {
                        items.push(TxInWitness::SimpleNumber(0))
                    } else {
                        let mut buffer = vec![0; item_len as usize];
                        let mut handle = stream.take(item_len);
                        handle.read_exact(&mut buffer).await?;
                        items.push(TxInWitness::ComplexElem(buffer))
                    }
                    tx_in.witness = Some(items.clone());
                }
            }
        }
        let mut locktime_buffer = [0; 4];
        stream.read_exact(&mut locktime_buffer).await?;
        let locktime = LittleEndian::read_u32(&locktime_buffer);
        Ok(Tx {
            version,
            tx_ins: inputs,
            tx_outs: outputs,
            locktime,
            testnet,
            segwit,
            _hash_prevouts: Vec::new(),
            _hash_sequence: Vec::new(),
            _hash_outputs: Vec::new(),
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(self.version.to_le_bytes().to_vec());
        if self.segwit {
            result.push([0_u8, 1_u8].to_vec())
        }
        result.push(utils::encode_varint(self.tx_ins.len())?);
        for tx_in in &self.tx_ins {
            let intx = tx_in.serialize()?;
            result.push(intx)
        }
        result.push(utils::encode_varint(self.tx_outs.len())?);
        for tx_out in &self.tx_outs {
            let outx = tx_out.serialize()?;
            result.push(outx)
        }
        if self.segwit {
            for tx_in in &self.tx_ins {
                match &tx_in.witness {
                    Some(witness) => {
                        for elem_witness in witness {
                            match elem_witness {
                                TxInWitness::SimpleNumber(num) => {
                                    result.push(utils::u32_to_little_endian(*num, 1)?)
                                }
                                TxInWitness::ComplexElem(elem) => {
                                    result.push(utils::encode_varint(elem.len())?);
                                    result.push(elem.to_vec());
                                }
                            }
                        }
                    }
                    None => bail!("tx is marked as segwit but witness is not present"),
                }
            }
        }
        result.push(self.locktime.to_le_bytes().to_vec());
        Ok(result.concat())
    }

    pub async fn fee(&self, testnet: bool) -> Result<BigInt> {
        let mut tx_ins_total = BigInt::from(0);
        for tx_in in &self.tx_ins {
            tx_ins_total += tx_in.value(testnet).await?;
        }

        let mut tx_outs_total = BigInt::from(0);
        for tx_out in &self.tx_outs {
            tx_outs_total += tx_out.amount.clone();
        }
        Ok(tx_ins_total - tx_outs_total)
    }

    pub async fn sig_hash(
        &self,
        input_index: usize,
        redeem_script: Option<Script>,
    ) -> Result<BigInt> {
        let mut s = self.version.to_le_bytes().to_vec();
        s.append(&mut utils::encode_varint(self.tx_ins.len())?);
        for (i, tx_in) in self.tx_ins.iter().enumerate() {
            let script_sig: Option<Script>;
            if i == input_index {
                match redeem_script.as_ref() {
                    Some(redeem) => script_sig = Some(redeem.clone()),
                    None => script_sig = Some(tx_in.script_pubkey(self.testnet).await?),
                }
            } else {
                script_sig = None;
            }
            let mut tx = TxIn::new(
                tx_in.prev_tx.clone(),
                tx_in.prev_index.clone(),
                script_sig,
                tx_in.sequence.clone(),
                None,
            )
            .serialize()?;
            s.append(&mut tx);
        }

        s.append(&mut utils::encode_varint(self.tx_outs.len())?);
        for tx_out in &self.tx_outs {
            s.append(&mut tx_out.clone().serialize()?)
        }
        s.append(&mut self.locktime.to_le_bytes().to_vec());
        s.append(&mut utils::u32_to_little_endian(
            *OpCodeFunctions::op_sig_hash_all().as_ref(),
            4,
        )?);
        let hash = utils::hash256(&s);
        return Ok(BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash));
    }

    pub fn hash_prevouts(&mut self) -> Result<Vec<u8>> {
        if self._hash_prevouts.is_empty() {
            let mut all_prevouts: Vec<Vec<u8>> = Vec::new();
            let mut all_sequence: Vec<Vec<u8>> = Vec::new();
            for tx_in in &self.tx_ins {
                let mut prev_tx = tx_in.prev_tx.clone();
                prev_tx.reverse();
                all_prevouts.push(prev_tx);
                all_prevouts.push(tx_in.prev_index.to_le_bytes().to_vec());
                match tx_in.sequence.as_ref() {
                    Some(s) => all_sequence.push(s.to_le_bytes().to_vec()),
                    None => all_sequence.push(utils::u32_to_little_endian(0xffffffff, 4)?),
                }
            }
            self._hash_prevouts = utils::hash256(&all_prevouts.concat());
            self._hash_sequence = utils::hash256(&all_sequence.concat());
        }
        Ok(self._hash_prevouts.to_vec())
    }

    pub fn hash_sequence(&mut self) -> Result<Vec<u8>> {
        if self._hash_sequence.is_empty() {
            self.hash_prevouts()?;
        }
        Ok(self._hash_sequence.to_vec())
    }

    pub fn hash_ouputs(&mut self) -> Result<Vec<u8>> {
        if self._hash_outputs.is_empty() {
            let mut all_outputs: Vec<Vec<u8>> = Vec::new();
            for tx_out in &self.tx_outs {
                all_outputs.push(tx_out.serialize()?);
            }
            self._hash_outputs = utils::hash256(&all_outputs.concat());
        }

        Ok(self._hash_outputs.to_vec())
    }

    pub async fn sig_hash_bip143(
        &mut self,
        input_index: usize,
        redeem_script: Option<Script>,
        witness_script: Option<Script>,
    ) -> Result<BigInt> {
        let tx_in = self.tx_ins[input_index].clone();
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(self.version.to_le_bytes().to_vec());
        result.push(self.hash_prevouts()?);
        result.push(self.hash_sequence()?);
        let mut prev_tx = tx_in.prev_tx.clone();
        prev_tx.reverse();
        result.push(prev_tx);
        result.push(tx_in.prev_index.to_le_bytes().to_vec());
        let script_code: Vec<u8>;
        if let Some(witness) = witness_script {
            script_code = witness.serialize()?;
        } else if let Some(redeem) = redeem_script {
            match &redeem.cmds[1] {
                Command::Element(elm) => {
                    script_code = utils::p2pkh_script(elm.clone()).serialize()?;
                }
                Command::Operation(_) => bail!("redeem script should be an command element"),
            }
        } else {
            match &tx_in.script_pubkey(self.testnet).await?.cmds[1] {
                Command::Element(elm) => {
                    script_code = utils::p2pkh_script(elm.clone()).serialize()?;
                }
                Command::Operation(_) => bail!("default case should be an command element"),
            }
        }
        result.push(script_code);
        result.push(tx_in.value(self.testnet).await?.to_le_bytes().to_vec());
        match tx_in.sequence.as_ref() {
            Some(s) => result.push(s.to_le_bytes().to_vec()),
            None => result.push(utils::u32_to_little_endian(0xffffffff, 4)?),
        }
        result.push(self.hash_ouputs()?);
        result.push(self.locktime.to_le_bytes().to_vec());
        result.push(1_u32.to_le_bytes().to_vec());
        let hash = utils::hash256(&result.concat());
        return Ok(BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash));
    }

    pub async fn verify_input(&mut self, input_index: usize) -> Result<bool> {
        let tx_in = self.tx_ins[input_index].clone();
        let script_pubkey = tx_in.script_pubkey(self.testnet).await?;
        let z: BigInt;
        let witness: Option<Vec<TxInWitness>>;
        if script_pubkey.is_p2sh_script_pubkey() {
            // OP_0 , SIG1, SIG2, ..., RedeemScript
            let cmd = match tx_in
                .script_sig
                .as_ref()
                .context("unable to get script_sig as ref")?
                .cmds
                .last()
                .context("unable to get last cmd form script_sig")?
            {
                Command::Element(elm) => elm,
                Command::Operation(_) => panic!("invalid last Cmd for redeem script"),
            };
            let raw_redeem = [utils::encode_varint(cmd.len())?, cmd.to_vec()].concat();
            let mut raw_redeem_cursor = Cursor::new(raw_redeem);
            let _redeem_script = Script::parse(&mut raw_redeem_cursor).await?;
            if _redeem_script.is_p2wpkh_script_pubkey() {
                z = self
                    .sig_hash_bip143(input_index, Some(_redeem_script), None)
                    .await?;
                witness = tx_in.witness.clone();
            } else if _redeem_script.is_p2wsh_script_pubkey() {
                let command = match &tx_in.witness {
                    Some(witness) => match witness.last() {
                        Some(last_witness_elm) => match last_witness_elm {
                            TxInWitness::SimpleNumber(num) => utils::u32_to_little_endian(*num, 1)?,
                            TxInWitness::ComplexElem(elm) => elm.to_vec(),
                        },
                        None => bail!("is_p2wsh_script_pubkey has an invalid witness"),
                    },
                    None => bail!("is_p2wsh_script_pubkey has an invalid witness"),
                };
                let raw_witness = [utils::encode_varint(command.len())?, command].concat();
                let mut raw_witness_cursor = Cursor::new(raw_witness);
                let witness_script = Script::parse(&mut raw_witness_cursor).await?;
                z = self
                    .sig_hash_bip143(input_index, None, Some(witness_script))
                    .await?;
                witness = tx_in.witness;
            } else {
                z = self.sig_hash(input_index, Some(_redeem_script)).await?;
                witness = None;
            }
        } else {
            if script_pubkey.is_p2wpkh_script_pubkey() {
                z = self.sig_hash_bip143(input_index, None, None).await?;
                witness = tx_in.witness.clone();
            } else if script_pubkey.is_p2wsh_script_pubkey() {
                let command = match &tx_in.witness {
                    Some(witness) => match witness.last() {
                        Some(last_witness_elm) => match last_witness_elm {
                            TxInWitness::SimpleNumber(num) => utils::u32_to_little_endian(*num, 1)?,
                            TxInWitness::ComplexElem(elm) => elm.to_vec(),
                        },
                        None => bail!("is_p2wsh_script_pubkey has an invalid witness"),
                    },
                    None => bail!("is_p2wsh_script_pubkey has an invalid witness"),
                };
                let raw_witness = [utils::encode_varint(command.len())?, command].concat();
                let mut raw_witness_cursor = Cursor::new(raw_witness);
                let witness_script = Script::parse(&mut raw_witness_cursor).await?;
                z = self
                    .sig_hash_bip143(input_index, None, Some(witness_script))
                    .await?;
                witness = tx_in.witness;
            } else {
                z = self.sig_hash(input_index, None).await?;
                witness = None;
            }
        }

        let z = Signature::signature_hash_from_int(z);
        match tx_in.script_sig.clone() {
            Some(script_sig) => {
                let combined = script_sig + script_pubkey;
                combined.evaluate(z, witness).await
            }
            None => Ok(false),
        }
    }

    pub async fn verify(&mut self) -> Result<bool> {
        if self.fee(self.testnet).await? < BigInt::from(0) {
            return Ok(false);
        } else {
            for i in 0..self.tx_ins.len() {
                if !self.verify_input(i).await? {
                    return Ok(false);
                }
            }
        }
        return Ok(true);
    }

    pub fn id(&self) -> Result<String> {
        Ok(hex::encode(self.hash()?))
    }

    fn hash(&self) -> Result<Vec<u8>> {
        let mut a = utils::hash256(&self.serialize()?);
        a.reverse();
        Ok(a)
    }

    pub async fn sign_input(
        &mut self,
        input_index: usize,
        private_key: PrivateKey,
    ) -> Result<bool> {
        let z = self.sig_hash(input_index, None).await?;
        let sign = private_key.sign(&Signature::signature_hash_from_int(z), None)?;
        let mut der_sighash = sign.der()?;
        der_sighash.append(&mut utils::u32_to_little_endian(
            *OpCodeFunctions::op_sig_hash_all().as_ref(),
            1,
        )?);
        // der_sighash.push(1);
        let sec = private_key.point.sec(Some(true))?;
        let script_sig = Script::new(Some(vec![
            Command::Element(der_sighash),
            Command::Element(sec),
        ]));
        self.tx_ins[input_index].script_sig = Some(script_sig);
        self.verify_input(input_index).await
    }

    pub fn is_coinbase(&self) -> bool {
        if self.tx_ins.len() > 1 {
            return false;
        }
        let tx_in = &self.tx_ins[0];
        if tx_in.prev_tx != [0_u8; 32] {
            return false;
        }
        if tx_in.prev_index != 0xffffffff {
            return false;
        }
        true
    }

    pub fn coinbase_height(&self) -> Option<BigInt> {
        if !self.is_coinbase() {
            return None;
        }
        let first_tx = &self.tx_ins[0];
        first_tx
            .script_sig
            .as_ref()
            .map(|script_sig| match &script_sig.cmds[0] {
                Command::Element(elm) => utils::little_endian_to_int(&elm),
                Command::Operation(_) => panic!("Invalid coinbase first cmd"),
            })
    }
}

impl Display for Tx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut tx_ins = String::new();
        for tx_in in &self.tx_ins {
            tx_ins += &format!("{}\n", tx_in);
        }
        let mut tx_outs = String::new();
        for tx_out in &self.tx_outs {
            tx_outs += &format!("{}\n", tx_out)
        }
        writeln!(
            f,
            "tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}",
            self.id().unwrap(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime
        )
    }
}

impl TxIn {
    pub fn new(
        prev_tx: Vec<u8>,
        prev_index: u32,
        script_sig: Option<Script>,
        sequence: Option<u32>,
        witness: Option<Vec<TxInWitness>>,
    ) -> Self {
        TxIn {
            prev_tx,
            prev_index,
            script_sig,
            sequence,
            witness,
        }
    }

    pub async fn parse<R: tokio::io::AsyncBufRead + Unpin>(stream: &mut R) -> Result<Self> {
        let mut prev_tx_buffer = [0; 32];
        stream.read_exact(&mut prev_tx_buffer).await?;
        prev_tx_buffer.reverse(); // because is little endian
        let mut prev_tx_index_buffer = [0; 4];
        stream.read_exact(&mut prev_tx_index_buffer).await?;
        let prev_index = LittleEndian::read_u32(&prev_tx_index_buffer);
        let script_sig = Script::parse(stream).await?;
        let mut sequence_buffer = [0; 4];
        stream.read_exact(&mut sequence_buffer).await?;
        let sequence = LittleEndian::read_u32(&sequence_buffer);
        Ok(TxIn {
            prev_tx: prev_tx_buffer.to_vec(),
            prev_index,
            script_sig: Some(script_sig),
            sequence: Some(sequence),
            witness: None,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        let mut prev_tx = self.prev_tx.clone();
        prev_tx.reverse();
        result.push(prev_tx);
        result.push(self.prev_index.to_le_bytes().to_vec());
        match &self.script_sig {
            Some(script_sig) => result.push(script_sig.serialize()?),
            None => result.push([0].to_vec()),
        };
        match self.sequence.as_ref() {
            Some(s) => result.push(s.to_le_bytes().to_vec()),
            None => result.push(utils::u32_to_little_endian(0xffffffff, 4)?),
        }
        Ok(result.concat())
    }

    pub async fn fetch_tx(&self, testnet: bool) -> Result<Tx> {
        let mut tx_fetcher = TxFetcher::new();
        tx_fetcher
            .fetch(&hex::encode(self.prev_tx.clone()), testnet, false)
            .await
    }

    pub async fn value(&self, testnet: bool) -> Result<u64> {
        let tx = self.fetch_tx(testnet).await?;
        let index = self.prev_index as usize;
        Ok(tx.tx_outs[index].amount.clone())
    }

    /// Fetch the TX
    pub async fn script_pubkey(&self, testnet: bool) -> Result<Script> {
        let tx = self.fetch_tx(testnet).await?;
        let index = self.prev_index as usize;
        Ok(tx.tx_outs[index].script_pubkey.clone())
    }
}

impl Display for TxIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            hex::encode(self.prev_tx.clone()),
            self.prev_index
        )
    }
}

impl TxOut {
    pub fn new(amount: u64, script_pubkey: Script) -> Self {
        TxOut {
            amount,
            script_pubkey,
        }
    }

    pub async fn parse<R: tokio::io::AsyncBufRead + Unpin>(stream: &mut R) -> Result<Self> {
        let mut amount_buffer = [0; 8];
        stream.read_exact(&mut amount_buffer).await?;
        let amount = LittleEndian::read_u64(&amount_buffer); // utils::little_endian_to_int(&amount_buffer);
        let script_pubkey = Script::parse(stream).await?;
        Ok(TxOut {
            amount,
            script_pubkey,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(self.amount.to_le_bytes().to_vec());
        result.push(self.script_pubkey.serialize()?);
        Ok(result.concat())
    }
}

impl Display for TxOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.amount, self.script_pubkey)
    }
}

#[cfg(test)]
mod tx_tests {
    use std::io::Cursor;

    use num_bigint::BigInt;

    use crate::{
        op::OpCodeFunctions,
        private_key::PrivateKey,
        s256_point::S256Point,
        script::{Command, Script},
        signature::Signature,
        tx::{TxIn, TxOut},
        tx_fetcher::TxFetcher,
        utils,
    };

    use super::Tx;
    use anyhow::{Context, Ok, Result};

    #[tokio::test]
    async fn test_tx_version() -> Result<()> {
        let raw_tx = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600")?;
        let mut stream = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut stream, false).await?;
        assert_eq!(tx.version, 1);
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_inputs() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        assert_eq!(tx.tx_ins.len(), 1);
        assert_eq!(tx.tx_ins[0].prev_index, 0);
        assert_eq!(
            hex::encode(tx.tx_ins[0].prev_tx.clone()),
            "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        );
        assert_eq!(hex::encode(tx.tx_ins[0].script_sig.clone().context("script_sig not present")?.serialize()?), "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a");
        assert_eq!(
            tx.tx_ins[0]
                .sequence
                .clone()
                .context("sequence not present")?,
            0xfffffffe_u32
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_outputs() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        assert_eq!(tx.tx_outs.len(), 2);
        assert_eq!(tx.tx_outs[0].amount, 32454049_u64);
        assert_eq!(
            hex::encode(tx.tx_outs[0].script_pubkey.serialize()?),
            "1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac"
        );
        assert_eq!(tx.tx_outs[1].amount, 10011545_u64);
        assert_eq!(
            hex::encode(tx.tx_outs[1].script_pubkey.serialize()?),
            "1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_parse_locktime() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        assert_eq!(tx.locktime, 410393);
        Ok(())
    }

    #[tokio::test]
    async fn test_tx_serialize() -> Result<()> {
        let tx = "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode.clone());
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        assert_eq!(tx_encode, tx.serialize()?);
        Ok(())
    }

    #[tokio::test]
    async fn test_long_tx() -> Result<()> {
        let tx = "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600";
        let tx_bytes = hex::decode(tx)?;
        let mut reader_mem = Cursor::new(tx_bytes);
        let tx_parsed = Tx::parse(&mut reader_mem, false).await?;
        //TODO add these tests when Script has a display impl
        // assert_eq!("304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937", hex::encode(tx_parsed.tx_ins[1].script_sig));
        // assert_eq!("", hex::encode(tx_parsed.tx_outs[0].script_pubkey.serialize()));
        assert_eq!(40000000_u64, tx_parsed.tx_outs[1].amount);
        Ok(())
    }

    #[tokio::test]
    async fn test_fee_tx() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        assert_eq!(tx.fee(false).await?, BigInt::from(40000));

        let tx = "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        assert_eq!(tx.fee(false).await?, BigInt::from(140500));
        Ok(())
    }

    #[tokio::test]
    async fn test_fee_positive_tx() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        assert!(tx.fee(false).await? > BigInt::from(0));
        Ok(())
    }

    #[tokio::test]
    async fn test_sig_hash_and_verify_input() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false).await?;
        let tx_sig_hash = tx.sig_hash(0, None).await?;
        assert_eq!(
            "18037338614366229343027734445863508930887653120159589908930024158807354868134",
            tx_sig_hash.to_string()
        );

        let der = "3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed";
        let sig_encode = hex::decode(der)?;
        let mut cursor_sig = Cursor::new(sig_encode);
        let sig_parsed = Signature::parse(&mut cursor_sig)?;
        let sec = "0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a";
        let sec_encode = hex::decode(sec)?;
        let point = S256Point::parse(&sec_encode)?;
        let z = Signature::signature_hash_from_int(tx_sig_hash);
        assert!(point.verify(&z, sig_parsed)?);
        Ok(())
    }

    #[tokio::test]
    async fn test_tx_verify() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let mut tx = Tx::parse(&mut cursor_tx, false).await?;
        assert!(tx.verify().await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_tx_signing() -> Result<()> {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let mut tx = Tx::parse(&mut cursor_tx, false).await?;
        let z = tx.sig_hash(0, None).await?;
        let private_key =
            PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(8675309)))?;
        let mut der_sighash = private_key
            .sign(&Signature::signature_hash_from_int(z), None)?
            .der()?;
        der_sighash.append(&mut utils::u32_to_little_endian(
            *OpCodeFunctions::op_sig_hash_all().as_ref(),
            1,
        )?);
        let sec = private_key.point.sec(Some(true))?;
        let script_sig = Script::new(Some(vec![
            Command::Element(der_sighash),
            Command::Element(sec),
        ]));
        tx.tx_ins[0].script_sig = Some(script_sig);
        assert_eq!("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006a47304402207db2402a3311a3b845b038885e3dd889c08126a8570f26a844e3e4049c482a11022010178cdca4129eacbeab7c44648bf5ac1f9cac217cd609d216ec2ebc8d242c0a012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67feffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600", hex::encode(tx.serialize()?));
        Ok(())
    }

    #[tokio::test]
    async fn test_tx_sign_input() -> Result<()> {
        let tx = "010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000";
        let tx_encode = hex::decode(tx)?;
        let mut cursor_tx = Cursor::new(tx_encode);
        let mut tx = Tx::parse(&mut cursor_tx, true).await?;
        let private_key =
            PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(8675309)))?;
        assert!(tx.sign_input(0, private_key).await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_tx_with_two_inputs_and_one_output() -> Result<()> {
        let want = "0100000002cca175bc8125f679bf21d76c3da4d08952f0ddc63dbe9d7f916306d7b0467517000000006b483045022100bd4a9297d5b000232f01093e8c4fec035b99ebef5de38e073ceded393c8488e3022079661ab7aa3f55ff37e2819029ed50eba163f24a44451d4eaa169f28a832b0ac012102a39eecbb9f8c6de1efec44c51e2e580dd790c2bd35e6fa1c9564ab7d794e3143ffffffff3bfe2faa0d5d64608ebe8dea810962bb35e1a29f8e35940f1e2787695355d13f010000006b483045022100c07f377818e8daa37bbfef1530694e85739df3a87819fcc0482891bacc6d6ef402206b7df12af9ff2fadad6815f157ede3a14d8e972a75f1586849ce18693766cf4e012102a39eecbb9f8c6de1efec44c51e2e580dd790c2bd35e6fa1c9564ab7d794e3143ffffffff0187611a00000000001976a914d5985c6d780579b61f9bff365a689b4fa2ec528988ac00000000";

        let prev_tx_faucet =
            hex::decode("177546b0d70663917f9dbe3dc6ddf05289d0a43d6cd721bf79f62581bc75a1cc")?;
        let prev_tx_faucet_index = 0;
        let prev_tx_ex4 =
            hex::decode("3fd155536987271e0f94358e9fa2e135bb620981ea8dbe8e60645d0daa2ffe3b")?;
        let prev_tx_ex4_index = 1;
        let target_address = "mzzLk9MmXzmjCBLgjoeNDxrbdrt511t5Gm";
        let target_amount = 0.01728903;
        let secret = "f3r10@programmingblockchain.com my secret";
        let priva = PrivateKey::new(&PrivateKey::generate_secret(secret))?;
        let mut tx_ins: Vec<TxIn> = Vec::new();
        tx_ins.push(TxIn::new(
            prev_tx_faucet,
            prev_tx_faucet_index,
            None,
            None,
            None,
        ));
        tx_ins.push(TxIn::new(prev_tx_ex4, prev_tx_ex4_index, None, None, None));
        let mut tx_outs: Vec<TxOut> = Vec::new();
        let h160 = utils::decode_base58(target_address)?;
        let script_pubkey = utils::p2pkh_script(h160);
        let target_satoshis = (target_amount * 100_000_000_f64) as u64;
        tx_outs.push(TxOut::new(target_satoshis, script_pubkey));
        let mut tx_obj = Tx::new(1, tx_ins, tx_outs, 0, true, false);
        // each may have different private keys to unlock the ScriptPubKey
        assert!(tx_obj.sign_input(0, priva.clone()).await?);
        assert!(tx_obj.sign_input(1, priva.clone()).await?);
        assert_eq!(want, hex::encode(tx_obj.serialize()?));
        Ok(())
    }

    #[tokio::test]
    async fn test_sig_hash() -> Result<()> {
        let mut fetcher = TxFetcher::new();
        let tx = fetcher
            .fetch(
                "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03",
                false,
                true,
            )
            .await?;
        let want = BigInt::parse_bytes(
            b"27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6",
            16,
        )
        .context("unable to parse bytes to bigint")?;
        assert_eq!(tx.sig_hash(0, None).await?, want);
        Ok(())
    }

    #[tokio::test]
    async fn test_p2sh_verify() -> Result<()> {
        let mut fetcher = TxFetcher::new();
        let mut tx = fetcher
            .fetch(
                "46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b",
                false,
                true,
            )
            .await?;
        assert!(tx.verify().await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_p2pkh() -> Result<()> {
        let mut fetcher = TxFetcher::new();
        let mut tx = fetcher
            .fetch(
                "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03",
                false,
                true,
            )
            .await?;
        assert!(tx.verify().await?);
        let mut tx2 = fetcher
            .fetch(
                "5418099cc755cb9dd3ebc6cf1a7888ad53a1a3beb5a025bce89eb1bf7f1650a2",
                true,
                true,
            )
            .await?;
        assert!(tx2.verify().await?);
        Ok(())
    }

    #[tokio::test]
    async fn test_verify_p2wpkh() {
        let mut fetcher = TxFetcher::new();
        let mut tx = fetcher
            .fetch(
                "d869f854e1f8788bcff294cc83b280942a8c728de71eb709a2c29d10bfe21b7c",
                true,
                true,
            )
            .await
            .unwrap();
        assert!(tx.verify().await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_p2sh_p2wpkh() {
        let mut fetcher = TxFetcher::new();
        let mut tx = fetcher
            .fetch(
                "c586389e5e4b3acb9d6c8be1c19ae8ab2795397633176f5a6442a261bbdefc3a",
                false,
                true,
            )
            .await
            .unwrap();
        assert!(tx.verify().await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_p2wsh() {
        let mut fetcher = TxFetcher::new();
        let mut tx = fetcher
            .fetch(
                "78457666f82c28aa37b74b506745a7c7684dc7842a52a457b09f09446721e11c",
                true,
                true,
            )
            .await
            .unwrap();
        assert!(tx.verify().await.unwrap());
    }

    #[tokio::test]
    async fn test_verify_p2sh_p2wsh() {
        let mut fetcher = TxFetcher::new();
        let mut tx = fetcher
            .fetch(
                "954f43dbb30ad8024981c07d1f5eb6c9fd461e2cf1760dd1283f052af746fc88",
                true,
                true,
            )
            .await
            .unwrap();
        assert!(tx.verify().await.unwrap());
    }

    #[tokio::test]
    async fn test_is_coinbase() -> Result<()> {
        let raw_tx = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000")?;
        let mut stream = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut stream, false).await?;
        assert!(tx.is_coinbase());
        Ok(())
    }

    #[tokio::test]
    async fn test_coinbase_height() -> Result<()> {
        let raw_tx = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000")?;
        let mut stream = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut stream, false).await?;
        assert_eq!(tx.coinbase_height(), Some(BigInt::from(465879)));

        let raw_tx = hex::decode("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600")?;
        let mut stream = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut stream, false).await?;
        assert_eq!(tx.coinbase_height(), None);
        Ok(())
    }

    #[tokio::test]
    async fn test_input_value() {
        let tx_hash =
            hex::decode("d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81")
                .unwrap();
        let testnet = false;
        let index = 0;
        let want = 42505594;
        let tx_in = TxIn::new(tx_hash, index, None, None, None);
        assert_eq!(tx_in.value(testnet).await.unwrap(), want);
    }

    #[tokio::test]
    async fn test_input_pubkey() {
        let tx_hash =
            hex::decode("d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81")
                .unwrap();
        let index = 0;
        let testnet = false;
        let tx_in = TxIn::new(tx_hash, index, None, None, None);
        let want = hex::decode("1976a914a802fc56c704ce87c42d7c92eb75e7896bdc41ae88ac").unwrap();
        assert_eq!(
            tx_in
                .script_pubkey(testnet)
                .await
                .unwrap()
                .serialize()
                .unwrap(),
            want
        )
    }
}
