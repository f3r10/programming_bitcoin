use std::{
    fmt::Display,
    io::{Cursor, Read, Seek},
};

use byteorder::{BigEndian, ByteOrder};
use num_bigint::BigInt;

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
    pub amount: BigInt,
    pub script_pubkey: Script,
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_tx: Vec<u8>,
    pub prev_index: BigInt,
    pub script_sig: Option<Script>,
    pub sequence: Option<BigInt>,
}

#[derive(Debug, Clone)]
pub struct Tx {
    pub version: BigInt,
    pub tx_ins: Vec<TxIn>,
    pub tx_outs: Vec<TxOut>,
    pub locktime: BigInt,
    pub testnet: bool,
}

impl Tx {
    pub fn new(
        version: BigInt,
        tx_ins: Vec<TxIn>,
        tx_outs: Vec<TxOut>,
        locktime: BigInt,
        testnet: bool,
    ) -> Self {
        Tx {
            version,
            tx_ins,
            tx_outs,
            locktime,
            testnet,
        }
    }

    pub fn parse<R: Read + Seek>(stream: &mut R, testnet: bool) -> Self {
        let mut buffer = [0; 4];

        let mut handle = stream.take(4);
        handle.read(&mut buffer).unwrap();
        let version = utils::little_endian_to_int(&buffer);
        let pos = stream.stream_position().unwrap();

        // The next two bytes represents if the TX is segwit
        // Not all TX's have this mark so if not, it is necessary to restart the position.
        // TODO handle segwit correctly
        let mut buffer = [0; 2];
        let mut handle = stream.take(2);
        handle.read(&mut buffer).unwrap();
        if buffer == [0_u8, 1_u8] {
        } else {
            stream.seek(std::io::SeekFrom::Start(pos)).unwrap();
        }
        let num_inputs_buf = utils::read_varint(stream).to_signed_bytes_be();
        let num_inputs = BigEndian::read_uint(&num_inputs_buf, num_inputs_buf.len());
        let mut inputs: Vec<TxIn> = Vec::new();
        for _ in 0..num_inputs {
            inputs.push(TxIn::parse(stream))
        }
        let num_outputs_buf = utils::read_varint(stream).to_signed_bytes_be();
        let num_outputs = BigEndian::read_uint(&num_outputs_buf, num_outputs_buf.len());
        let mut outputs: Vec<TxOut> = Vec::new();
        for _ in 0..num_outputs {
            outputs.push(TxOut::parse(stream))
        }
        let mut locktime_buffer = [0; 4];
        stream.read_exact(&mut locktime_buffer).unwrap();
        let locktime = utils::little_endian_to_int(&locktime_buffer);
        Tx {
            version,
            tx_ins: inputs,
            tx_outs: outputs,
            locktime,
            testnet,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(utils::int_to_little_endian(&self.version, 4));
        result.push(utils::encode_varint(self.tx_ins.len()));
        for tx_in in &self.tx_ins {
            let intx = tx_in.serialize();
            result.push(intx)
        }
        result.push(utils::encode_varint(self.tx_outs.len()));
        for tx_out in &self.tx_outs {
            let outx = tx_out.serialize();
            result.push(outx)
        }
        result.push(utils::int_to_little_endian(&self.locktime, 4));
        result.concat()
    }

    pub fn fee(&self, testnet: bool) -> BigInt {
        let mut tx_ins_total = BigInt::from(0);
        for tx_in in &self.tx_ins {
            tx_ins_total += tx_in.value(testnet);
        }

        let mut tx_outs_total = BigInt::from(0);
        for tx_out in &self.tx_outs {
            tx_outs_total += tx_out.amount.clone();
        }
        tx_ins_total - tx_outs_total
    }

    pub fn sig_hash(&self, input_index: usize, redeem_script: Option<Script>) -> BigInt {
        let mut s = utils::int_to_little_endian(&self.version, 4);
        s.append(&mut utils::encode_varint(self.tx_ins.len()));
        for (i, tx_in) in self.tx_ins.iter().enumerate() {
            let script_sig: Option<Script>;
            if i == input_index {
                match redeem_script.as_ref() {
                    Some(redeem) => script_sig = Some(redeem.clone()),
                    None => script_sig = Some(tx_in.script_pubkey(self.testnet)),
                }
            } else {
                script_sig = None;
            }
            let mut tx = TxIn::new(
                tx_in.prev_tx.clone(),
                tx_in.prev_index.clone(),
                script_sig,
                tx_in.sequence.clone(),
            )
            .serialize();
            s.append(&mut tx);
        }

        s.append(&mut utils::encode_varint(self.tx_outs.len()));
        for tx_out in &self.tx_outs {
            s.append(&mut tx_out.clone().serialize())
        }
        s.append(&mut utils::int_to_little_endian(&self.locktime, 4));
        s.append(&mut utils::u32_to_little_endian(
            *OpCodeFunctions::op_sig_hash_all().as_ref(),
            4,
        ));
        let hash = utils::hash256(&s);
        return BigInt::from_bytes_be(num_bigint::Sign::Plus, &hash);
    }

    pub fn verify_input(&self, input_index: usize) -> bool {
        let tx_in = &self.tx_ins[input_index];
        let script_pubkey = tx_in.script_pubkey(self.testnet);
        let redeem_script: Option<Script>;
        if script_pubkey.is_p2sh_script_pubkey() {
            // OP_0 , SIG1, SIG2, ..., RedeemScript
            let cmd = match tx_in.script_sig.as_ref().unwrap().cmds.last().unwrap() {
                Command::Element(elm) => elm,
                Command::Operation(_) => panic!("invalid last Cmd for redeem script"),
            };
            let raw_redeem = [utils::encode_varint(cmd.len()), cmd.to_vec()].concat();
            let mut raw_redeem_cursor = Cursor::new(raw_redeem);
            redeem_script = Some(Script::parse(&mut raw_redeem_cursor));
        } else {
            redeem_script = None
        }
        let sig_hash = self.sig_hash(input_index, redeem_script);
        let z = Signature::signature_hash_from_int(sig_hash);
        match tx_in.script_sig.clone() {
            Some(script_sig) => {
                let combined = script_sig + script_pubkey;
                combined.evaluate(z)
            }
            None => false,
        }
    }

    pub fn verify(&self) -> bool {
        if self.fee(self.testnet) < BigInt::from(0) {
            return false;
        } else {
            for i in 0..self.tx_ins.len() {
                if !self.verify_input(i) {
                    return false;
                }
            }
        }
        return true;
    }

    fn id(&self) -> String {
        hex::encode(self.hash())
    }

    fn hash(&self) -> Vec<u8> {
        let mut a = utils::hash256(&self.serialize());
        a.reverse();
        a
    }

    pub fn sign_input(&mut self, input_index: usize, private_key: PrivateKey) -> bool {
        let z = self.sig_hash(input_index, None);
        let sign = private_key.sign(&Signature::signature_hash_from_int(z), None);
        let mut der_sighash = sign.der();
        der_sighash.append(&mut utils::u32_to_little_endian(
            *OpCodeFunctions::op_sig_hash_all().as_ref(),
            1,
        ));
        // der_sighash.push(1);
        let sec = private_key.point.sec(Some(true));
        let script_sig = Script::new(Some(vec![
            Command::Element(der_sighash),
            Command::Element(sec),
        ]));
        self.tx_ins[input_index].script_sig = Some(script_sig);
        self.verify_input(input_index)
    }

    pub fn is_coinbase(&self) -> bool {
        if self.tx_ins.len() > 1 {
            return false
        }
        let tx_in = &self.tx_ins[0];
        if tx_in.prev_tx  != [0_u8; 32] {
            return false
        }
        if tx_in.prev_index != BigInt::parse_bytes(b"ffffffff", 16).unwrap()  {
            return false
        }
        true
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
            self.id(),
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
        prev_index: BigInt,
        script_sig: Option<Script>,
        sequence: Option<BigInt>,
    ) -> Self {
        TxIn {
            prev_tx,
            prev_index,
            script_sig,
            sequence,
        }
    }

    pub fn parse<R: Read>(stream: &mut R) -> Self {
        let mut prev_tx_buffer = [0; 32];
        stream.read_exact(&mut prev_tx_buffer).unwrap();
        prev_tx_buffer.reverse(); // because is little endian
        let mut prev_tx_index_buffer = [0; 4];
        stream.read_exact(&mut prev_tx_index_buffer).unwrap();
        let prev_index = utils::little_endian_to_int(&prev_tx_index_buffer);
        let script_sig = Script::parse(stream);
        let mut sequence_buffer = [0; 4];
        stream.read_exact(&mut sequence_buffer).unwrap();
        let sequence = utils::little_endian_to_int(&sequence_buffer);
        TxIn {
            prev_tx: prev_tx_buffer.to_vec(),
            prev_index,
            script_sig: Some(script_sig),
            sequence: Some(sequence),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        let mut prev_tx = self.prev_tx.clone();
        prev_tx.reverse();
        result.push(prev_tx);
        result.push(utils::int_to_little_endian(&self.prev_index, 4));
        match &self.script_sig {
            Some(script_sig) => result.push(script_sig.serialize()),
            None => result.push([0].to_vec()),
        };
        match self.sequence.as_ref() {
            Some(s) => result.push(utils::int_to_little_endian(s, 4)),
            None => result.push(utils::u32_to_little_endian(0xffffffff, 4)),
        }
        result.concat()
    }

    pub fn fetch_tx(&self, testnet: bool) -> Tx {
        let mut tx_fetcher = TxFetcher::new();
        tx_fetcher.fetch(&hex::encode(self.prev_tx.clone()), testnet, false)
    }

    pub fn value(&self, testnet: bool) -> BigInt {
        let tx = self.fetch_tx(testnet);
        let index_buf = self.prev_index.to_signed_bytes_be();
        let index = BigEndian::read_int(&index_buf, index_buf.len()) as usize;
        tx.tx_outs[index].amount.clone()
    }

    /// Fetch the TX
    pub fn script_pubkey(&self, testnet: bool) -> Script {
        let tx = self.fetch_tx(testnet);
        let index_buf = self.prev_index.to_signed_bytes_be();
        let index = BigEndian::read_int(&index_buf, index_buf.len()) as usize;
        tx.tx_outs[index].script_pubkey.clone()
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
    pub fn new(amount: BigInt, script_pubkey: Script) -> Self {
        TxOut {
            amount,
            script_pubkey,
        }
    }

    pub fn parse<R: Read>(stream: &mut R) -> Self {
        let mut amount_buffer = [0; 8];
        stream.read_exact(&mut amount_buffer).unwrap();
        let amount = utils::little_endian_to_int(&amount_buffer);
        let script_pubkey = Script::parse(stream);
        TxOut {
            amount,
            script_pubkey,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(utils::int_to_little_endian(&self.amount, 8));
        result.push(self.script_pubkey.serialize());
        result.concat()
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

    #[test]
    fn test_parse_inputs() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        assert_eq!(tx.tx_ins.len(), 1);
        assert_eq!(tx.tx_ins[0].prev_index, BigInt::from(0));
        assert_eq!(
            hex::encode(tx.tx_ins[0].prev_tx.clone()),
            "d1c789a9c60383bf715f3f6ad9d14b91fe55f3deb369fe5d9280cb1a01793f81"
        );
        assert_eq!(hex::encode(tx.tx_ins[0].script_sig.clone().unwrap().serialize()), "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a");
        assert_eq!(
            tx.tx_ins[0].sequence.clone().unwrap(),
            BigInt::from(0xfffffffe_u32)
        );
    }

    #[test]
    fn test_parse_outputs() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        assert_eq!(tx.tx_outs.len(), 2);
        assert_eq!(tx.tx_outs[0].amount, BigInt::from(32454049));
        assert_eq!(
            hex::encode(tx.tx_outs[0].script_pubkey.serialize()),
            "1976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac"
        );
        assert_eq!(tx.tx_outs[1].amount, BigInt::from(10011545));
        assert_eq!(
            hex::encode(tx.tx_outs[1].script_pubkey.serialize()),
            "1976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac"
        );
    }

    #[test]
    fn test_parse_locktime() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        assert_eq!(tx.locktime, BigInt::from(410393));
    }

    #[test]
    fn test_tx_serialize() {
        let tx = "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode.clone());
        let tx = Tx::parse(&mut cursor_tx, false);
        assert_eq!(tx_encode, tx.serialize());
    }

    #[test]
    fn test_long_tx() {
        let tx = "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600";
        let tx_bytes = hex::decode(tx).unwrap();
        let mut reader_mem = Cursor::new(tx_bytes);
        let tx_parsed = Tx::parse(&mut reader_mem, false);
        //TODO add these tests when Script has a display impl
        // assert_eq!("304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a71601035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937", hex::encode(tx_parsed.tx_ins[1].script_sig));
        // assert_eq!("", hex::encode(tx_parsed.tx_outs[0].script_pubkey.serialize()));
        assert_eq!(BigInt::from(40000000), tx_parsed.tx_outs[1].amount);
    }

    #[test]
    fn test_fee_tx() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        assert_eq!(tx.fee(false), BigInt::from(40000));

        let tx = "010000000456919960ac691763688d3d3bcea9ad6ecaf875df5339e148a1fc61c6ed7a069e010000006a47304402204585bcdef85e6b1c6af5c2669d4830ff86e42dd205c0e089bc2a821657e951c002201024a10366077f87d6bce1f7100ad8cfa8a064b39d4e8fe4ea13a7b71aa8180f012102f0da57e85eec2934a82a585ea337ce2f4998b50ae699dd79f5880e253dafafb7feffffffeb8f51f4038dc17e6313cf831d4f02281c2a468bde0fafd37f1bf882729e7fd3000000006a47304402207899531a52d59a6de200179928ca900254a36b8dff8bb75f5f5d71b1cdc26125022008b422690b8461cb52c3cc30330b23d574351872b7c361e9aae3649071c1a7160121035d5c93d9ac96881f19ba1f686f15f009ded7c62efe85a872e6a19b43c15a2937feffffff567bf40595119d1bb8a3037c356efd56170b64cbcc160fb028fa10704b45d775000000006a47304402204c7c7818424c7f7911da6cddc59655a70af1cb5eaf17c69dadbfc74ffa0b662f02207599e08bc8023693ad4e9527dc42c34210f7a7d1d1ddfc8492b654a11e7620a0012102158b46fbdff65d0172b7989aec8850aa0dae49abfb84c81ae6e5b251a58ace5cfeffffffd63a5e6c16e620f86f375925b21cabaf736c779f88fd04dcad51d26690f7f345010000006a47304402200633ea0d3314bea0d95b3cd8dadb2ef79ea8331ffe1e61f762c0f6daea0fabde022029f23b3e9c30f080446150b23852028751635dcee2be669c2a1686a4b5edf304012103ffd6f4a67e94aba353a00882e563ff2722eb4cff0ad6006e86ee20dfe7520d55feffffff0251430f00000000001976a914ab0c0b2e98b1ab6dbf67d4750b0a56244948a87988ac005a6202000000001976a9143c82d7df364eb6c75be8c80df2b3eda8db57397088ac46430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        assert_eq!(tx.fee(false), BigInt::from(140500));
    }

    #[test]
    fn test_fee_positive_tx() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        assert!(tx.fee(false) > BigInt::from(0));
    }

    #[test]
    fn test_sig_hash_and_verify_input() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        let tx_sig_hash = tx.sig_hash(0, None);
        assert_eq!(
            "18037338614366229343027734445863508930887653120159589908930024158807354868134",
            tx_sig_hash.to_string()
        );

        let der = "3045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed";
        let sig_encode = hex::decode(der).unwrap();
        let mut cursor_sig = Cursor::new(sig_encode);
        let sig_parsed = Signature::parse(&mut cursor_sig);
        let sec = "0349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a";
        let sec_encode = hex::decode(sec).unwrap();
        let point = S256Point::parse(&sec_encode);
        let z = Signature::signature_hash_from_int(tx_sig_hash);
        assert!(point.verify(&z, sig_parsed))
    }

    #[test]
    fn test_tx_verify() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let tx = Tx::parse(&mut cursor_tx, false);
        assert!(tx.verify());
    }

    #[test]
    fn test_tx_signing() {
        let tx = "0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278afeffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let mut tx = Tx::parse(&mut cursor_tx, false);
        let z = tx.sig_hash(0, None);
        let private_key =
            PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(8675309)));
        let mut der_sighash = private_key
            .sign(&Signature::signature_hash_from_int(z), None)
            .der();
        der_sighash.append(&mut utils::u32_to_little_endian(
            *OpCodeFunctions::op_sig_hash_all().as_ref(),
            1,
        ));
        let sec = private_key.point.sec(Some(true));
        let script_sig = Script::new(Some(vec![
            Command::Element(der_sighash),
            Command::Element(sec),
        ]));
        tx.tx_ins[0].script_sig = Some(script_sig);
        assert_eq!("0100000001813f79011acb80925dfe69b3def355fe914bd1d96a3f5f71bf8303c6a989c7d1000000006a47304402207db2402a3311a3b845b038885e3dd889c08126a8570f26a844e3e4049c482a11022010178cdca4129eacbeab7c44648bf5ac1f9cac217cd609d216ec2ebc8d242c0a012103935581e52c354cd2f484fe8ed83af7a3097005b2f9c60bff71d35bd795f54b67feffffff02a135ef01000000001976a914bc3b654dca7e56b04dca18f2566cdaf02e8d9ada88ac99c39800000000001976a9141c4bc762dd5423e332166702cb75f40df79fea1288ac19430600", hex::encode(tx.serialize()));
    }

    #[test]
    fn test_tx_sign_input() {
        let tx = "010000000199a24308080ab26e6fb65c4eccfadf76749bb5bfa8cb08f291320b3c21e56f0d0d00000000ffffffff02408af701000000001976a914d52ad7ca9b3d096a38e752c2018e6fbc40cdf26f88ac80969800000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac00000000";
        let tx_encode = hex::decode(tx).unwrap();
        let mut cursor_tx = Cursor::new(tx_encode);
        let mut tx = Tx::parse(&mut cursor_tx, true);
        let private_key =
            PrivateKey::new(&PrivateKey::generate_simple_secret(BigInt::from(8675309)));
        assert!(tx.sign_input(0, private_key));
    }
    #[test]
    fn test_tx_with_two_inputs_and_one_output() {
        let want = "0100000002cca175bc8125f679bf21d76c3da4d08952f0ddc63dbe9d7f916306d7b0467517000000006b483045022100bd4a9297d5b000232f01093e8c4fec035b99ebef5de38e073ceded393c8488e3022079661ab7aa3f55ff37e2819029ed50eba163f24a44451d4eaa169f28a832b0ac012102a39eecbb9f8c6de1efec44c51e2e580dd790c2bd35e6fa1c9564ab7d794e3143ffffffff3bfe2faa0d5d64608ebe8dea810962bb35e1a29f8e35940f1e2787695355d13f010000006b483045022100c07f377818e8daa37bbfef1530694e85739df3a87819fcc0482891bacc6d6ef402206b7df12af9ff2fadad6815f157ede3a14d8e972a75f1586849ce18693766cf4e012102a39eecbb9f8c6de1efec44c51e2e580dd790c2bd35e6fa1c9564ab7d794e3143ffffffff0187611a00000000001976a914d5985c6d780579b61f9bff365a689b4fa2ec528988ac00000000";

        let prev_tx_faucet =
            hex::decode("177546b0d70663917f9dbe3dc6ddf05289d0a43d6cd721bf79f62581bc75a1cc")
                .unwrap();
        let prev_tx_faucet_index = BigInt::from(0);
        let prev_tx_ex4 =
            hex::decode("3fd155536987271e0f94358e9fa2e135bb620981ea8dbe8e60645d0daa2ffe3b")
                .unwrap();
        let prev_tx_ex4_index = BigInt::from(1);
        let target_address = "mzzLk9MmXzmjCBLgjoeNDxrbdrt511t5Gm";
        let target_amount = 0.01728903;
        let secret = "f3r10@programmingblockchain.com my secret";
        let priva = PrivateKey::new(&PrivateKey::generate_secret(secret));
        let mut tx_ins: Vec<TxIn> = Vec::new();
        tx_ins.push(TxIn::new(prev_tx_faucet, prev_tx_faucet_index, None, None));
        tx_ins.push(TxIn::new(prev_tx_ex4, prev_tx_ex4_index, None, None));
        let mut tx_outs: Vec<TxOut> = Vec::new();
        let h160 = utils::decode_base58(target_address);
        let script_pubkey = utils::p2pkh_script(h160);
        let target_satoshis = BigInt::from((target_amount * 100_000_000_f64) as u64);
        tx_outs.push(TxOut::new(target_satoshis, script_pubkey));
        let mut tx_obj = Tx::new(BigInt::from(1), tx_ins, tx_outs, BigInt::from(0), true);
        // each may have different private keys to unlock the ScriptPubKey
        assert!(tx_obj.sign_input(0, priva.clone()));
        assert!(tx_obj.sign_input(1, priva.clone()));
        assert_eq!(want, hex::encode(tx_obj.serialize()));
    }

    #[test]
    fn test_sig_hash() {
        let mut fetcher = TxFetcher::new();
        let tx = fetcher.fetch(
            "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03",
            false,
            true,
        );
        let want = BigInt::parse_bytes(
            b"27e0c5994dec7824e56dec6b2fcb342eb7cdb0d0957c2fce9882f715e85d81a6",
            16,
        )
        .unwrap();
        assert_eq!(tx.sig_hash(0, None), want)
    }

    #[test]
    fn test_verify_p2sh() {
        let mut fetcher = TxFetcher::new();
        let tx = fetcher.fetch(
            "46df1a9484d0a81d03ce0ee543ab6e1a23ed06175c104a178268fad381216c2b",
            false,
            true,
        );
        assert!(tx.verify());
    }

    #[test]
    fn test_verify_p2pkh() {
        let mut fetcher = TxFetcher::new();
        let tx = fetcher.fetch(
            "452c629d67e41baec3ac6f04fe744b4b9617f8f859c63b3002f8684e7a4fee03",
            false,
            true,
        );
        assert!(tx.verify());
        let tx2 = fetcher.fetch(
            "5418099cc755cb9dd3ebc6cf1a7888ad53a1a3beb5a025bce89eb1bf7f1650a2",
            true,
            true,
        );
        assert!(tx2.verify());
    }

    #[test]
    fn test_is_coinbase() {
        let raw_tx = hex::decode("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff5e03d71b07254d696e656420627920416e74506f6f6c20626a31312f4542312f4144362f43205914293101fabe6d6d678e2c8c34afc36896e7d9402824ed38e856676ee94bfdb0c6c4bcd8b2e5666a0400000000000000c7270000a5e00e00ffffffff01faf20b58000000001976a914338c84849423992471bffb1a54a8d9b1d69dc28a88ac00000000").unwrap();
        let mut stream = Cursor::new(raw_tx);
        let tx = Tx::parse(&mut stream, false);
        assert!(tx.is_coinbase())
    }
}
