use std::{fmt::Display, io::Read};

use num_bigint::BigInt;

use crate::{script::Script, tx_fetcher::TxFetcher, utils};

#[derive(Debug, Clone)]
pub struct TxOut {
    pub amount: BigInt,
    pub script_pubkey: Script,
}

#[derive(Debug, Clone)]
pub struct TxIn {
    pub prev_tx: Vec<u8>,
    pub prev_index: BigInt,
    pub script_sig: Script,
    pub sequence: BigInt,
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

    pub fn parse<R: Read>(stream: &mut R, testnet: bool) -> Self {
        let mut buffer = [0; 4];

        let mut handle = stream.take(4);
        handle.read(&mut buffer).unwrap(); // .read_u32::<LittleEndian>().unwrap(); //.read(&mut buffer).unwrap();
        let version = utils::little_endian_to_int(&buffer);
        let num_inputs = utils::read_varint(stream).to_u32_digits().1.pop().unwrap();
        let mut inputs: Vec<TxIn> = Vec::new();
        for _ in 0..num_inputs {
            inputs.push(TxIn::parse(stream))
        }
        let num_outputs = utils::read_varint(stream).to_u32_digits().1.pop().unwrap();
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
        result.push(utils::int_to_little_endian(self.version.clone(), 4));
        result.push(utils::encode_varint(self.tx_ins.len()));
        for tx_in in &self.tx_ins {
            result.push(tx_in.serialize())
        }
        result.push(utils::encode_varint(self.tx_outs.len()));
        for tx_out in &self.tx_outs {
            result.push(tx_out.serialize())
        }
        result.push(utils::int_to_little_endian(self.locktime.clone(), 4));
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
}

impl TxIn {
    pub fn new(prev_tx: Vec<u8>, prev_index: BigInt, script_sig: Script, sequence: BigInt) -> Self {
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
            script_sig,
            sequence,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        let mut prev_tx = self.prev_tx.clone();
        prev_tx.reverse();
        result.push(prev_tx);
        result.push(utils::int_to_little_endian(self.prev_index.clone(), 4));
        result.push(self.script_sig.serialize());
        result.push(utils::int_to_little_endian(self.sequence.clone(), 4));
        result.concat()
    }

    pub fn fetch_tx(&self, testnet: bool) -> Tx {
        let mut tx_fetcher = TxFetcher::new();
        tx_fetcher
            .fetch(&hex::encode(self.prev_tx.clone()), testnet, false)
            .clone()
    }

    pub fn value(&self, testnet: bool) -> BigInt {
        let tx = self.fetch_tx(testnet);
        let index = self.prev_index.to_u32_digits().1.pop().unwrap() as usize;
        tx.tx_outs[index].amount.clone()
    }

    pub fn script_pubkey(&self, testnet: bool) -> Script {
        let tx = self.fetch_tx(testnet);
        let index = self.prev_index.to_u32_digits().1.pop().unwrap() as usize;
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
        result.push(utils::int_to_little_endian(self.amount.clone(), 8));
        result.push(self.script_pubkey.serialize());
        result.concat()
    }
}

impl Display for TxOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            self.amount,
            hex::encode(self.script_pubkey.serialize())
        )
    }
}

#[cfg(test)]
mod tx_tests {
    use std::io::Cursor;

    use num_bigint::BigInt;

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
        assert_eq!(hex::encode(tx.tx_ins[0].script_sig.serialize()), "6b483045022100ed81ff192e75a3fd2304004dcadb746fa5e24c5031ccfcf21320b0277457c98f02207a986d955c6e0cb35d446a89d3f56100f4d7f67801c31967743a9c8e10615bed01210349fc4e631e3624a545de3f89f5d8684c7b8138bd94bdd531d2e213bf016b278a");
        assert_eq!(tx.tx_ins[0].sequence, BigInt::from(0xfffffffe_u32));
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
}
