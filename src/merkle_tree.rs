use anyhow::{bail, Context, Result};
use std::fmt::Display;
use tokio::io::{AsyncBufRead, AsyncReadExt};

use crate::utils;

pub struct MerkleTree {
    pub total: u32,
    max_depth: i32,
    pub nodes: Vec<Vec<Vec<u8>>>,
    pub current_depth: i32,
    pub current_index: i32,
}

impl MerkleTree {
    pub fn new(total: f32) -> Result<Self> {
        let max_depth = total.log2().ceil() as i32;
        let mut merkle_tree: Vec<Vec<Vec<u8>>> = vec![];
        for depth in 0..(max_depth + 1) {
            let num_items = (total / 2.0_f32.powi(max_depth - depth)).ceil() as usize;
            let level_hashes = vec![vec![0_u8]; num_items.try_into()?];
            merkle_tree.push(level_hashes);
        }
        Ok(Self {
            total: total as u32,
            max_depth,
            nodes: merkle_tree,
            current_depth: 0,
            current_index: 0,
        })
    }

    pub fn up(&mut self) -> () {
        self.current_depth -= 1;
        self.current_index /= 2;
    }

    pub fn left(&mut self) -> () {
        self.current_depth += 1;
        self.current_index *= 2;
    }

    pub fn right(&mut self) -> () {
        self.current_depth += 1;
        self.current_index = self.current_index * 2 + 1;
    }

    pub fn root(&self) -> Vec<u8> {
        self.nodes[0][0].clone()
    }
    pub fn set_current_node(&mut self, value: Vec<u8>) -> () {
        self.nodes[self.current_depth as usize][self.current_index as usize] = value;
    }

    pub fn get_current_node(&self) -> Vec<u8> {
        self.nodes[self.current_depth as usize][self.current_index as usize].clone()
    }

    pub fn get_left_node(&self) -> Vec<u8> {
        self.nodes[(self.current_depth + 1) as usize][(self.current_index * 2) as usize].clone()
    }

    pub fn get_right_node(&self) -> Vec<u8> {
        self.nodes[(self.current_depth + 1) as usize][(self.current_index * 2 + 1) as usize].clone()
    }

    pub fn is_leaf(&self) -> bool {
        self.current_depth == (self.max_depth as i32)
    }

    pub fn right_exists(&self) -> bool {
        self.nodes[(self.current_depth + 1) as usize].len() > (self.current_index * 2 + 1) as usize
    }

    pub fn populate_tree(&mut self, flag_bits: Vec<u8>, hashes: Vec<Vec<u8>>) -> Result<()> {
        let mut flag_bits = flag_bits;
        let mut hashes = hashes;
        flag_bits.reverse();
        hashes.reverse();
        while self.root().len() == 1 {
            if self.is_leaf() {
                flag_bits.pop();
                self.set_current_node(hashes.pop().context("unable to move last hash")?);
                self.up();
            } else {
                let left_hash = self.get_left_node();
                if left_hash.len() == 1 {
                    if flag_bits.pop().context("unable to remove last flat_bit")? == 0 {
                        self.set_current_node(hashes.pop().context("unable to move last hash")?);
                        self.up();
                    } else {
                        self.left();
                    }
                } else if self.right_exists() {
                    let right_hash = self.get_right_node();
                    if right_hash.len() == 1 {
                        self.right();
                    } else {
                        self.set_current_node(utils::merkle_parent(left_hash, right_hash));
                        self.up();
                    }
                } else {
                    self.set_current_node(utils::merkle_parent(left_hash.clone(), left_hash));
                    self.up();
                }
            }
        }
        if hashes.len() != 0 {
            bail!("hashes not all consumed {}", hashes.len());
        }
        for flag_bit in flag_bits {
            if flag_bit != 0 {
                bail!("flag bits not all consumed");
            }
        }
        Ok(())
    }
}

impl Display for MerkleTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut result: Vec<String> = vec![];
        for (depth, level) in self.nodes.iter().enumerate() {
            let mut items: Vec<String> = vec![];
            for (index, h) in level.iter().enumerate() {
                let short = if h.len() == 1 {
                    "None".to_string()
                } else {
                    let mut res = hex::encode(h);
                    res.truncate(8);
                    format!("{}...", res)
                };
                if (depth as i32) == self.current_depth && (index as i32) == self.current_index {
                    items.push(format!("*{}*", short));
                } else {
                    items.push(format!("{}", short));
                }
            }
            result.push(items.join(", "));
        }
        write!(f, "{}", result.join("\n"))
    }
}

pub struct MerkleBlock {
    pub version: u32,
    pub previous_block: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: u32,
    pub bits: [u8; 4],
    pub nonce: [u8; 4],
    pub num_total_tx: u32,
    pub hashes: Vec<Vec<u8>>,
    pub flag_bits: Vec<u8>,
}

impl MerkleBlock {
    pub fn new(
        version: u32,
        previous_block: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: u32,
        bits: [u8; 4],
        nonce: [u8; 4],
        num_total_tx: u32,
        hashes: Vec<Vec<u8>>,
        flag_bits: Vec<u8>,
    ) -> Self {
        Self {
            version,
            previous_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
            num_total_tx,
            hashes,
            flag_bits,
        }
    }

    pub async fn parse<R: AsyncBufRead + Unpin>(stream: &mut R) -> Result<Self> {
        let mut version_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut version_buffer).await?;
        let version = u32::from_le_bytes(version_buffer);
        let mut prev_block = [0; 32];
        let mut handle = stream.take(32);
        handle.read_exact(&mut prev_block).await?;
        prev_block.reverse();
        let mut merkle_root = [0; 32];
        let mut handle = stream.take(32);
        handle.read_exact(&mut merkle_root).await?;
        merkle_root.reverse();
        let mut timestamp_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut timestamp_buffer).await?;
        let timestamp = u32::from_le_bytes(timestamp_buffer);
        let mut bits = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut bits).await?;
        let mut nonce = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut nonce).await?;
        let mut total_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut total_buffer).await?;
        let total = u32::from_le_bytes(total_buffer);
        let num_hashes = utils::read_varint_async(stream).await?;
        let mut hashes: Vec<Vec<u8>> = vec![];
        for _ in 0..num_hashes {
            let mut hash_buffer = [0; 32];
            let mut handle = stream.take(32);
            handle.read_exact(&mut hash_buffer).await?;
            hash_buffer.reverse();
            hashes.push(hash_buffer.to_vec());
        }
        let flags_length = utils::read_varint_async(stream).await?;
        let mut flags_buffer = vec![0; flags_length as usize];
        let mut handle = stream.take(flags_length);
        handle.read_exact(&mut flags_buffer).await?;
        Ok(Self {
            version,
            previous_block: prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
            num_total_tx: total,
            hashes,
            flag_bits: flags_buffer,
        })
    }

    pub fn is_valid(&self) -> Result<bool> {
        let flag_bits = utils::bytes_to_bit_field(self.flag_bits.clone());
        let mut hashes = self.hashes.clone();
        for hash in hashes.iter_mut() {
            hash.reverse()
        }
        let mut merkle_tree = MerkleTree::new(self.num_total_tx as f32)?;
        merkle_tree.populate_tree(flag_bits, hashes)?;
        let mut root = merkle_tree.root();
        root.reverse();
        Ok(root == self.merkle_root)
    }
}

#[cfg(test)]
mod merkle_tree_tests {
    use std::io::Cursor;

    use crate::merkle_tree::MerkleBlock;

    use super::MerkleTree;
    use anyhow::{Ok, Result};
    use tokio::io::BufReader;

    #[test]
    fn test_merkle_tree_init() -> Result<()> {
        let tree = MerkleTree::new(9.0)?;
        assert_eq!(tree.nodes[0].len(), 1);
        assert_eq!(tree.nodes[1].len(), 2);
        assert_eq!(tree.nodes[2].len(), 3);
        assert_eq!(tree.nodes[3].len(), 5);
        assert_eq!(tree.nodes[4].len(), 9);
        Ok(())
    }

    #[test]
    fn test_merkle_tree_populate_1() -> Result<()> {
        let hex_hashes = vec![
            "9745f7173ef14ee4155722d1cbf13304339fd00d900b759c6f9d58579b5765fb",
            "5573c8ede34936c29cdfdfe743f7f5fdfbd4f54ba0705259e62f39917065cb9b",
            "82a02ecbb6623b4274dfcab82b336dc017a27136e08521091e443e62582e8f05",
            "507ccae5ed9b340363a0e6d765af148be9cb1c8766ccc922f83e4ae681658308",
            "a7a4aec28e7162e1e9ef33dfa30f0bc0526e6cf4b11a576f6c5de58593898330",
            "bb6267664bd833fd9fc82582853ab144fece26b7a8a5bf328f8a059445b59add",
            "ea6d7ac1ee77fbacee58fc717b990c4fcccf1b19af43103c090f601677fd8836",
            "457743861de496c429912558a106b810b0507975a49773228aa788df40730d41",
            "7688029288efc9e9a0011c960a6ed9e5466581abf3e3a6c26ee317461add619a",
            "b1ae7f15836cb2286cdd4e2c37bf9bb7da0a2846d06867a429f654b2e7f383c9",
            "9b74f89fa3f93e71ff2c241f32945d877281a6a50a6bf94adac002980aafe5ab",
            "b3a92b5b255019bdaf754875633c2de9fec2ab03e6b8ce669d07cb5b18804638",
            "b5c0b915312b9bdaedd2b86aa2d0f8feffc73a2d37668fd9010179261e25e263",
            "c9d52c5cb1e557b92c84c52e7c4bfbce859408bedffc8a5560fd6e35e10b8800",
            "c555bc5fc3bc096df0a0c9532f07640bfb76bfe4fc1ace214b8b228a1297a4c2",
            "f9dbfafc3af3400954975da24eb325e326960a25b87fffe23eef3e7ed2fb610e",
        ];
        let tx_hashes: Vec<Vec<u8>> = hex_hashes
            .iter()
            .map(|tx| hex::decode(tx).unwrap())
            .collect();
        let mut tree = MerkleTree::new(hex_hashes.len() as f32)?;
        tree.populate_tree([1_u8; 31].to_vec(), tx_hashes)?;
        let root = "597c4bafe3832b17cbbabe56f878f4fc2ad0f6a402cee7fa851a9cb205f87ed1";
        assert_eq!(hex::encode(tree.root()), root);
        Ok(())
    }

    #[test]
    fn test_merkle_tree_populate_2() -> Result<()> {
        let hex_hashes = vec![
            "42f6f52f17620653dcc909e58bb352e0bd4bd1381e2955d19c00959a22122b2e",
            "94c3af34b9667bf787e1c6a0a009201589755d01d02fe2877cc69b929d2418d4",
            "959428d7c48113cb9149d0566bde3d46e98cf028053c522b8fa8f735241aa953",
            "a9f27b99d5d108dede755710d4a1ffa2c74af70b4ca71726fa57d68454e609a2",
            "62af110031e29de1efcad103b3ad4bec7bdcf6cb9c9f4afdd586981795516577",
        ];
        let tx_hashes: Vec<Vec<u8>> = hex_hashes
            .iter()
            .map(|tx| hex::decode(tx).unwrap())
            .collect();
        let mut tree = MerkleTree::new(hex_hashes.len() as f32)?;
        tree.populate_tree([1_u8; 11].to_vec(), tx_hashes)?;
        let root = "a8e8bd023169b81bc56854137a135b97ef47a6a7237f4c6e037baed16285a5ab";
        assert_eq!(hex::encode(tree.root()), root);
        Ok(())
    }

    #[tokio::test]
    async fn test_merkle_block_parse() -> Result<()> {
        let merkle_block_hex = "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635";
        let merkle_block = hex::decode(merkle_block_hex)?;
        let cursor = Cursor::new(&merkle_block);
        let mut stream = BufReader::new(cursor);
        let mb = MerkleBlock::parse(&mut stream).await?;
        let version = 0x20000000;
        assert_eq!(mb.version, version);
        let mut merkle_root_hex =
            hex::decode("ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4")?;
        merkle_root_hex.reverse();
        assert_eq!(mb.merkle_root.to_vec(), merkle_root_hex);
        let mut prev_block_hex =
            hex::decode("df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000")?;
        prev_block_hex.reverse();
        assert_eq!(mb.previous_block.to_vec(), prev_block_hex);
        let timestamp: u32 = u32::from_le_bytes(hex::decode("dc7c835b")?.try_into().unwrap());
        assert_eq!(mb.timestamp, timestamp);
        let bits = hex::decode("67d8001a")?;
        assert_eq!(mb.bits.to_vec(), bits);
        let nonce = hex::decode("c157e670")?;
        assert_eq!(mb.nonce.to_vec(), nonce);
        let total: u32 = u32::from_le_bytes(hex::decode("bf0d0000")?.try_into().unwrap());
        assert_eq!(mb.num_total_tx, total);
        let hex_hashes = vec![
            "ba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a",
            "7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d",
            "34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2",
            "158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cba",
            "ee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763ce",
            "f8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097",
            "c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d",
            "6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543",
            "d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274c",
            "dfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb62261",
        ];
        let tx_hashes: Vec<Vec<u8>> = hex_hashes
            .iter()
            .map(|tx| hex::decode(tx).unwrap())
            .map(|mut tx| {
                tx.reverse();
                tx
            })
            .collect();
        assert_eq!(mb.hashes, tx_hashes);
        let flags = hex::decode("b55635")?;
        assert_eq!(mb.flag_bits, flags);

        Ok(())
    }

    #[tokio::test]
    async fn test_merkle_block_is_valid() -> Result<()> {
        let merkle_block_hex = "00000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670bf0d00000aba412a0d1480e370173072c9562becffe87aa661c1e4a6dbc305d38ec5dc088a7cf92e6458aca7b32edae818f9c2c98c37e06bf72ae0ce80649a38655ee1e27d34d9421d940b16732f24b94023e9d572a7f9ab8023434a4feb532d2adfc8c2c2158785d1bd04eb99df2e86c54bc13e139862897217400def5d72c280222c4cbaee7261831e1550dbb8fa82853e9fe506fc5fda3f7b919d8fe74b6282f92763cef8e625f977af7c8619c32a369b832bc2d051ecd9c73c51e76370ceabd4f25097c256597fa898d404ed53425de608ac6bfe426f6e2bb457f1c554866eb69dcb8d6bf6f880e9a59b3cd053e6c7060eeacaacf4dac6697dac20e4bd3f38a2ea2543d1ab7953e3430790a9f81e1c67f5b58c825acf46bd02848384eebe9af917274cdfbb1a28a5d58a23a17977def0de10d644258d9c54f886d47d293a411cb6226103b55635";
        let merkle_block = hex::decode(merkle_block_hex)?;
        let cursor = Cursor::new(&merkle_block);
        let mut stream = BufReader::new(cursor);
        let mb = MerkleBlock::parse(&mut stream).await?;
        assert!(mb.is_valid()?);
        Ok(())
    }
}
