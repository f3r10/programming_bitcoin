use std::io::{Read, Seek};

use crate::utils;

pub struct Block {
    pub version: u32,     //4 bytes
    pub prev_block: [u8; 32],  // 32 bytes
    pub merkle_root: [u8; 32], // 32 bytes
    pub timestamp: u32,   // 4 bytes
    pub bits: [u8; 4],        // 4 bytes
    pub nonce: [u8; 4],       // 4 bytes
}

impl Block {
    pub fn new(
        version: u32,
        prev_block: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: u32,
        bits: [u8; 4],
        nonce: [u8; 4]
    ) -> Self {
        Block { version, prev_block, merkle_root, timestamp, bits, nonce}
    }

    pub fn parse<R: Read + Seek>(stream: &mut R) -> Self {
        let mut version_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut version_buffer).unwrap();
        let version = u32::from_le_bytes(version_buffer);
        let mut prev_block = [0; 32];
        let mut handle = stream.take(32);
        handle.read(&mut prev_block).unwrap();
        prev_block.reverse();
        let mut merkle_root = [0; 32];
        let mut handle = stream.take(32);
        handle.read(&mut merkle_root).unwrap();
        merkle_root.reverse();
        let mut timestamp_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut timestamp_buffer).unwrap();
        let timestamp = u32::from_le_bytes(timestamp_buffer);
        let mut bits = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut bits).unwrap();
        let mut nonce = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut nonce).unwrap();
        Block { version, prev_block, merkle_root, timestamp, bits, nonce}
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(utils::u32_to_little_endian(self.version, 4));
        result.push(self.prev_block.clone().into_iter().rev().collect::<Vec<u8>>());
        result.push(self.merkle_root.clone().into_iter().rev().collect::<Vec<u8>>());
        result.push(utils::u32_to_little_endian(self.timestamp, 4));
        result.push(self.bits.to_vec());
        result.push(self.nonce.to_vec());
        result.concat()
    }

    pub fn hash(&self) -> Vec<u8> {
        let s = self.serialize();
        let mut sha = utils::hash256(&s);
        sha.reverse();
        sha
    }

    pub fn bip9(&self) -> bool {
        self.version >> 29 == 0b001
    }

    pub fn bip91(&self) -> bool {
        self.version >> 4 & 1 == 1
    }

    pub fn bip141(&self) -> bool {
        self.version >> 1 & 1 == 1
    }
}


#[cfg(test)]
mod block_tests {
    use std::io::Cursor;

    use super::Block;

    #[test]
    fn test_block_parse() {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut stream = Cursor::new(block_raw);
        let block = Block::parse(&mut stream);
        assert_eq!(block.version, 0x20000002);
        let want = hex::decode("000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e").unwrap();
        assert_eq!(want, block.prev_block);
        let want = hex::decode("be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b").unwrap();
        assert_eq!(want, block.merkle_root);
        assert_eq!(0x59a7771e, block.timestamp);
        assert_eq!(hex::decode("e93c0118").unwrap(), block.bits);
        assert_eq!(hex::decode("a4ffd71d").unwrap(), block.nonce);

    }

    #[test]
    fn test_block_serialize() {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert_eq!(block.serialize(), block_raw)
    }

    #[test]
    fn test_block_hash() {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert_eq!(block.hash(), hex::decode("0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523").unwrap())
    }

    #[test]
    fn test_block_bip9() {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert!(block.bip9());
        let block_raw = hex::decode("0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert_eq!(block.bip9(), false);
    }

    #[test]
    fn test_block_bip91() {
        let block_raw = hex::decode("1200002028856ec5bca29cf76980d368b0a163a0bb81fc192951270100000000000000003288f32a2831833c31a25401c52093eb545d28157e200a64b21b3ae8f21c507401877b5935470118144dbfd1").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert!(block.bip91());
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert_eq!(block.bip91(), false);
    }

    #[test]
    fn test_block_bip141() {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert!(block.bip141());
        let block_raw = hex::decode("0000002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618").unwrap();
        let mut stream = Cursor::new(&block_raw);
        let block = Block::parse(&mut stream);
        assert_eq!(block.bip141(), false);
    }
}
