use crate::utils;
use anyhow::Result;
use num_bigint::BigUint;
use tokio::io::{AsyncBufRead, AsyncReadExt};

pub const GENESIS_BLOCK: &str = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

pub const LOWEST_BITS: &str = "ffff001d";

pub struct Block {
    pub version: u32,          //4 bytes
    pub prev_block: [u8; 32],  // 32 bytes
    pub merkle_root: [u8; 32], // 32 bytes
    pub timestamp: u32,        // 4 bytes
    pub bits: [u8; 4],         // 4 bytes
    pub nonce: [u8; 4],        // 4 bytes
}

impl Block {
    pub fn new(
        version: u32,
        prev_block: [u8; 32],
        merkle_root: [u8; 32],
        timestamp: u32,
        bits: [u8; 4],
        nonce: [u8; 4],
    ) -> Self {
        Block {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
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
        Ok(Block {
            version,
            prev_block,
            merkle_root,
            timestamp,
            bits,
            nonce,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(utils::u32_to_little_endian(self.version, 4)?);
        result.push(
            self.prev_block
                .clone()
                .into_iter()
                .rev()
                .collect::<Vec<u8>>(),
        );
        result.push(
            self.merkle_root
                .clone()
                .into_iter()
                .rev()
                .collect::<Vec<u8>>(),
        );
        result.push(utils::u32_to_little_endian(self.timestamp, 4)?);
        result.push(self.bits.to_vec());
        result.push(self.nonce.to_vec());
        Ok(result.concat())
    }

    pub fn hash(&self) -> Result<Vec<u8>> {
        let s = self.serialize()?;
        let mut sha = utils::hash256(&s);
        sha.reverse();
        Ok(sha)
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

    pub fn difficulty(&self) -> Result<BigUint> {
        let target = utils::bits_to_target(self.bits)?;
        let difficulty = 0xffff_u32 * BigUint::from(256_u32).pow(0x1d - 3) / target;
        Ok(difficulty)
    }

    pub fn target(&self) -> Result<BigUint> {
        utils::bits_to_target(self.bits)
    }

    pub fn check_pow(&self) -> Result<bool> {
        let hash = utils::hash256(&self.serialize()?);
        let proof = utils::little_endian_unit_to_int(hash.as_slice());
        Ok(proof < self.target()?)
    }
}

#[cfg(test)]
mod block_tests {
    use std::io::Cursor;

    use crate::utils;

    use super::Block;
    use anyhow::{Context, Result};
    use num_bigint::BigUint;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn test_block_parse() -> Result<()> {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(block.version, 0x20000002);
        let want = hex::decode("000000000000000000fd0c220a0a8c3bc5a7b487e8c8de0dfa2373b12894c38e")?;
        assert_eq!(want, block.prev_block);
        let want = hex::decode("be258bfd38db61f957315c3f9e9c5e15216857398d50402d5089a8e0fc50075b")?;
        assert_eq!(want, block.merkle_root);
        assert_eq!(0x59a7771e, block.timestamp);
        assert_eq!(hex::decode("e93c0118")?, block.bits);
        assert_eq!(hex::decode("a4ffd71d")?, block.nonce);
        Ok(())
    }

    #[tokio::test]
    async fn test_block_serialize() -> Result<()> {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(block.serialize()?, block_raw);
        Ok(())
    }

    #[tokio::test]
    async fn test_block_hash() -> Result<()> {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(
            block.hash()?,
            hex::decode("0000000000000000007e9e4c586439b0cdbe13b1370bdd9435d76a644d047523")?
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_block_bip9() -> Result<()> {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert!(block.bip9());
        let block_raw = hex::decode("0400000039fa821848781f027a2e6dfabbf6bda920d9ae61b63400030000000000000000ecae536a304042e3154be0e3e9a8220e5568c3433a9ab49ac4cbb74f8df8e8b0cc2acf569fb9061806652c27")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(block.bip9(), false);
        Ok(())
    }

    #[tokio::test]
    async fn test_block_bip91() -> Result<()> {
        let block_raw = hex::decode("1200002028856ec5bca29cf76980d368b0a163a0bb81fc192951270100000000000000003288f32a2831833c31a25401c52093eb545d28157e200a64b21b3ae8f21c507401877b5935470118144dbfd1")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert!(block.bip91());
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(block.bip91(), false);
        Ok(())
    }

    #[tokio::test]
    async fn test_block_bip141() -> Result<()> {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert!(block.bip141());
        let block_raw = hex::decode("0000002066f09203c1cf5ef1531f24ed21b1915ae9abeb691f0d2e0100000000000000003de0976428ce56125351bae62c5b8b8c79d8297c702ea05d60feabb4ed188b59c36fa759e93c0118b74b2618")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(block.bip141(), false);
        Ok(())
    }

    #[tokio::test]
    async fn test_target() -> Result<()> {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        let target_raw =
            BigUint::parse_bytes(b"13ce9000000000000000000000000000000000000000000", 16)
                .context("unable to parse raw target")?;
        assert_eq!(block.target()?, target_raw);
        assert_eq!(block.difficulty()?, BigUint::from(888171856257_u64));
        Ok(())
    }

    #[tokio::test]
    async fn test_difficulty() -> Result<()> {
        let block_raw = hex::decode("020000208ec39428b17323fa0ddec8e887b4a7c53b8c0a0a220cfd0000000000000000005b0750fce0a889502d40508d39576821155e9c9e3f5c3157f961db38fd8b25be1e77a759e93c0118a4ffd71d")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(block.difficulty()?, BigUint::from(888171856257_u64));
        Ok(())
    }

    #[tokio::test]
    async fn test_pow() -> Result<()> {
        let block_raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec1")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert!(block.check_pow()?);

        let block_raw = hex::decode("04000000fbedbbf0cfdaf278c094f187f2eb987c86a199da22bbb20400000000000000007b7697b29129648fa08b4bcd13c9d5e60abb973a1efac9c8d573c71c807c56c3d6213557faa80518c3737ec0")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let block = Block::parse(&mut stream).await?;
        assert_eq!(block.check_pow()?, false);
        Ok(())
    }

    #[tokio::test]
    async fn test_calculate_new_bits() -> Result<()> {
        let block_raw = hex::decode("000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let last_block = Block::parse(&mut stream).await?;

        let block_raw = hex::decode("02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474")?;
        let cursor = Cursor::new(&block_raw);
        let mut stream = BufReader::new(cursor);
        let first_block = Block::parse(&mut stream).await?;
        let new_bits = utils::calculate_new_bits(&last_block, &first_block)?;
        assert_eq!(hex::encode(new_bits), "80df6217");
        Ok(())
    }
}
