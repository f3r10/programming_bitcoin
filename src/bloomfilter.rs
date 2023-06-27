use std::ops::Rem;

use crate::{network::GenericMessage, utils};
use anyhow::Result;

pub struct BloomFilter {
    pub size: u64,
    pub bit_field: Vec<u8>,
    pub function_count: u32,
    pub tweak: u32,
}

const BIP37_CONSTANT: u64 = 0xfba4c795_u64;

impl BloomFilter {
    pub fn new(size: u64, function_count: u32, tweak: u32) -> Self {
        let len = (size * 8) as usize;
        let bit_field = vec![0; len];
        BloomFilter {
            size,
            bit_field,
            function_count,
            tweak,
        }
    }

    pub fn add(&mut self, item: &[u8]) -> () {
        for i in 0..self.function_count {
            let seed = (i as u64) * BIP37_CONSTANT + (self.tweak as u64);
            let h = utils::murmur3_64_seeded(item, seed);
            let bit = h.rem((self.size * 8) as u64);
            self.bit_field[bit as usize] = 1;
        }
    }

    pub fn filter_bytes(&self) -> Result<Vec<u8>> {
        utils::bit_field_to_bytes(self.bit_field.to_vec())
    }

    pub fn filterload(&self, flag: Option<u8>) -> Result<GenericMessage> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(utils::encode_varint(self.size as usize)?);
        result.push(self.filter_bytes()?);
        result.push(utils::u32_to_little_endian(self.function_count, 4)?);
        result.push(utils::u32_to_little_endian(self.tweak, 4)?);
        result.push(flag.unwrap_or(1).to_le_bytes().to_vec());
        Ok(GenericMessage::new(b"filterload".to_vec(), result.concat()))
    }
}

#[cfg(test)]
mod bloomfilter_tests {
    use super::BloomFilter;
    use anyhow::Result;

    #[test]
    fn test_add() -> Result<()> {
        let mut bf = BloomFilter::new(10, 5, 99);
        let item = "Hello World";
        bf.add(item.as_bytes());
        let expected = "0000000a080000000140";
        assert_eq!(hex::encode(bf.filter_bytes()?), expected);
        let item = "Goodbye!";
        bf.add(item.as_bytes());
        let expected = "4000600a080000010940";
        assert_eq!(hex::encode(bf.filter_bytes()?), expected);
        Ok(())
    }
    #[test]
    fn test_filterload() -> Result<()> {
        let mut bf = BloomFilter::new(10, 5, 99);
        let item = "Hello World";
        bf.add(item.as_bytes());
        let item = "Goodbye!";
        bf.add(item.as_bytes());
        let expected = "0a4000600a080000010940050000006300000001";
        assert_eq!(hex::encode(bf.filterload(None)?.serialize()), expected);
        Ok(())
    }
}
