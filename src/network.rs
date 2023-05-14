use std::{
    fmt::Display,
    io::{Read, Seek},
};

use anyhow::{bail, Result};

use crate::utils;

pub struct NetworkEnvelope {
    pub command: Vec<u8>,
    pub payload: Vec<u8>,
    pub magic: [u8; 4],
}

pub static NETWORK_MAGIC: [u8; 4] = *b"\xf9\xbe\xb4\xd9";
pub static TESNET_NETWORK_MAGIC: [u8; 4] = *b"\x0b\x11\x09\x07";

impl NetworkEnvelope {
    pub fn new(command: Vec<u8>, payload: Vec<u8>, testnet: bool) -> Self {
        let magic = if testnet {
            NETWORK_MAGIC
        } else {
            TESNET_NETWORK_MAGIC
        };
        NetworkEnvelope {
            command,
            payload,
            magic,
        }
    }

    pub fn parse<R: Read + Seek>(stream: &mut R, testnet: bool) -> Result<Self> {
        let expected_magic: [u8; 4];
        if testnet {
            expected_magic = TESNET_NETWORK_MAGIC
        } else {
            expected_magic = NETWORK_MAGIC
        }

        let mut magic_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut magic_buffer)?;
        if magic_buffer.is_empty() {
            bail!("Connection reset!")
        }
        if magic_buffer != expected_magic {
            bail!(
                "magic is not right {} vs {}",
                hex::encode(magic_buffer),
                hex::encode(expected_magic)
            )
        }

        let mut command_buffer = [0; 12];
        let mut handle = stream.take(12);
        handle.read(&mut command_buffer)?;
        let command_buffer_stripped_zeros: Vec<u8> = utils::strip_zero_end(&command_buffer);

        let mut payload_len_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut payload_len_buffer)?;
        let payload_len = u32::from_le_bytes(payload_len_buffer) as u64;
        println!("payload_len: {}", payload_len);

        let mut checksum_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut checksum_buffer)?;
        println!("checksum_buffer: {:x?}", checksum_buffer);

        let mut payload_buffer = vec![0_u8; payload_len as usize];
        let mut handle = stream.take(payload_len);
        handle.read_exact(&mut payload_buffer)?;
        println!("payload_buffer: {:x?}", payload_buffer);
        let calculated_checksum = &utils::hash256(&payload_buffer)[0..4];
        println!("calculated_checksum: {:x?}", calculated_checksum);
        if calculated_checksum != checksum_buffer {
            bail!("checksum does not match")
        }
        Ok(NetworkEnvelope {
            command: command_buffer_stripped_zeros,
            payload: payload_buffer,
            magic: magic_buffer,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(self.magic.to_vec());
        result.push(self.command.to_vec());
        result.push(vec![0; 12 - self.command.len()]);
        result.push(utils::usize_to_little_endian(self.payload.len(), 4)?);
        result.push(utils::hash256(&self.payload)[0..4].to_vec());
        result.push(self.payload.to_vec());
        Ok(result.concat())
    }
}

impl Display for NetworkEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}",
            String::from_utf8(self.command.to_vec()).expect("invalid utf-8 sequence"),
            hex::encode(&self.payload)
        )
    }
}

#[cfg(test)]
mod network_tests {
    use std::io::Cursor;

    use anyhow::Result;

    use super::NetworkEnvelope;

    #[test]
    fn test_network_parse() -> Result<()> {
        let msg = hex::decode("f9beb4d976657261636b000000000000000000005df6e0e2")?;
        let mut stream = Cursor::new(msg);
        let envelope = NetworkEnvelope::parse(&mut stream, false)?;
        assert_eq!(envelope.command, b"verack");
        assert_eq!(envelope.payload, b"");
        let msg = hex::decode("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")?;
        let mut stream = Cursor::new(&msg);
        let envelope = NetworkEnvelope::parse(&mut stream, false)?;
        assert_eq!(envelope.command, b"version");
        assert_eq!(envelope.payload, msg[24..]);
        Ok(())
    }
    #[test]
    fn test_network_serialize() -> Result<()> {
        let msg = hex::decode("f9beb4d976657261636b000000000000000000005df6e0e2")?;
        let mut stream = Cursor::new(&msg);
        let envelope = NetworkEnvelope::parse(&mut stream, false)?;
        assert_eq!(envelope.serialize()?, msg);
        let msg = hex::decode("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")?;
        let mut stream = Cursor::new(&msg);
        let envelope = NetworkEnvelope::parse(&mut stream, false)?;
        assert_eq!(envelope.serialize()?, msg);
        Ok(())
    }
}
