use std::{
    fmt::Display,
    io::{Read, Seek},
};

use anyhow::{bail, Result};
use chrono::prelude::*;
use rand::Rng;

use crate::utils;

pub struct NetworkEnvelope {
    pub command: Vec<u8>,
    pub payload: Vec<u8>,
    pub magic: [u8; 4],
}

pub struct VersionMessage {
    pub version: [u8; 4],
    pub timestamp: [u8; 8],
    pub services: [u8; 8],
    pub receiver_services: [u8; 8],
    pub receiver_ip: [u8; 16],
    pub receiver_port: [u8; 2],
    pub sender_services: [u8; 8],
    pub sender_ip: [u8; 16],
    pub sender_port: [u8; 2],
    pub nonce: [u8; 8],
    pub user_agent: Vec<u8>,
    pub latest_block: [u8; 4],
    pub relay: bool,
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

        let mut checksum_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read(&mut checksum_buffer)?;

        let mut payload_buffer = vec![0_u8; payload_len as usize];
        let mut handle = stream.take(payload_len);
        handle.read_exact(&mut payload_buffer)?;
        let calculated_checksum = &utils::hash256(&payload_buffer)[0..4];
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

impl VersionMessage {
    pub fn new_default() -> Result<Self> {
        let version = 70015_u32.to_le_bytes();
        let services = 0_u64.to_le_bytes();
        let timestamp = Utc::now().timestamp_millis().to_le_bytes();
        let receiver_services = 0_u64.to_le_bytes();
        let receiver_ip: [u8; 16] = [
            [0_u8; 10].to_vec(),
            [0xff, 0xff].to_vec(),
            [0_u8; 4].to_vec(),
        ]
        .concat()
        .try_into()
        .unwrap();
        let receiver_port = 8333_u16.to_be_bytes();
        let sender_services = 0_u64.to_le_bytes();
        let sender_ip: [u8; 16] = [
            [0_u8; 10].to_vec(),
            [0xff, 0xff].to_vec(),
            [0_u8; 4].to_vec(),
        ]
        .concat()
        .try_into()
        .unwrap();
        let sender_port = 8333_u16.to_be_bytes();
        let mut rng = rand::thread_rng();
        let nonce = rng.gen_range(0..u64::MAX).to_le_bytes();
        let user_agent = b"/programmingbitcoin:0.1/".to_vec();
        let latest_block = 0_u32.to_le_bytes();
        let relay = false;
        Ok(VersionMessage {
            version,
            timestamp,
            services,
            receiver_services,
            receiver_ip,
            receiver_port,
            sender_services,
            sender_ip,
            sender_port,
            nonce,
            user_agent,
            latest_block,
            relay,
        })
    }
    pub fn new(
        version: Option<[u8; 4]>,
        services: Option<[u8; 8]>,
        timestamp: Option<[u8; 8]>,
        receiver_services: Option<[u8; 8]>,
        receiver_ip: Option<[u8; 4]>,
        receiver_port: Option<[u8; 2]>,
        sender_services: Option<[u8; 8]>,
        sender_ip: Option<[u8; 4]>,
        sender_port: Option<[u8; 2]>,
        nonce: Option<[u8; 8]>,
        user_agent: Option<Vec<u8>>,
        latest_block: Option<[u8; 4]>,
        relay: Option<bool>,
    ) -> Result<Self> {
        let version = version.unwrap_or(70015_u32.to_le_bytes());
        let services = services.unwrap_or(0_u64.to_le_bytes());
        let timestamp = timestamp.unwrap_or(Utc::now().timestamp_millis().to_le_bytes());
        let receiver_services = receiver_services.unwrap_or(0_u64.to_le_bytes());
        let receiver_ip: [u8; 16] = [
            [0_u8; 10].to_vec(),
            [0xff, 0xff].to_vec(),
            receiver_ip.unwrap_or([0_u8; 4]).to_vec(),
        ]
        .concat()
        .try_into()
        .unwrap();
        let receiver_port = receiver_port.unwrap_or(8333_u16.to_be_bytes());
        let sender_services = sender_services.unwrap_or(0_u64.to_le_bytes());
        let sender_ip: [u8; 16] = [
            [0_u8; 10].to_vec(),
            [0xff, 0xff].to_vec(),
            sender_ip.unwrap_or([0_u8; 4]).to_vec(),
        ]
        .concat()
        .try_into()
        .unwrap();
        let sender_port = sender_port.unwrap_or(8333_u16.to_be_bytes());
        let mut rng = rand::thread_rng();
        let nonce = nonce.unwrap_or(rng.gen_range(0..u64::MAX).to_le_bytes());
        let user_agent = user_agent.unwrap_or(b"/programmingbitcoin:0.1/".to_vec());
        let latest_block = latest_block.unwrap_or(0_u32.to_le_bytes());
        let relay = relay.unwrap_or(false);
        Ok(VersionMessage {
            version,
            timestamp,
            services,
            receiver_services,
            receiver_ip,
            receiver_port,
            sender_services,
            sender_ip,
            sender_port,
            nonce,
            user_agent,
            latest_block,
            relay,
        })
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(self.version.to_vec());
        result.push(self.services.to_vec());
        result.push(self.timestamp.to_vec());
        result.push(self.receiver_services.to_vec());
        result.push(self.receiver_ip.to_vec());
        result.push(self.receiver_port.to_vec());
        result.push(self.sender_services.to_vec());
        result.push(self.sender_ip.to_vec());
        result.push(self.sender_port.to_vec());
        result.push(self.nonce.to_vec());
        result.push(utils::encode_varint(self.user_agent.len())?);
        result.push(self.user_agent.clone());
        result.push(self.latest_block.to_vec());
        if self.relay {
            result.push(1_u8.to_be_bytes().to_vec());
        } else {
            result.push(0_u8.to_be_bytes().to_vec());
        }
        Ok(result.concat())
    }
}

#[cfg(test)]
mod network_tests {
    use std::io::Cursor;

    use anyhow::Result;

    use super::{NetworkEnvelope, VersionMessage};

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

    #[test]
    fn test_version_message_serialize() -> Result<()> {
        let mut v = VersionMessage::new_default()?;
        v.timestamp = [0; 8];
        v.nonce = [0; 8];
        assert_eq!(hex::encode(v.serialize()?), "7f11010000000000000000000000000000000000000000000000000000000000000000000000ffff00000000208d000000000000000000000000000000000000ffff00000000208d0000000000000000182f70726f6772616d6d696e67626974636f696e3a302e312f0000000000");
        Ok(())
    }
}
