use std::fmt::Display;

use tokio::{
    io::{AsyncBufRead, AsyncReadExt, AsyncWriteExt, BufReader, BufWriter, ReadHalf, WriteHalf},
    net::{TcpSocket, TcpStream},
};

use anyhow::{bail, Ok, Result};
use chrono::prelude::*;
use rand::Rng;

use crate::{block::Block, utils};

pub enum Messages {
    VerAckMessage(VerAckMessage),
    VersionMessage(VersionMessage),
    GetHeadersMessage(GetHeadersMessage),
}

pub struct HeadersMessage {
    pub command: Vec<u8>,
    pub blocks: Vec<Block>,
}

pub struct GetHeadersMessage {
    pub command: Vec<u8>,
    pub version: [u8; 4],
    pub num_hashes: u8,
    pub start_block: Vec<u8>,
    pub end_block: Vec<u8>,
}

pub struct VerAckMessage {
    pub command: Vec<u8>,
}

pub struct NetworkEnvelope {
    pub command: Vec<u8>,
    pub payload: Vec<u8>,
    pub magic: [u8; 4],
}

#[derive(Debug, Clone)]
pub struct VersionMessage {
    command: [u8; 7],
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

pub struct SimpleNode {
    pub testnet: bool,
    pub logging: bool,
    pub writer: BufWriter<WriteHalf<TcpStream>>,
    pub reader: BufReader<ReadHalf<TcpStream>>,
}

pub static NETWORK_MAGIC: [u8; 4] = *b"\xf9\xbe\xb4\xd9";
pub static TESNET_NETWORK_MAGIC: [u8; 4] = *b"\x0b\x11\x09\x07";

impl NetworkEnvelope {
    pub fn new(command: Vec<u8>, payload: Vec<u8>, testnet: bool) -> Self {
        let magic = if testnet {
            TESNET_NETWORK_MAGIC
        } else {
            NETWORK_MAGIC
        };
        NetworkEnvelope {
            command,
            payload,
            magic,
        }
    }

    pub async fn parse<R: AsyncBufRead + Unpin>(stream: &mut R, testnet: bool) -> Result<Self> {
        let expected_magic: [u8; 4];
        if testnet {
            expected_magic = TESNET_NETWORK_MAGIC
        } else {
            expected_magic = NETWORK_MAGIC
        }

        let mut magic_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut magic_buffer).await?;
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
        handle.read_exact(&mut command_buffer).await?;
        let command_buffer_stripped_zeros: Vec<u8> = utils::strip_zero_end(&command_buffer);

        let mut payload_len_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut payload_len_buffer).await?;
        let payload_len = u32::from_le_bytes(payload_len_buffer) as u64;

        let mut checksum_buffer = [0; 4];
        let mut handle = stream.take(4);
        handle.read_exact(&mut checksum_buffer).await?;

        let mut payload_buffer = vec![0_u8; payload_len as usize];
        let mut handle = stream.take(payload_len);
        handle.read_exact(&mut payload_buffer).await?;
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
        let command = *b"version";
        Ok(VersionMessage {
            command,
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
        let command = *b"version";
        Ok(VersionMessage {
            command,
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

impl SimpleNode {
    pub async fn new_and_send(
        host: &str,
        port: u32,
        testnet: bool,
        logging: bool,
    ) -> Result<SimpleNode> {
        let addrs = format!("{}:{}", host, port);
        let socket = TcpSocket::new_v4()?;
        let addr = addrs.parse()?;
        let stream = socket.connect(addr).await?;
        let (reader, writer) = tokio::io::split(stream);

        Ok(SimpleNode {
            testnet,
            logging,
            writer: BufWriter::new(writer),
            reader: BufReader::new(reader),
        })
    }

    pub async fn handshake(&mut self) -> Result<NetworkEnvelope> {
        let message = VersionMessage::new_default()?;
        let envelope =
            NetworkEnvelope::new(message.command.to_vec(), message.serialize()?, self.testnet);
        self.writer.write_all(&envelope.serialize()?).await?;
        self.writer.flush().await?;

        let r = self.read().await?;
        if self.logging {
            println!("handshake::receving: {}", r);
        }
        if r.command == message.command.to_vec() {
            self.send(crate::network::Messages::VerAckMessage(VerAckMessage::new()))
                .await?;
        }
        let r = self.read().await?;
        if self.logging {
            println!("handshake::receving: {}", r);
        }
        if r.command == VerAckMessage::new().command {
            Ok(r)
        } else {
            bail!("handshake error")
        }
    }

    pub async fn send(&mut self, message: Messages) -> Result<()> {
        match message {
            Messages::VerAckMessage(message) => {
                let envelope = NetworkEnvelope::new(
                    message.command.to_vec(),
                    message.serialize(),
                    self.testnet,
                );

                self.writer.write_all(&envelope.serialize()?).await?;
                self.writer.flush().await?;
                Ok(())
            }
            Messages::VersionMessage(message) => {
                let envelope = NetworkEnvelope::new(
                    message.command.to_vec(),
                    message.serialize()?,
                    self.testnet,
                );
                println!("serialized: {}", hex::encode(envelope.serialize()?));

                self.writer.write_all(&envelope.serialize()?).await?;
                self.writer.flush().await?;
                Ok(())
            }
            Messages::GetHeadersMessage(message) => {
                let envelope = NetworkEnvelope::new(
                    message.command.to_vec(),
                    message.serialize()?,
                    self.testnet,
                );

                self.writer.write_all(&envelope.serialize()?).await?;
                self.writer.flush().await?;
                Ok(())
            }
        }
    }

    pub async fn read(&mut self) -> Result<NetworkEnvelope> {
        let envelope = NetworkEnvelope::parse(&mut self.reader, self.testnet).await?;
        if self.logging {
            println!("receiving: {}", envelope);
        }
        Ok(envelope)
    }
}

impl VerAckMessage {
    pub fn new() -> Self {
        VerAckMessage {
            command: b"verack".to_vec(),
        }
    }
    pub fn serialize(&self) -> Vec<u8> {
        b"".to_vec()
    }
}

impl GetHeadersMessage {
    pub fn new(start_block: Vec<u8>) -> Self {
        let version = 70015_u32.to_le_bytes();
        let num_hashes = 1_u8;
        let end_block = [0_u8; 32].to_vec();
        Self {
            command: b"getheaders".to_vec(),
            version,
            num_hashes,
            start_block,
            end_block,
        }
    }

    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut result: Vec<Vec<u8>> = Vec::new();
        result.push(self.version.to_vec());
        result.push(utils::encode_varint(self.num_hashes as usize)?);
        let mut start_block = self.start_block.to_vec();
        start_block.reverse();
        result.push(start_block);
        let mut end_block = self.end_block.to_vec();
        end_block.reverse();
        result.push(end_block);
        Ok(result.concat())
    }
}

impl HeadersMessage {
    pub fn new(blocks: Vec<Block>) -> Self {
        Self {
            command: b"headers".to_vec(),
            blocks,
        }
    }

    pub async fn parse<R: AsyncBufRead + Unpin>(stream: &mut R) -> Result<Self> {
        let num_headers = read_varint_async(stream).await?;
        let mut blocks: Vec<Block> = vec![];
        for _ in 0..num_headers {
            let p = Block::parse(stream).await?;
            blocks.push(p);
            let num_txs = read_varint_async(stream).await?;
            if num_txs != 0 {
                bail!("number of txs not 0")
            }
        }
        Ok(Self {
            command: b"headers".to_vec(),
            blocks,
        })
    }
}

pub async fn read_varint_async<R: AsyncBufRead + Unpin>(stream: &mut R) -> Result<u64> {
    let mut buffer = [0; 1];
    stream.read_exact(&mut buffer).await?;
    if buffer[0] == 0xfd {
        let mut buffer = [0; 2];
        stream.read_exact(&mut buffer).await?;
        let num = u16::from_le_bytes(buffer) as u64;
        Ok(num)
    } else if buffer[0] == 0xfe {
        let mut buffer = [0; 4];
        stream.read_exact(&mut buffer).await?;
        let num = u32::from_le_bytes(buffer) as u64;
        Ok(num)
    } else if buffer[0] == 0xff {
        let mut buffer = [0; 8];
        stream.read_exact(&mut buffer).await?;
        let num = u64::from_le_bytes(buffer);
        Ok(num)
    } else {
        let num = u8::from_le_bytes(buffer) as u64;
        Ok(num)
    }
}

#[cfg(test)]
mod network_tests {
    use std::io::Cursor;

    use crate::{
        block::Block,
        network::{HeadersMessage, NetworkEnvelope},
        utils::calculate_new_bits_2,
    };
    use anyhow::{bail, Result};
    use num_integer::Integer;
    use tokio::io::BufReader;

    use super::{GetHeadersMessage, SimpleNode, VersionMessage};

    #[tokio::test]
    async fn test_network_parse() -> Result<()> {
        let msg = hex::decode("f9beb4d976657261636b000000000000000000005df6e0e2")?;
        let cursor = Cursor::new(msg);
        let mut stream = BufReader::new(cursor);
        let envelope = NetworkEnvelope::parse(&mut stream, false).await?;
        assert_eq!(envelope.command, b"verack");
        assert_eq!(envelope.payload, b"");
        let msg = hex::decode("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")?;
        let cursor = Cursor::new(&msg);
        let mut stream = BufReader::new(cursor);
        let envelope = NetworkEnvelope::parse(&mut stream, false).await?;
        assert_eq!(envelope.command, b"version");
        assert_eq!(envelope.payload, msg[24..]);
        Ok(())
    }

    #[tokio::test]
    async fn test_network_serialize() -> Result<()> {
        let msg = hex::decode("f9beb4d976657261636b000000000000000000005df6e0e2")?;
        let cursor = Cursor::new(&msg);
        let mut stream = BufReader::new(cursor);
        let envelope = NetworkEnvelope::parse(&mut stream, false).await?;
        assert_eq!(envelope.serialize()?, msg);
        let msg = hex::decode("f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001")?;
        let cursor = Cursor::new(&msg);
        let mut stream = BufReader::new(cursor);
        let envelope = NetworkEnvelope::parse(&mut stream, false).await?;
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

    #[tokio::test]
    #[ignore = "it is necessary to execute a full bitcoin node"]
    async fn test_handshake() -> Result<()> {
        let mut node = SimpleNode::new_and_send("127.0.0.1", 8333, false, true).await?;
        let ans = node.handshake().await;
        assert!(ans.is_ok());
        Ok(())
    }

    #[test]
    fn test_get_headers_message_serialize() -> Result<()> {
        let block_hex =
            hex::decode("0000000000000000001237f46acddf58578a37e213d2a6edc4884a2fcad05ba3")?;
        let gh = GetHeadersMessage::new(block_hex);
        assert_eq!(hex::encode(gh.serialize()?), "7f11010001a35bd0ca2f4a88c4eda6d213e2378a5758dfcd6af437120000000000000000000000000000000000000000000000000000000000000000000000000000000000");
        Ok(())
    }

    #[tokio::test]
    async fn test_headers_message_parse() -> Result<()> {
        let msg_hex = hex::decode("0200000020df3b053dc46f162a9b00c7f0d5124e2676d47bbe7c5d0793a500000000000000ef445fef2ed495c275892206ca533e7411907971013ab83e3b47bd0d692d14d4dc7c835b67d8001ac157e670000000002030eb2540c41025690160a1014c577061596e32e426b712c7ca00000000000000768b89f07044e6130ead292a3f51951adbd2202df447d98789339937fd006bd44880835b67d8001ade09204600")?;
        let cursor = Cursor::new(&msg_hex);
        let mut stream = BufReader::new(cursor);
        let headers = HeadersMessage::parse(&mut stream).await?;
        assert_eq!(headers.blocks.len(), 2);
        Ok(())
    }

    #[tokio::test]
    #[ignore = "it is necessary to execute a full bitcoin node"]
    async fn test_node_get_headers() -> Result<()> {
        let genesis_block = hex::decode(crate::block::GENESIS_BLOCK)?;
        let cursor = Cursor::new(&genesis_block);
        let mut stream = BufReader::new(cursor);
        let mut previous = Block::parse(&mut stream).await?;
        let mut first_epoch_timestamp = previous.timestamp;
        let mut expected_bits = hex::decode(crate::block::LOWEST_BITS)?;
        let mut count = 1_i32;
        let mut node = SimpleNode::new_and_send("127.0.0.1", 8333, false, true).await?;
        let ans = node.handshake().await;
        assert!(ans.is_ok());
        for _ in 0..19 {
            let getheaders = GetHeadersMessage::new(previous.hash()?);
            node.send(crate::network::Messages::GetHeadersMessage(getheaders))
                .await?;
            let mut r = node.read().await?;
            while r.command != b"headers" {
                r = node.read().await?;
            }
            if r.command == b"headers" {
                let cursor = Cursor::new(&r.payload);
                let mut stream = BufReader::new(cursor);
                let headers = HeadersMessage::parse(&mut stream).await?;
                for header in headers.blocks {
                    if !header.check_pow()? {
                        bail!("bad PoW at block {}", count)
                    }
                    if header.prev_block.to_vec() != previous.hash()? {
                        bail!("discontinuous block at {}", count)
                    }
                    if count.div_mod_floor(&2016).1 == 0 {
                        let time_diff = previous.timestamp - first_epoch_timestamp;
                        expected_bits =
                            calculate_new_bits_2(previous.bits, time_diff as i32)?.to_vec();
                        println!("{}", hex::encode(&expected_bits));
                        first_epoch_timestamp = header.timestamp;
                    }
                    if header.bits.to_vec() != expected_bits {
                        bail!("bad bits at block {}", count)
                    }
                    previous = header;
                    count += 1;
                }
            } else {
                assert!(false)
            }
        }
        Ok(())
    }
}
