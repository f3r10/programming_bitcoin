use std::{collections::HashMap, io::Cursor};

use serde::Deserialize;

use crate::tx::Tx;
use anyhow::{Result, bail};

pub struct TxFetcher {
    cache: HashMap<String, Tx>,
}

#[derive(Deserialize, Debug)]
struct TxRemote {
    pub hex: String,
    pub hash: String,
}

impl TxFetcher {
    pub fn new() -> Self {
        TxFetcher {
            cache: HashMap::new(),
        }
    }

    pub fn get_url(testnet: bool) -> String {
        if testnet {
            "https://api.blockcypher.com/v1/btc/test3".to_string()
        } else {
            "https://api.blockcypher.com/v1/btc/main".to_string()
        }
    }

    pub async fn fetch(&mut self, tx_id: &str, testnet: bool, fresh: bool) -> Result<Tx> {
        if fresh || !self.cache.contains_key(tx_id) {
            let url = format!(
                "{}/txs/{}?includeHex=true",
                TxFetcher::get_url(testnet),
                tx_id
            );
            let res = reqwest::get(url).await?; //blocking::get(url)?;
            let tx_remote: TxRemote = res.json().await?;
            let hex_decode = hex::decode(tx_remote.hex)?;
            let mut reader = Cursor::new(hex_decode);
            let tx = Tx::parse(&mut reader, testnet).await?;
            if tx_remote.hash != tx_id {
                bail!("not the same id")
            }
            self.cache.insert(tx_id.to_string(), tx);
        }
        match self.cache.get_mut(&tx_id.to_string()) {
            Some(tx) => {
                tx.testnet = testnet;
                Ok(tx.clone())
            }
            None => panic!("tx not present"),
        }
    }
}
