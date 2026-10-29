//! Tiled logs pinned from the Chrome CT log list (see logs.json).

use crate::checkpoint::LogKey;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct Log {
    pub description: String,
    pub operator: String,
    pub origin: String,
    pub monitoring_url: String,
    pub key: String,
    pub log_id: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct LogList {
    pub source: String,
    pub log_list_version: String,
    pub log_list_timestamp: String,
    pub tiled_logs: Vec<Log>,
}

pub fn pinned() -> LogList {
    serde_json::from_str(include_str!("../logs.json")).expect("logs.json")
}

impl Log {
    pub fn key(&self) -> LogKey {
        LogKey {
            origin: self.origin.clone(),
            spki_der: STANDARD.decode(&self.key).expect("key base64"),
        }
    }
    pub fn log_id_bytes(&self) -> [u8; 32] {
        STANDARD
            .decode(&self.log_id)
            .expect("log_id base64")
            .try_into()
            .expect("32 bytes")
    }
}

impl LogList {
    pub fn by_description(&self, d: &str) -> Option<&Log> {
        self.tiled_logs.iter().find(|l| l.description == d)
    }
    pub fn by_log_id(&self, id: &[u8; 32]) -> Option<&Log> {
        self.tiled_logs.iter().find(|l| &l.log_id_bytes() == id)
    }
}
