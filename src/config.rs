use crate::config;
use serde::{Deserialize, Serialize};
use serde_json::from_reader;
use std::{fs::File, process::exit};

#[derive(Debug, Deserialize, Serialize, PartialOrd, PartialEq)]
pub struct Config {
    address: String,
    port: u16,
    thread_count: usize,
    #[serde(with = "serde_level_filter")]
    log_level: log::LevelFilter,
}

impl Config {
    pub fn address(&self) -> String {
        format!("{}:{}", self.address, self.port)
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    pub fn log_level(&self) -> log::LevelFilter {
        self.log_level
    }

    pub fn load_config(reader: File) -> config::Config {
        match from_reader::<File, config::Config>(reader) {
            Ok(config) => config,
            Err(e) => {
                log::error!("Failed to read config file: {}", e);
                exit(-0x69)
            }
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            address: "0.0.0.0".to_string(),
            port: 80,
            thread_count: 25,
            log_level: log::LevelFilter::Warn,
        }
    }
}

// this will allow de/serialization of LevelFilter
pub mod serde_level_filter {
    use serde::{Deserializer, Serializer};

    use super::*;

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub fn serialize<S>(lf: &log::LevelFilter, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        lf.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<log::LevelFilter, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let filter = string.parse().map_err(serde::de::Error::custom)?;
        Ok(filter)
    }
}
