use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize, PartialOrd, PartialEq)]
pub struct Config {
    address: String,
    thread_count: usize,
    #[serde(with = "serde_level_filter")]
    log_level: log::LevelFilter,
}

impl Config {
    pub fn address(&self) -> &str {
        &self.address
    }

    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    pub fn log_level(&self) -> log::LevelFilter {
        self.log_level
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
