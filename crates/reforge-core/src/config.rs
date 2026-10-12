use crate::Fault;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub max_files: usize,
    pub max_extracted_bytes: u64,
    pub max_file_bytes: u64,
    pub max_binary_bytes: u64,
    pub max_depth: usize,
    pub max_strings: usize,
    pub timeout_seconds: u64,
    pub function_timeout_seconds: u64,
    pub min_free_bytes: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_extracted_bytes: 20 * 1024 * 1024 * 1024,
            max_file_bytes: 4 * 1024 * 1024 * 1024,
            max_binary_bytes: 256 * 1024 * 1024,
            max_depth: 8,
            max_strings: 10_000,
            timeout_seconds: 600,
            function_timeout_seconds: 30,
            min_free_bytes: 128 * 1024 * 1024,
        }
    }
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let value: Self = match path {
            Some(p) => toml::from_str(&std::fs::read_to_string(p).context("read configuration")?)
                .context("parse configuration (see examples/reforge.toml)")?,
            None => Self::default(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn validate(&self) -> Result<()> {
        if self.max_files == 0
            || self.max_files > 1_000_000
            || self.max_depth > 32
            || self.max_file_bytes == 0
            || self.max_file_bytes > self.max_extracted_bytes
            || self.max_binary_bytes == 0
            || self.max_binary_bytes > 1024 * 1024 * 1024
            || self.timeout_seconds == 0
            || self.timeout_seconds > 86_400
            || self.function_timeout_seconds == 0
            || self.function_timeout_seconds > 3600
            || self.max_strings > 100_000
        {
            return Err(Fault::Configuration(
                "invalid resource limits; see examples/reforge.toml".into(),
            )
            .into());
        }
        Ok(())
    }
}
