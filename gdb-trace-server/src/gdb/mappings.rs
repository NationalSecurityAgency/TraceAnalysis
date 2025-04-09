use anyhow::Result;
use serde::Deserialize;
use std::{path::PathBuf, str::FromStr};

// FIXME: This is specialized to use the pin output version
#[derive(Deserialize)]
struct TextMapping {
    name: String,
    low: String,
    high: String,
}

impl TryInto<Mapping> for TextMapping {
    type Error = anyhow::Error;

    fn try_into(self) -> Result<Mapping> {
        Ok(Mapping {
            path: PathBuf::from_str(&self.name)?,
            base: u64::from_str_radix(&self.low.trim_start_matches("0x"), 16)?,
        })
    }
}

#[derive(Debug, Default)]
pub struct Mapping {
    path: PathBuf,
    base: u64,
}

impl Mapping {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            ..Default::default()
        }
    }

    pub fn base(&self) -> u64 {
        self.base
    }

    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

/// TODO: Documentation
// Should this function try to load the mappnigs from the sysroot? We could implement
// a function that takes an address and a buffer and tries to read from that address
// (offset from the base) which the mapping would know about..
pub fn parse_mappings_from_sysroot(map_file: String) -> Result<Vec<Mapping>> {
    std::fs::read_to_string(map_file)?
        .lines()
        .map(|item| {
            serde_json::from_str::<TextMapping>(item)
                .map(TryInto::try_into)
                .map_err(Into::into)
        })
        .collect::<Result<Vec<Result<Mapping>>>>()?
        .into_iter()
        .collect()
}
