use serde::{Deserialize, Serialize};
use rand::Rng;
use std::collections::BTreeMap;

use crate::error::{Error, Result};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DirInfo {
    pub keys: Keys,
    pub items: BTreeMap<String, Item>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Keys {
    pub obfuscation_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum Item {
    #[serde(rename = "file")]
    File (FileInfo),
    #[serde(rename = "dir")]
    Dir { obfuscated_name: String },
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct FileInfo {
    pub mtime: i64,
    pub size: u64,
    pub checksum: String,
    pub obfuscated_name: String,
}

impl DirInfo {
    pub fn new() -> Self {
        let mut obfuscation_key = [0u8; 32];
        rand::thread_rng().fill(&mut obfuscation_key);
        DirInfo {
            keys: Keys {
                obfuscation_key: hex::encode(obfuscation_key),
            },
            items: BTreeMap::new(),
        }
    }

    pub fn from_str(contents: &str) -> Result<Self> {
        let dir_info: DirInfo = toml::from_str(contents)?;
        dir_info.verify()?;
        Ok(dir_info)
    }

    pub fn to_string(&self) -> Result<String> {
        self.verify()?;
        Ok(toml::to_string(self)?)
    }

    pub fn verify(&self) -> Result<()> {
        self.parse_obfuscation_key()?;
        Ok(())
    }

    pub fn parse_obfuscation_key(&self) -> Result<[u8; 32]> {
        let key_bytes = hex::decode(&self.keys.obfuscation_key)?;
        Ok(key_bytes.try_into().map_err(|_| Error::Generic("Invalid obfuscation key length"))?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dir_info_serialization() {
        let dir_info = DirInfo {
            keys: Keys {
                obfuscation_key: "test_obfuscation_key".to_string(),
            },
            items: {
                let mut items = BTreeMap::new();
                items.insert(
                    "file1".to_string(),
                    Item::File (
                        FileInfo {
                            mtime: 1234567890,
                            size: 1024,
                            checksum: "checksum1".to_string(),
                            obfuscated_name: "obfuscated_name1".to_string(),
                        }
                    ),
                );
                items.insert(
                    "dir1".to_string(),
                    Item::Dir {
                        obfuscated_name: "obfuscated_name3".to_string(),
                    },
                );
                items
            },
        };

        let toml_string = toml::to_string_pretty(&dir_info).unwrap();
        let deserialized: DirInfo = toml::from_str(&toml_string).unwrap();

        assert_eq!(dir_info, deserialized);
    }
}
