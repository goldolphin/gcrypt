use serde::{Deserialize, Serialize};
use rand::Rng;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    pub keys: Keys,
    pub items: HashMap<String, Item>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Keys {
    pub obfuscation_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "type")]
pub enum Item {
    #[serde(rename = "file")]
    File {
        checksum: String,
        obfuscated_name: String,
    },
    #[serde(rename = "dir")]
    Dir { obfuscated_name: String },
}

impl Config {
    pub fn new() -> Self {
        let mut obfuscation_key = [0u8; 32];
        rand::thread_rng().fill(&mut obfuscation_key);
        Config {
            keys: Keys {
                obfuscation_key: hex::encode(obfuscation_key),
            },
            items: HashMap::new(),
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.verify()?;
        Ok(config)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let toml_string = toml::to_string_pretty(self)?;
        fs::write(path, toml_string)?;
        Ok(())
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
    use tempfile::tempdir;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            keys: Keys {
                obfuscation_key: "test_obfuscation_key".to_string(),
            },
            items: {
                let mut items = HashMap::new();
                items.insert(
                    "file1".to_string(),
                    Item::File {
                        checksum: "checksum1".to_string(),
                        obfuscated_name: "obfuscated_name1".to_string(),
                    },
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

        let toml_string = toml::to_string_pretty(&config).unwrap();
        let deserialized: Config = toml::from_str(&toml_string).unwrap();

        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_config_from_file() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("test_config.toml");

        let config = Config {
            items: {
                let mut items = HashMap::new();
                items.insert(
                    "file1".to_string(),
                    Item::File {
                        checksum: "checksum1".to_string(),
                        obfuscated_name: "obfuscated_name1".to_string(),
                    },
                );
                items.insert(
                    "dir1".to_string(),
                    Item::Dir {
                        obfuscated_name: "obfuscated_name3".to_string(),
                    },
                );
                items
            },
            ..Config::new()
        };

        config.to_file(&config_path).unwrap();
        let loaded_config = Config::from_file(&config_path).unwrap();

        assert_eq!(config, loaded_config);
    }

    #[test]
    fn test_item_types() {
        let file_item = Item::File {
            checksum: "test_checksum".to_string(),
            obfuscated_name: "test_obfuscated_name".to_string(),
        };

        let dir_item = Item::Dir {
            obfuscated_name: "test_obfuscated_name".to_string(),
        };

        match file_item {
            Item::File {
                checksum,
                obfuscated_name,
            } => {
                assert_eq!(checksum, "test_checksum");
                assert_eq!(obfuscated_name, "test_obfuscated_name");
            }
            _ => panic!("Expected File item"),
        }

        match dir_item {
            Item::Dir { obfuscated_name } => {
                assert_eq!(obfuscated_name, "test_obfuscated_name");
            }
            _ => panic!("Expected Dir item"),
        }
    }
}
