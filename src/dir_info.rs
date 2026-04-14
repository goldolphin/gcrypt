use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::error::Result;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct DirInfo {
    pub items: BTreeMap<String, FileInfo>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct FileInfo {
    pub mtime: i64,
    pub size: u64,
    pub checksum: String,
}

impl DirInfo {
    pub fn new() -> Self {
        DirInfo {
            items: BTreeMap::new(),
        }
    }

    pub fn from_str(contents: &str) -> Result<Self> {
        Ok(toml::from_str(contents)?)
    }

    pub fn to_string(&self) -> Result<String> {
        Ok(toml::to_string(self)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dir_info_serialization() {
        let dir_info = DirInfo {
            items: {
                let mut items = BTreeMap::new();
                items.insert(
                    "file1".to_string(),
                    FileInfo {
                        mtime: 1234567890,
                        size: 1024,
                        checksum: "checksum1".to_string(),
                    },
                );
                items.insert(
                    "dir1/file2".to_string(),
                    FileInfo {
                        mtime: 1234567890,
                        size: 2048,
                        checksum: "checksum2".to_string(),
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
