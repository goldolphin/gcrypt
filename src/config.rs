use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use std::path::Path;

use crate::error::Result;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Config {
    pub identity_path: PathBuf,
    pub recipients: Vec<String>,
}

impl Config {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn to_file(&self, path: impl AsRef<Path>) -> Result<()> {
        let contents = toml::to_string(self)?;
        fs::write(path, contents)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            identity_path: PathBuf::from("test_identity.txt"),
            recipients: vec!["test_recipient1".to_string(), "test_recipient2".to_string()],
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
            identity_path: PathBuf::from("test_identity.txt"),
            recipients: vec!["test_recipient1".to_string(), "test_recipient2".to_string()],
        };

        config.to_file(&config_path).unwrap();
        let loaded_config = Config::from_file(&config_path).unwrap();

        assert_eq!(config, loaded_config);
    }
}
