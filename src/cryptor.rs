use crate::config::{Config, Item};
use crate::crypto::{decrypt_file, encrypt_file, obfuscate_filename};
use crate::error::{Result};
use age::x25519;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::{BufReader};
use std::path::Path;

const CONFIG_FILE_NAME: &str = ".gcrypt";
const ENCRYPTED_CONFIG_FILE_NAME: &str = ".gcrypted";

/// Calculate the SHA256 checksum of a file
fn calculate_file_checksum<P: AsRef<Path>>(file_path: P) -> Result<String> {
    let mut reader = BufReader::new(fs::File::open(file_path)?);
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

/// Load or create a .gcrypt configuration file
///
/// # Arguments
/// * `config_path` - Path to the .gcrypt configuration file
///
/// # Returns
/// Result indicating success or failure
pub fn load_or_create_config(config_path: impl AsRef<Path>) -> Result<Config> {
    let path = config_path.as_ref();
    let config = match Config::from_file(path) {
        Ok(c) => c,
        Err(_) => {
            let c = Config::new();
            c.to_file(path)?;
            c
        }
    };
    Ok(config)
}

/// Encrypt a directory
///
/// # Arguments
/// * `input_dir` - Path to the input directory to encrypt
/// * `output_dir` - Path to the output directory where encrypted files will be stored
/// * `recipient` - Recipient key for encryption
///
/// # Returns
/// Result indicating success or failure
pub fn encrypt_directory<P: AsRef<Path>, Q: AsRef<Path>>(
    input_dir: P,
    output_dir: Q,
    recipients: &Vec<x25519::Recipient>,
) -> Result<()> {
    let input = input_dir.as_ref();
    let output = output_dir.as_ref();

    // create the output directory if it doesn't exist
    fs::create_dir_all(output)?;

    // Load the config
    let config_path = input.join(CONFIG_FILE_NAME);
    let config = load_or_create_config(&config_path)?;
    let obfuscation_key = config.parse_obfuscation_key()?;

    // Process directory entries
    let mut updated_items: HashMap<String, Item> = HashMap::new();
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        if file_name_str == CONFIG_FILE_NAME || file_name_str.starts_with('.') {
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let checksum = calculate_file_checksum(&path)?;
            let obfuscated_name = obfuscate_filename(&obfuscation_key, &file_name_str);
            let input_file = input.join(file_name_str.as_ref());
            let output_file = output.join(&obfuscated_name);
            let item = Item::File {
                checksum,
                obfuscated_name,
            };
            if config.items.get(file_name_str.as_ref()) != Some(&item)
             || !output_file.is_file() {
                // Encrypt the file if it has changed or is new
                encrypt_file(&input_file, &output_file, recipients)?;
            }
            updated_items.insert(
                file_name_str.to_string(),
                item,
            );
        } else if file_type.is_dir() {
            let obfuscated_name = obfuscate_filename(&obfuscation_key, &file_name_str);
            let input_subdir = input.join(file_name_str.as_ref());
            let output_subdir = output.join(&obfuscated_name);
            // Encrypt the directory recursively
            encrypt_directory(input_subdir, output_subdir, recipients)?;
            updated_items.insert(
                file_name_str.to_string(),
                Item::Dir {
                    obfuscated_name,
                },
            );
        }        
    }
    // Update the config with the new items
    let mut updated_config = config.clone();
    updated_config.items = updated_items;
    updated_config.to_file(&config_path)?;

    // Encrypt the .gcrypt file and save it to the output directory
    encrypt_file(&config_path, &output.join(ENCRYPTED_CONFIG_FILE_NAME), recipients)?;

    Ok(())
}

/// Decrypt a directory
///
/// # Arguments
/// * `input_dir` - Path to the encrypted input directory
/// * `output_dir` - Path to the output directory where decrypted files will be stored
/// * `identity` - The identity key for decryption
///
/// # Returns
/// Result indicating success or failure
pub fn decrypt_directory<P: AsRef<Path>, Q: AsRef<Path>>(
    input_dir: P,
    output_dir: Q,
    identity: &x25519::Identity,
) -> Result<()> {
    let input = input_dir.as_ref();
    let output = output_dir.as_ref();

    // create the output directory if it doesn't exist
    fs::create_dir_all(output)?;

    // Decrypt the .gcrypt file and save it to the output directory
    let config_path = output.join(CONFIG_FILE_NAME);
    decrypt_file(&input.join(ENCRYPTED_CONFIG_FILE_NAME), &config_path, identity)?;
    let config = Config::from_file(config_path)?;

    // Process each item in the config
    for (name, item) in &config.items {
        match item {
            Item::File {
                checksum,
                obfuscated_name,
            } => {
                let input_file = input.join(obfuscated_name);
                let output_file = output.join(name);
                if output_file.is_file() {
                    let existing_checksum = calculate_file_checksum(&output_file)?;
                    if existing_checksum == *checksum {
                        continue; // Skip decryption if the file is unchanged
                    }
                }

                // Decrypt the file
                decrypt_file(&input_file, &output_file, identity)?;
            }
            Item::Dir { obfuscated_name } => {
                let input_subdir = input.join(obfuscated_name);
                let output_subdir = output.join(name);
                // Decrypt the subdirectory recursively
                decrypt_directory(&input_subdir, &output_subdir, identity)?;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use std::io::{Write, Read};
    use tempfile::tempdir;

    #[test]
    fn test_calculate_file_checksum() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");

        // Create a test file
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"Hello, World!").unwrap();

        // Calculate checksum
        let checksum = calculate_file_checksum(&file_path).unwrap();

        // Verify it's not empty
        assert!(!checksum.is_empty());

        // Verify it's a valid hex string
        assert!(checksum.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify same content produces same checksum
        let checksum2 = calculate_file_checksum(&file_path).unwrap();
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_encrypt_directory() {
        let input_dir = tempdir().unwrap();
        let output_dir = tempdir().unwrap();

        // Create test files and directories
        let file_path = input_dir.path().join("test.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"Test content").unwrap();

        let subdir_path = input_dir.path().join("subdir");
        fs::create_dir(&subdir_path).unwrap();

        let subfile_path = subdir_path.join("subfile.txt");
        let mut subfile = fs::File::create(&subfile_path).unwrap();
        subfile.write_all(b"Subfile content").unwrap();

        // Generate a key pair for testing
        let (_, recipient) = generate_keypair().unwrap();

        // Encrypt the directory
        encrypt_directory(input_dir.path(), output_dir.path(), &vec![recipient]).unwrap();

        // Verify .gcrypt file was created in input directory
        let gcrypt_path = input_dir.path().join(".gcrypt");
        assert!(gcrypt_path.exists());

        // Verify encrypted files were created in output directory
        let config = Config::from_file(&gcrypt_path).unwrap();

        // Check that items exist in config
        assert!(config.items.contains_key("test.txt"));
        assert!(config.items.contains_key("subdir"));

        // Verify encrypted file exists
        if let Item::File {
            checksum: _,
            obfuscated_name,
        } = config.items.get("test.txt").unwrap()
        {
            let encrypted_file = output_dir.path().join(obfuscated_name);
            assert!(encrypted_file.exists());
        }

        // Verify encrypted subdirectory exists
        if let Item::Dir { obfuscated_name } = config.items.get("subdir").unwrap() {
            let encrypted_subdir = output_dir.path().join(obfuscated_name);
            assert!(encrypted_subdir.exists());

            // Verify subfile was encrypted
            let sub_gcrypt_path = input_dir.path().join("subdir").join(".gcrypt");
            assert!(sub_gcrypt_path.exists());

            let sub_config = Config::from_file(&sub_gcrypt_path).unwrap();
            assert!(sub_config.items.contains_key("subfile.txt"));

            if let Item::File {
                checksum: _,
                obfuscated_name,
            } = sub_config.items.get("subfile.txt").unwrap()
            {
                let encrypted_subfile = encrypted_subdir.join(obfuscated_name);
                assert!(encrypted_subfile.exists());
            }
        }
    }

    #[test]
    fn test_decrypt_directory() {
        let input_dir = tempdir().unwrap();
        let output_dir = tempdir().unwrap();
        let decrypted_dir = tempdir().unwrap();

        // Create test files and directories
        let file_path = input_dir.path().join("test.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"Test content").unwrap();

        let subdir_path = input_dir.path().join("subdir");
        fs::create_dir(&subdir_path).unwrap();

        let subfile_path = subdir_path.join("subfile.txt");
        let mut subfile = fs::File::create(&subfile_path).unwrap();
        subfile.write_all(b"Subfile content").unwrap();

        // Generate a key pair for testing
        let (identity, recipient) = generate_keypair().unwrap();

        // Encrypt the directory
        encrypt_directory(input_dir.path(), output_dir.path(), &vec![recipient]).unwrap();

        // Decrypt the directory
        decrypt_directory(output_dir.path(), decrypted_dir.path(), &identity).unwrap();

        // Verify decrypted files exist and have correct content
        let decrypted_file = decrypted_dir.path().join("test.txt");
        assert!(decrypted_file.exists());

        let mut decrypted_content = String::new();
        fs::File::open(&decrypted_file)
            .unwrap()
            .read_to_string(&mut decrypted_content)
            .unwrap();
        assert_eq!(decrypted_content, "Test content");

        // Verify decrypted subdirectory exists
        let decrypted_subdir = decrypted_dir.path().join("subdir");
        assert!(decrypted_subdir.exists());

        // Verify decrypted subfile exists and has correct content
        let decrypted_subfile = decrypted_subdir.join("subfile.txt");
        assert!(decrypted_subfile.exists());

        decrypted_content.clear();
        fs::File::open(&decrypted_subfile)
            .unwrap()
            .read_to_string(&mut decrypted_content)
            .unwrap();
        assert_eq!(decrypted_content, "Subfile content");
    }
}
