use crate::config::Config;
use crate::crypto::{decrypt_file, encrypt_file, obfuscate_filename, read_identity_from_file};
use crate::error::{Result, Error};
use crate::dir_info::{DirInfo, Item, FileInfo};
use age::x25519;
use filetime::FileTime;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{BufReader};
use std::path::{Path, PathBuf};
use std::str::FromStr;

const DIR_INFO_FILENAME: &str = ".gcrypt";

pub struct KeySet {
    identity: x25519::Identity,
    recipients: Vec<x25519::Recipient>,
}

impl KeySet {
    pub fn from_config(config: &Config) -> Result<Self> {
        let identity_path = config.identity_path.to_string_lossy();
        let identity_path = shellexpand::tilde(identity_path.as_ref());
        let identity = read_identity_from_file(identity_path.as_ref())?;
        let mut recipients = config.recipients.iter()
            .map(|line| {
                let r = x25519::Recipient::from_str(line).map_err(Error::Generic)?;
                Ok(r)
            })
            .collect::<Result<Vec<_>>>()?;
        let my_recipient = identity.to_public();

        // Ensure the identity's recipient is included for accessing encrypted data.
        if !recipients.contains(&my_recipient) {
            recipients.push(my_recipient);
        }
        Ok(Self { identity, recipients })
    }
}

pub struct Reporter {
    unchanged_by_metadata: Vec<PathBuf>,
    unchanged_by_checksum: Vec<PathBuf>,
    added: Vec<PathBuf>,
    modified: Vec<PathBuf>,
    deleted: Vec<PathBuf>,
    updated_dir_infos: Vec<PathBuf>,
}

impl Reporter {
    pub fn new() -> Self {
        Self {
            unchanged_by_metadata: Vec::new(),
            unchanged_by_checksum: Vec::new(),
            added: Vec::new(),
            modified: Vec::new(),
            deleted: Vec::new(),
            updated_dir_infos: Vec::new(),
        }
    }

    pub fn report(&self) {
        println!("Input:");
        println!("  Total files: {}", self.unchanged_by_metadata.len() + self.unchanged_by_checksum.len() + self.added.len() + self.modified.len());
        println!("  Unchanged files(by metadata): {}", self.unchanged_by_metadata.len());
        println!("  Unchanged files(by checksum): {}", self.unchanged_by_checksum.len());
        println!("  Added files: {}", self.added.len());
        for path in &self.added {
            println!("    | {}", path.to_string_lossy());
        }
        println!("  Modified files: {}", self.modified.len());
        for path in &self.modified {
            println!("    | {}", path.to_string_lossy());
        }

        println!("  Updated DirInfos: {}", self.updated_dir_infos.len());
        println!("Deleted items in output: {}", self.deleted.len());
        for path in &self.deleted {
            println!("    | {}", path.to_string_lossy());
        }
    }
}

fn get_file_mtime(path: impl AsRef<Path>) -> Result<i64> {
    let metadata = fs::metadata(path.as_ref())?;
    let mtime = FileTime::from_last_modification_time(&metadata).seconds();
    Ok(mtime)
}

fn set_file_mtime(path: impl AsRef<Path>, mtime: i64) -> Result<()> {
    let file_time = FileTime::from_unix_time(mtime, 0);
    filetime::set_file_mtime(path.as_ref(), file_time)?;
    Ok(())
}

/// Calculate the SHA256 checksum of a file
fn calculate_file_checksum(file_path: impl AsRef<Path>) -> Result<String> {
    let mut reader = BufReader::new(fs::File::open(file_path)?);
    let mut hasher = Sha256::new();
    std::io::copy(&mut reader, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

impl DirInfo {
    fn from_file(path: impl AsRef<Path>, identity: &x25519::Identity) -> Result<Self> {
        let mut buf = Vec::<u8>::new();
        decrypt_file(&mut File::open(path)?, &mut buf, identity)?;
        DirInfo::from_str(&String::from_utf8(buf)?)
    }
    
    fn to_file(&self, path: impl AsRef<Path>, recipients: &[x25519::Recipient]) -> Result<()> {
        let buf = self.to_string()?;
        encrypt_file(&mut buf.as_bytes(), &mut File::create(path)?, recipients)?;
        Ok(())
    }
}

/// Load or create a DirInfo file
///
/// # Arguments
/// * `path` - Path to the DirInfo file
/// * `identity` - The identity key for decryption
///
/// # Returns
/// Result indicating success or failure
pub fn load_or_create_dir_info(path: impl AsRef<Path>, identity: &x25519::Identity) -> Result<DirInfo> {
    let dir_info: DirInfo = match DirInfo::from_file(path.as_ref(), identity) {
        Ok(c) => c,
        Err(_) => DirInfo::new()
    };
    Ok(dir_info)
}

fn clean_dir(dir_path: impl AsRef<Path>, white_list: &BTreeSet<&str>, reporter: &mut Reporter) -> Result<()> {
    for entry in fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        if white_list.contains(file_name_str.as_ref()) {
            continue;
        }

        if path.is_dir() {
            fs::remove_dir_all(&path)?;
        } else {
            fs::remove_file(&path)?;
        }
        reporter.deleted.push(path);
    }

    Ok(())
}

/// Encrypt a directory
///
/// # Arguments
/// * `input_dir` - Path to the input directory to encrypt
/// * `output_dir` - Path to the output directory where encrypted files will be stored
/// * `key_set` - Set of keys for encryption
///
/// # Returns
/// Result indicating success or failure
pub fn encrypt_directory(
    input_dir: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    key_set: &KeySet,
    reporter: &mut Reporter,
) -> Result<()> {
    let input = input_dir.as_ref();
    let output = output_dir.as_ref();

    // create the output directory if it doesn't exist
    fs::create_dir_all(output)?;

    // Load the DirInfo
    let dir_info_path = output.join(DIR_INFO_FILENAME);
    let dir_info = load_or_create_dir_info(&dir_info_path, &key_set.identity)?;
    let obfuscation_key = dir_info.parse_obfuscation_key()?;

    // Process directory entries
    let mut updated_items: BTreeMap<String, Item> = BTreeMap::new();
    for entry in fs::read_dir(input)? {
        let entry = entry?;
        let input_file = entry.path();
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        if file_name_str == DIR_INFO_FILENAME || file_name_str.starts_with('.') {
            continue;
        }

        let file_type = entry.file_type()?;
        if file_type.is_file() {
            let mtime = get_file_mtime(&input_file)?;
            let size = entry.metadata()?.len();
            let obfuscated_name = obfuscate_filename(&obfuscation_key, &file_name_str);
            let (checksum, to_encrypt) = match dir_info.items.get(file_name_str.as_ref()) {
                Some(Item::File (recorded)) if *recorded.obfuscated_name == obfuscated_name => {
                    if recorded.mtime == mtime && recorded.size == size {
                        // File is unchanged based on metadata
                        reporter.unchanged_by_metadata.push(input_file.clone());
                        (recorded.checksum.clone(), false)
                    } else {
                        let checksum = calculate_file_checksum(&input_file)?;
                        if *recorded.checksum == checksum {
                            // File is unchanged based on checksum
                            reporter.unchanged_by_checksum.push(input_file.clone());
                            (checksum, false)
                        } else {
                            // File is modified
                            reporter.modified.push(input_file.clone());
                            (checksum, true)
                        }
                    }
                }
                _ => {
                    // New file or obfuscated_name is changed
                    let checksum = calculate_file_checksum(&input_file)?;
                    reporter.added.push(input_file.clone());
                    (checksum, true)
                }
            };
            if to_encrypt {
                let output_file = output.join(&obfuscated_name);
                encrypt_file(&mut File::open(&input_file)?, &mut File::create(&output_file)?, &key_set.recipients)?;
            }
            updated_items.insert(
                file_name_str.to_string(),
                Item::File(
                    FileInfo {
                        mtime,
                        size,
                        checksum,
                        obfuscated_name,
                    }
                ),
            );
        } else if file_type.is_dir() {
            let obfuscated_name = obfuscate_filename(&obfuscation_key, &file_name_str);
            let input_subdir = input.join(file_name_str.as_ref());
            let output_subdir = output.join(&obfuscated_name);
            // Encrypt the directory recursively
            encrypt_directory(input_subdir, output_subdir, key_set, reporter)?;
            updated_items.insert(
                file_name_str.to_string(),
                Item::Dir {
                    obfuscated_name,
                },
            );
        }        
    }

    // Update the DirInfo with the new items
    let mut updated_dir_info = dir_info.clone();
    updated_dir_info.items = updated_items;
    if updated_dir_info != dir_info || !dir_info_path.is_file() {
        reporter.updated_dir_infos.push(input.to_path_buf());

        // Save the updated DirInfo
        updated_dir_info.to_file(&dir_info_path, &key_set.recipients)?;
    }

    // Delete items in output directory but not in input directory
    let mut white_list = updated_dir_info.items.values().map(|item| match item {
        Item::File (info) => info.obfuscated_name.as_str(),
        Item::Dir { obfuscated_name } => obfuscated_name,
    }).collect::<BTreeSet<_>>();
    white_list.insert(DIR_INFO_FILENAME);
    clean_dir(output, &white_list, reporter)?;

    Ok(())
}

/// Decrypt a directory
///
/// # Arguments
/// * `input_dir` - Path to the encrypted input directory
/// * `output_dir` - Path to the output directory where decrypted files will be stored
/// * `key_set` - Set of keys for decryption
///
/// # Returns
/// Result indicating success or failure
pub fn decrypt_directory(
    input_dir: impl AsRef<Path>,
    output_dir: impl AsRef<Path>,
    key_set: &KeySet,
    reporter: &mut Reporter,
) -> Result<()> {
    let input = input_dir.as_ref();
    let output = output_dir.as_ref();

    // create the output directory if it doesn't exist
    fs::create_dir_all(output)?;

    // Load the DirInfo
    let dir_info_path = input.join(DIR_INFO_FILENAME);
    let dir_info = load_or_create_dir_info(&dir_info_path, &key_set.identity)?;

    // Process each item in the config
    for (name, item) in &dir_info.items {
        match item {
            Item::File (recorded) => {
                let input_file = input.join(&recorded.obfuscated_name);
                let output_file = output.join(name);
                let (mtime, to_decrypt) = if output_file.is_file() {
                    let mtime = get_file_mtime(&output_file)?;
                    let size = output_file.metadata()?.len();
                    if mtime == recorded.mtime && size == recorded.size {
                        reporter.unchanged_by_metadata.push(output_file.clone());
                        (mtime, false)
                    } else {
                        let checksum = calculate_file_checksum(&output_file)?;
                        if checksum == *recorded.checksum {
                            reporter.unchanged_by_checksum.push(output_file.clone());
                            (mtime, false)
                        } else {
                            reporter.modified.push(output_file.clone());
                            (mtime, true)
                        }
                    }
                } else {
                    reporter.added.push(output_file.clone());
                    (0, true)
                };

                if to_decrypt {
                    decrypt_file(&mut File::open(&input_file)?, &mut File::create(&output_file)?, &key_set.identity)?;
                }
                if mtime != recorded.mtime {
                    set_file_mtime(&output_file, recorded.mtime)?;
                }
            }
            Item::Dir { obfuscated_name } => {
                let input_subdir = input.join(obfuscated_name);
                let output_subdir = output.join(name);
                // Decrypt the subdirectory recursively
                decrypt_directory(&input_subdir, &output_subdir, key_set, reporter)?;
            }
        }
    }

    // Delete items in output directory but not in input directory
    let white_list = dir_info.items.keys().map(String::as_str).collect::<BTreeSet<_>>();
    clean_dir(output, &white_list, reporter)?;

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

        // Generate a KeySet for testing
        let (identity, recipient) = generate_keypair().unwrap();
        let key_set = KeySet {
            identity,
            recipients: vec![recipient],
        };

        // Encrypt the directory
        encrypt_directory(input_dir.path(), output_dir.path(), &key_set, &mut Reporter::new()).unwrap();

        // Verify DirInfo file was created in output directory
        let dir_info_path = output_dir.path().join(DIR_INFO_FILENAME);
        assert!(dir_info_path.exists());

        // Verify encrypted files were created in output directory
        let dir_info = load_or_create_dir_info(dir_info_path, &key_set.identity).unwrap();

        // Check that items exist in DirInfo
        assert!(dir_info.items.contains_key("test.txt"));
        assert!(dir_info.items.contains_key("subdir"));

        // Verify encrypted file exists
        if let Item::File (info) = dir_info.items.get("test.txt").unwrap() {
            let encrypted_file = output_dir.path().join(&info.obfuscated_name);
            assert!(encrypted_file.exists());
        }

        // Verify encrypted subdirectory exists
        if let Item::Dir { obfuscated_name } = dir_info.items.get("subdir").unwrap() {
            let encrypted_subdir = output_dir.path().join(obfuscated_name);
            assert!(encrypted_subdir.exists());

            // Verify subfile was encrypted
            let dir_info_path = encrypted_subdir.join(DIR_INFO_FILENAME);
            assert!(dir_info_path.exists());

            let dir_info = load_or_create_dir_info(dir_info_path, &key_set.identity).unwrap();
            assert!(dir_info.items.contains_key("subfile.txt"));

            if let Item::File (info) = dir_info.items.get("subfile.txt").unwrap()
            {
                let encrypted_subfile = encrypted_subdir.join(&info.obfuscated_name);
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
        let key_set = KeySet {
            identity,
            recipients: vec![recipient],
        };

        // Encrypt the directory
        encrypt_directory(input_dir.path(), output_dir.path(), &key_set, &mut Reporter::new()).unwrap();

        // Decrypt the directory
        decrypt_directory(output_dir.path(), decrypted_dir.path(), &key_set, &mut Reporter::new()).unwrap();

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
