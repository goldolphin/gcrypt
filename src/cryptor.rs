use crate::config::Config;
use crate::crypto::{decrypt_file, encrypt_file, read_identity_from_file};
use crate::dir_info::{DirInfo, FileInfo};
use crate::error::{Error, Result};
use age::x25519;
use data_encoding::BASE32HEX_NOPAD;
use filetime::FileTime;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, DirEntry, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::str::FromStr;

const DIR_INFO_FILE: &str = "dir_info";
const OBJECTS_DIR: &str = "objects";

pub struct KeySet {
    identity: x25519::Identity,
    recipients: Vec<x25519::Recipient>,
}

impl KeySet {
    pub fn from_config(config: &Config) -> Result<Self> {
        let identity_path = config.identity_path.to_string_lossy();
        let identity_path = shellexpand::tilde(identity_path.as_ref());
        let identity = read_identity_from_file(identity_path.as_ref())?;
        let mut recipients = config
            .recipients
            .iter()
            .map(|line| {
                let r = x25519::Recipient::from_str(line).map_err(Error::Static)?;
                Ok(r)
            })
            .collect::<Result<Vec<_>>>()?;
        let my_recipient = identity.to_public();

        // Ensure the identity's recipient is included for accessing encrypted data.
        if !recipients.contains(&my_recipient) {
            recipients.push(my_recipient);
        }
        Ok(Self {
            identity,
            recipients,
        })
    }
}

pub struct Reporter {
    unchanged_by_metadata: u32,
    unchanged_by_checksum: u32,
    added: u32,
    modified: u32,
    only_in_output: u32,
    reuse: u32,
}

impl Reporter {
    pub fn new() -> Self {
        Self {
            unchanged_by_metadata: 0,
            unchanged_by_checksum: 0,
            added: 0,
            modified: 0,
            only_in_output: 0,
            reuse: 0,
        }
    }

    pub fn unchanged_by_metadata(&mut self, _: impl AsRef<Path>) {
        self.unchanged_by_metadata += 1;
    }

    pub fn unchanged_by_checksum(&mut self, _: impl AsRef<Path>) {
        self.unchanged_by_checksum += 1;
    }

    pub fn added(&mut self, path: impl AsRef<Path>) {
        self.added += 1;
        println!("ADD: {}", path.as_ref().to_string_lossy());
    }

    pub fn modified(&mut self, path: impl AsRef<Path>) {
        self.modified += 1;
        println!("MODIFY: {}", path.as_ref().to_string_lossy());
    }

    pub fn only_in_output(&mut self, path: impl AsRef<Path>) {
        self.only_in_output += 1;
        println!("ONLY IN OUTPUT: {}", path.as_ref().to_string_lossy());
    }

    pub fn reuse(&mut self, _: impl AsRef<Path>) {
        self.reuse += 1;
    }

    pub fn report(&self) {
        println!("--- Summary ---\nInput:");
        println!(
            "  Total files: {}",
            self.unchanged_by_metadata + self.unchanged_by_checksum + self.added + self.modified
        );
        println!(
            "  Unchanged files(by metadata): {}",
            self.unchanged_by_metadata
        );
        println!(
            "  Unchanged files(by checksum): {}",
            self.unchanged_by_checksum
        );
        println!("  Added files: {}", self.added);
        println!("  Modified files: {}", self.modified);
        println!("Files only in output: {}", self.only_in_output);
        if self.only_in_output > 0 {
            println!("  WARNING: These files will be deleted during encryption/decryption.");
        }
        println!("File reuse: {}", self.reuse);

        println!();
        if self.added == 0 && self.modified == 0 && self.only_in_output == 0 {
            println!("No files changed.");
        } else {
            println!("Files changed.");
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
    Ok(BASE32HEX_NOPAD.encode(&hasher.finalize()))
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TraverseOrder {
    PreOrder,
    PostOrder,
}

fn traverse_dir(
    dir: impl AsRef<Path>,
    order: TraverseOrder,
    callback: &mut impl FnMut(&DirEntry) -> Result<()>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if order == TraverseOrder::PreOrder {
            callback(&entry)?;
        }
        if path.is_dir() {
            traverse_dir(path, order, callback)?;
        }
        if order == TraverseOrder::PostOrder {
            callback(&entry)?;
        }
    }
    Ok(())
}

fn get_dir_info_path(encrypted_dir: impl AsRef<Path>) -> PathBuf {
    encrypted_dir.as_ref().join(DIR_INFO_FILE)
}

/// Load the DirInfo of a encrypted directory
pub fn load_dir_info(encrypted_dir: impl AsRef<Path>, key_set: &KeySet) -> Result<DirInfo> {
    DirInfo::from_file(get_dir_info_path(encrypted_dir.as_ref()), &key_set.identity)
}

struct Context<'a> {
    source_dir: &'a Path,
    encrypted_dir: &'a Path,
    dir_info_path: PathBuf,
    objects_dir: PathBuf,
}

impl<'a> Context<'a> {
    pub fn new(source_dir: &'a Path, encrypted_dir: &'a Path) -> Self {
        Self {
            source_dir,
            encrypted_dir,
            dir_info_path: get_dir_info_path(encrypted_dir),
            objects_dir: encrypted_dir.join(OBJECTS_DIR),
        }
    }

    pub fn load_dir_info(&self, key_set: &KeySet) -> Result<DirInfo> {
        load_dir_info(self.encrypted_dir, key_set)
    }

    pub fn get_source_file(&self, file_key: &str) -> PathBuf {
        self.source_dir.join(file_key)
    }

    pub fn get_file_key<'b>(&self, source_file: &'b Path) -> Result<std::borrow::Cow<'b, str>> {
        Ok(source_file.strip_prefix(self.source_dir)?.to_string_lossy())
    }

    pub fn get_encrypted_file(&self, file_info: &FileInfo) -> PathBuf {
        let subdir = &file_info.checksum[0..2];
        self.objects_dir.join(subdir).join(&file_info.checksum)
    }
}

struct NoopActions;

impl Actions for NoopActions {
    fn encrypt_file(
        &self,
        _source_file: impl AsRef<Path>,
        _encrypted_file: impl AsRef<Path>,
        _recipients: &[x25519::Recipient],
    ) -> Result<()> {
        Ok(())
    }

    fn load_dir_info(&self, context: &Context, key_set: &KeySet) -> Result<DirInfo> {
        context.load_dir_info(&key_set)
    }

    fn save_dir_info(
        &self,
        _dir_info: &DirInfo,
        _path: impl AsRef<Path>,
        _recipients: &[x25519::Recipient],
    ) -> Result<()> {
        Ok(())
    }

    fn remove_dir(&self, _path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }

    fn remove_file(&self, _path: impl AsRef<Path>) -> Result<()> {
        Ok(())
    }
}

/// Check status of a source directory against a encrypted directory
///
/// # Arguments
/// * `source_dir` - Path to the source directory
/// * `encrypted_dir` - Path to the encrypted directory
/// * `key_set` - Set of keys for encryption
/// * `reporter` - Reporter to update with encryption status
///
/// # Returns
/// Result indicating success or failure
pub fn check_status(
    source_dir: impl AsRef<Path>,
    encrypted_dir: impl AsRef<Path>,
    key_set: &KeySet,
    reporter: &mut Reporter,
) -> Result<()> {
    process_source_directory(
        source_dir,
        encrypted_dir,
        key_set,
        reporter,
        &NoopActions {},
    )
}

struct EncryptActions;

impl Actions for EncryptActions {
    fn encrypt_file(
        &self,
        source_file: impl AsRef<Path>,
        encrypted_file: impl AsRef<Path>,
        recipients: &[x25519::Recipient],
    ) -> Result<()> {
        let source_file = source_file.as_ref();
        let encrypted_file = encrypted_file.as_ref();
        if let Some(parent) = encrypted_file.parent() {
            fs::create_dir_all(parent)?;
        }
        encrypt_file(
            &mut File::open(source_file)?,
            &mut File::create(encrypted_file)?,
            recipients,
        )
    }

    fn load_dir_info(&self, context: &Context, key_set: &KeySet) -> Result<DirInfo> {
        context
            .load_dir_info(&key_set)
            .or_else(|_| Ok(DirInfo::new()))
    }

    fn save_dir_info(
        &self,
        dir_info: &DirInfo,
        path: impl AsRef<Path>,
        recipients: &[x25519::Recipient],
    ) -> Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        dir_info.to_file(path, recipients)
    }

    fn remove_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::remove_dir(path.as_ref())?;
        Ok(())
    }

    fn remove_file(&self, path: impl AsRef<Path>) -> Result<()> {
        fs::remove_file(path.as_ref())?;
        Ok(())
    }
}

/// Encrypt a directory
///
/// # Arguments
/// * `source_dir` - Path to the source directory
/// * `encrypted_dir` - Path to the encrypted directory
/// * `key_set` - Set of keys for encryption
/// * `reporter` - Reporter to update with encryption status
///
/// # Returns
/// Result indicating success or failure
pub fn encrypt_directory(
    source_dir: impl AsRef<Path>,
    encrypted_dir: impl AsRef<Path>,
    key_set: &KeySet,
    reporter: &mut Reporter,
) -> Result<()> {
    process_source_directory(
        source_dir,
        encrypted_dir,
        key_set,
        reporter,
        &EncryptActions {},
    )
}

trait Actions {
    fn encrypt_file(
        &self,
        source_file: impl AsRef<Path>,
        encrypted_file: impl AsRef<Path>,
        recipients: &[x25519::Recipient],
    ) -> Result<()>;

    fn load_dir_info(&self, context: &Context, key_set: &KeySet) -> Result<DirInfo>;

    fn save_dir_info(
        &self,
        dir_info: &DirInfo,
        path: impl AsRef<Path>,
        recipients: &[x25519::Recipient],
    ) -> Result<()>;

    fn remove_dir(&self, path: impl AsRef<Path>) -> Result<()>;

    fn remove_file(&self, path: impl AsRef<Path>) -> Result<()>;
}

fn process_source_directory(
    source_dir: impl AsRef<Path>,
    encrypted_dir: impl AsRef<Path>,
    key_set: &KeySet,
    reporter: &mut Reporter,
    actions: &impl Actions,
) -> Result<()> {
    let context = Context::new(source_dir.as_ref(), encrypted_dir.as_ref());

    // Load the DirInfo
    let input_dir_info = actions.load_dir_info(&context, key_set)?;

    // Process directory entries
    let mut output_dir_info = DirInfo::new();

    traverse_dir(
        context.source_dir,
        TraverseOrder::PreOrder,
        &mut |entry| -> Result<()> {
            let source_file = entry.path();
            let file_name = entry.file_name();
            let file_name_str = file_name.to_string_lossy();

            if file_name_str.starts_with('.') {
                return Ok(());
            }

            let file_type = entry.file_type()?;
            if file_type.is_file() {
                let mtime = get_file_mtime(&source_file)?;
                let size = entry.metadata()?.len();
                let file_key = context.get_file_key(&source_file)?;
                let (checksum, content_changed) = match input_dir_info.items.get(file_key.as_ref())
                {
                    Some(input_file_info)
                        if context.get_encrypted_file(input_file_info).is_file() =>
                    {
                        if input_file_info.mtime == mtime && input_file_info.size == size {
                            // File is unchanged based on metadata
                            reporter.unchanged_by_metadata(&source_file);
                            (input_file_info.checksum.clone(), false)
                        } else {
                            let checksum = calculate_file_checksum(&source_file)?;
                            if *input_file_info.checksum == checksum {
                                // File is unchanged based on checksum
                                reporter.unchanged_by_checksum(&source_file);
                                (checksum, false)
                            } else {
                                // File is modified
                                reporter.modified(&source_file);
                                (checksum, true)
                            }
                        }
                    }
                    _ => {
                        // New file or obfuscated_name is changed
                        let checksum = calculate_file_checksum(&source_file)?;
                        reporter.added(&source_file);
                        (checksum, true)
                    }
                };

                let output_file_info = FileInfo {
                    mtime,
                    size,
                    checksum,
                };
                if content_changed {
                    let encrypted_file = context.get_encrypted_file(&output_file_info);
                    if encrypted_file.is_file() {
                        // Reuse existing encrypted file if checksum matches
                        reporter.reuse(&source_file);
                    } else {
                        // Encrypt the file
                        actions.encrypt_file(&source_file, &encrypted_file, &key_set.recipients)?;
                    }
                }
                output_dir_info
                    .items
                    .insert(file_key.to_string(), output_file_info);
            }

            Ok(())
        },
    )?;

    // Update the DirInfo with the new items
    if output_dir_info != input_dir_info || !context.dir_info_path.is_file() {
        // Save the updated DirInfo
        actions.save_dir_info(
            &output_dir_info,
            &context.dir_info_path,
            &key_set.recipients,
        )?;
    }

    // Delete items in encrypted directory but not in source directory
    let mut whitelist = output_dir_info
        .items
        .values()
        .map(|file_info| context.get_encrypted_file(file_info))
        .collect::<BTreeSet<_>>();
    whitelist.insert(context.dir_info_path);
    traverse_dir(
        context.encrypted_dir,
        TraverseOrder::PostOrder,
        &mut |entry| {
            let path = entry.path();
            if path.is_dir() {
                if fs::read_dir(&path)?.next().is_none() {
                    actions.remove_dir(&path)?;
                }
            } else {
                if !whitelist.contains(&path) {
                    reporter.only_in_output(&path);
                    actions.remove_file(&path)?;
                }
            }
            Ok(())
        },
    )?;

    Ok(())
}

/// Decrypt a directory
///
/// # Arguments
/// * `source_dir` - Path to the source directory
/// * `encrypted_dir` - Path to the encrypted directory
/// * `key_set` - Set of keys for decryption
/// * `reporter` - Reporter to update with decryption status
///
/// # Returns
/// Result indicating success or failure
pub fn decrypt_directory(
    source_dir: impl AsRef<Path>,
    encrypted_dir: impl AsRef<Path>,
    key_set: &KeySet,
    reporter: &mut Reporter,
) -> Result<()> {
    let context = Context::new(source_dir.as_ref(), encrypted_dir.as_ref());

    // Load the DirInfo
    let input_dir_info = context.load_dir_info(&key_set)?;

    // Process each item in the config
    for (file_key, input_file_info) in &input_dir_info.items {
        let source_file = context.get_source_file(file_key);
        let (mtime, content_changed) = if source_file.is_file() {
            let mtime = get_file_mtime(&source_file)?;
            let size = source_file.metadata()?.len();
            if mtime == input_file_info.mtime && size == input_file_info.size {
                reporter.unchanged_by_metadata(&source_file);
                (mtime, false)
            } else {
                let checksum = calculate_file_checksum(&source_file)?;
                if checksum == input_file_info.checksum {
                    reporter.unchanged_by_checksum(&source_file);
                    (mtime, false)
                } else {
                    reporter.modified(&source_file);
                    (mtime, true)
                }
            }
        } else {
            reporter.added(&source_file);
            (0, true)
        };

        if content_changed {
            if let Some(parent) = source_file.parent() {
                fs::create_dir_all(parent)?;
            }
            let encrypted_file = context.get_encrypted_file(input_file_info);
            decrypt_file(
                &mut File::open(&encrypted_file)?,
                &mut File::create(&source_file)?,
                &key_set.identity,
            )?;
        }
        if mtime != input_file_info.mtime {
            set_file_mtime(&source_file, input_file_info.mtime)?;
        }
    }

    // Delete items in source directory but not in encrypted directory
    traverse_dir(context.source_dir, TraverseOrder::PostOrder, &mut |entry| {
        let path = entry.path();
        if path.is_dir() {
            if fs::read_dir(&path)?.next().is_none() {
                fs::remove_dir(&path)?;
            }
        } else {
            let file_key = context.get_file_key(&path)?;
            if !input_dir_info.items.contains_key(file_key.as_ref()) {
                reporter.only_in_output(&path);
                fs::remove_file(&path)?;
            }
        }
        Ok(())
    })?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use std::io::{Read, Write};
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

        // Verify same content produces same checksum
        let checksum2 = calculate_file_checksum(&file_path).unwrap();
        assert_eq!(checksum, checksum2);
    }

    #[test]
    fn test_encrypt_directory() {
        let source_dir = tempdir().unwrap();
        let encrypted_dir = tempdir().unwrap();

        // Create test files and directories
        let file_path = source_dir.path().join("test.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"Test content").unwrap();

        let subdir_path = source_dir.path().join("subdir");
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
        encrypt_directory(
            source_dir.path(),
            encrypted_dir.path(),
            &key_set,
            &mut Reporter::new(),
        )
        .unwrap();

        // Verify DirInfo file was created in encrypted directory
        let context = Context::new(source_dir.path(), encrypted_dir.path());
        assert!(context.dir_info_path.exists());

        // Verify encrypted files were created in encrypted directory
        let dir_info = context.load_dir_info(&key_set).unwrap();

        // Verify encrypted file exists
        let file_info = dir_info.items.get("test.txt").unwrap();
        let encrypted_file = context.get_encrypted_file(file_info);
        assert!(encrypted_file.is_file());

        let file_info = dir_info.items.get("subdir/subfile.txt").unwrap();
        let encrypted_file = context.get_encrypted_file(file_info);
        assert!(encrypted_file.is_file());
    }

    #[test]
    fn test_decrypt_directory() {
        let source_dir = tempdir().unwrap();
        let encrypted_dir = tempdir().unwrap();
        let decrypted_dir = tempdir().unwrap();

        // Create test files and directories
        let file_path = source_dir.path().join("test.txt");
        let mut file = fs::File::create(&file_path).unwrap();
        file.write_all(b"Test content").unwrap();

        let subdir_path = source_dir.path().join("subdir");
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
        encrypt_directory(
            source_dir.path(),
            encrypted_dir.path(),
            &key_set,
            &mut Reporter::new(),
        )
        .unwrap();

        // Decrypt the directory
        decrypt_directory(
            decrypted_dir.path(),
            encrypted_dir.path(),
            &key_set,
            &mut Reporter::new(),
        )
        .unwrap();

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
