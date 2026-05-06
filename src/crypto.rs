use age::{Decryptor, Encryptor, x25519};
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use crate::error::{Error, Result};

pub fn read_identity_from_file(path: impl AsRef<Path>) -> Result<x25519::Identity> {
    let content = std::fs::read_to_string(path)?;
    let str = content
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .next()
        .ok_or_else(|| Error::Static("No identity found in file"))?;
    let identity = x25519::Identity::from_str(str).map_err(Error::Static)?;
    Ok(identity)
}

/// Generate a new X25519 key pair for encryption
pub fn generate_keypair() -> Result<(x25519::Identity, x25519::Recipient)> {
    let identity = x25519::Identity::generate();
    let recipient = identity.to_public();
    Ok((identity, recipient))
}

/// Encrypt a file using age encryption
///
/// # Arguments
/// * `reader` - Reader for the input file to encrypt
/// * `writer` - Writer where the encrypted file will be saved
/// * `recipients` - List of public keys for encryption
///
/// # Returns
/// Result indicating success or failure
pub fn encrypt_file(
    reader: &mut impl Read,
    writer: &mut impl Write,
    recipients: &[x25519::Recipient],
) -> Result<()> {
    // Create encryptor
    let encryptor = Encryptor::with_recipients(
        recipients
            .iter()
            .map(|r| Box::new(r.clone()) as Box<_>)
            .collect(),
    )
    .ok_or(Error::Static("Failed to create encryptor"))?;

    // Encrypt the data
    let mut encrypt_writer = encryptor.wrap_output(writer)?;
    std::io::copy(reader, &mut encrypt_writer)?;
    encrypt_writer.finish()?.flush()?;
    Ok(())
}

/// Decrypt a file using age encryption
///
/// # Arguments
/// * `input_path` - Path to the encrypted file
/// * `writer` - Writer where the decrypted file will be saved
/// * `identity` - Private key for decryption
///
/// # Returns
/// Result indicating success or failure
pub fn decrypt_file(
    reader: &mut impl Read,
    writer: &mut impl Write,
    identity: &x25519::Identity,
) -> Result<()> {
    // Create decryptor
    let decryptor = match Decryptor::new(reader)? {
        Decryptor::Recipients(d) => d,
        _ => return Err(age::DecryptError::InvalidHeader)?,
    };

    // Decrypt the data
    let mut decrypt_reader = decryptor.decrypt(std::iter::once(identity as &dyn age::Identity))?;
    std::io::copy(&mut decrypt_reader, writer)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::{Read, Write};
    use tempfile::NamedTempFile;

    #[test]
    fn test_keypair_generation() {
        let (identity, recipient) = generate_keypair().unwrap();

        // Verify we can get the public key from identity
        let derived_recipient = identity.to_public();
        assert_eq!(recipient.to_string(), derived_recipient.to_string());
    }

    #[test]
    fn test_encrypt_decrypt_file() {
        // Generate a test key pair
        let (identity, recipient) = generate_keypair().unwrap();

        // Create test input file
        let mut input_file = NamedTempFile::new().unwrap();
        let test_content = b"Hello, this is a test file for encryption!";
        input_file.write_all(test_content).unwrap();
        input_file.flush().unwrap();

        // Create temporary output files
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        // Test encryption
        encrypt_file(
            &mut File::open(input_file.path()).unwrap(),
            &mut File::create(encrypted_file.path()).unwrap(),
            &vec![recipient],
        )
        .expect("Failed to encrypt file");

        // Verify encrypted file exists and is not empty
        assert!(encrypted_file.path().exists());
        let encrypted_size = encrypted_file.path().metadata().unwrap().len();
        assert!(encrypted_size > 0);

        // Test decryption
        decrypt_file(
            &mut File::open(encrypted_file.path()).unwrap(),
            &mut File::create(decrypted_file.path()).unwrap(),
            &identity,
        )
        .expect("Failed to decrypt file");

        // Verify decrypted content matches original
        let mut decrypted_content = Vec::new();
        File::open(decrypted_file.path())
            .unwrap()
            .read_to_end(&mut decrypted_content)
            .unwrap();

        assert_eq!(test_content, decrypted_content.as_slice());
    }

    #[test]
    fn test_empty_file() {
        let (identity, recipient) = generate_keypair().unwrap();

        // Create empty test input file
        let input_file = NamedTempFile::new().unwrap();

        // Create temporary output files
        let encrypted_file = NamedTempFile::new().unwrap();
        let decrypted_file = NamedTempFile::new().unwrap();

        // Test encryption of empty file
        encrypt_file(
            &mut File::open(input_file.path()).unwrap(),
            &mut File::create(encrypted_file.path()).unwrap(),
            &vec![recipient],
        )
        .expect("Failed to encrypt empty file");

        // Test decryption of empty file
        decrypt_file(
            &mut File::open(encrypted_file.path()).unwrap(),
            &mut File::create(decrypted_file.path()).unwrap(),
            &identity,
        )
        .expect("Failed to decrypt empty file");

        // Verify decrypted file is also empty
        let decrypted_size = decrypted_file.path().metadata().unwrap().len();
        assert_eq!(decrypted_size, 0);
    }
}
