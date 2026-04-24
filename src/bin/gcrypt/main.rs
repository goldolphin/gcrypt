use age::secrecy::ExposeSecret;
use clap::Parser;
use gcrypt::cryptor;
use gcrypt::crypto;
use std::fs;

#[derive(Parser, Debug)]
#[clap(
    version = "0.1.0",
    about = "A simple, portable folder-oriented encryption tool"
)]
struct Args {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
enum Command {
    /// Generate a new X25519 key pair
    Keygen {
        /// Path to the output file where the generated key pair will be saved
        #[clap(short, long, required = true)]
        output: String,
    },
    /// Encrypt a directory
    Encrypt {
        /// Path to the input directory to encrypt
        #[clap(short, long, required = true)]
        input: String,

        /// Path to the output directory where encrypted files will be stored
        #[clap(short, long, required = true)]
        output: String,

        /// Path to the file containing the recipient keys for encryption
        #[clap(long, required = true)]
        recipients: String,
    },
    /// Decrypt a directory
    Decrypt {
        /// Path to the encrypted input directory
        #[clap(short, long, required = true)]
        input: String,

        /// Path to the output directory where decrypted files will be stored
        #[clap(short, long, required = true)]
        output: String,

        /// Path to the file containing the identity key for decryption
        #[clap(long, required = true)]
        identity: String,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Keygen { output } => {
            let path = std::path::Path::new(&output);
            match path.parent() {
                Some(parent) => {
                    if !parent.as_os_str().is_empty() && !parent.is_dir() {
                        println!("Creating directories for key file...");
                        fs::create_dir_all(parent)?;
                    }
                }
                None => {
                    println!("Please specify a valid file path...");
                }
            }
            if path.exists() {
                Err("Key file already exists. Please specify a different filename.")?;
            }
            println!("Generating X25519 key pair...");
            let (identity, recipient) = gcrypt::crypto::generate_keypair()?;
            let key_pair_str = format!("# created: {}\n# public key: {}\n{}", chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true), recipient.to_string(), identity.to_string().expose_secret());
            fs::write(path, key_pair_str)?;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
            println!("Key pair generated and saved to {}.", path.to_string_lossy());
        }
        Command::Encrypt {
            input,
            output,
            recipients,
        } => {
            println!("Encrypting directory: {}", input);
            println!("Output directory: {}", output);
            println!("Using recipient keys file: {}", recipients);

            // Read the recipient keys from file
            let recipients = crypto::read_recipients_from_file(&recipients)?;

            cryptor::encrypt_directory(input, output, &recipients)?;
        }
        Command::Decrypt {
            input,
            output,
            identity,
        } => {
            println!("Decrypting directory: {}", input);
            println!("Output directory: {}", output);
            println!("Using identity key file: {}", identity);

            // Read the identity key from file
            let identity = crypto::read_identity_from_file(&identity)?;

            cryptor::decrypt_directory(input, output, &identity)?;
        }
    }
    Ok(())
}
