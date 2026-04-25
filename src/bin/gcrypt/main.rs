use age::secrecy::ExposeSecret;
use clap::Parser;
use gcrypt::cryptor;
use gcrypt::config;
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
        output: std::path::PathBuf,
    },
    /// Encrypt a directory
    Encrypt {
        /// Path to the input directory to encrypt
        #[clap(short, long, required = true)]
        input: std::path::PathBuf,

        /// Path to the output directory where encrypted files will be stored
        #[clap(short, long, required = true)]
        output: std::path::PathBuf,

        /// Path to the config file
        #[clap(short, long, required = true)]
        config: std::path::PathBuf,
    },
    /// Decrypt a directory
    Decrypt {
        /// Path to the encrypted input directory
        #[clap(short, long, required = true)]
        input: std::path::PathBuf,

        /// Path to the output directory where decrypted files will be stored
        #[clap(short, long, required = true)]
        output: std::path::PathBuf,

        /// Path to the config file
        #[clap(short, long, required = true)]
        config: std::path::PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    match args.command {
        Command::Keygen { output } => {
            let default_config = match output.parent() {
                Some(parent) => {
                    if !parent.as_os_str().is_empty() && !parent.is_dir() {
                        println!("Creating directories for key file...");
                        fs::create_dir_all(parent)?;
                    }
                    Ok(parent.join("gcrypt.config"))
                }
                None => {
                    Err("Please specify a valid file path...")

                }
            }?;

            if output.exists() {
                Err("Key file already exists. Please specify a different filename.")?;
            }

            println!("Generating X25519 key pair...");
            let (identity, recipient) = gcrypt::crypto::generate_keypair()?;
            let key_pair_str = format!("# created: {}\n# public key: {}\n{}", chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true), recipient.to_string(), identity.to_string().expose_secret());
            fs::write(&output, key_pair_str)?;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&output, fs::Permissions::from_mode(0o400))?;
            println!("Key pair generated and saved to {}.", output.to_string_lossy());

            if !default_config.exists() {
                let config = config::Config {
                    identity_path: output,
                    recipients: vec![],
                };
                config.to_file(&default_config)?;
                println!("Default config file created at {}.", default_config.to_string_lossy());
            }
        }

        Command::Encrypt {
            input,
            output,
            config,
        } => {
            println!("Encrypting directory: {}", input.to_string_lossy());
            println!("Output directory: {}", output.to_string_lossy());
            println!("Using config file: {}", config.to_string_lossy());

            let config = config::Config::from_file(config)?;
            let key_set = cryptor::KeySet::from_config(&config)?;
            let mut reporter = cryptor::Reporter::new();
            cryptor::encrypt_directory(input, output, &key_set, &mut reporter)?;
            reporter.report();
        }

        Command::Decrypt {
            input,
            output,
            config,
        } => {
            println!("Decrypting directory: {}", input.to_string_lossy());
            println!("Output directory: {}", output.to_string_lossy());
            println!("Using config file: {}", config.to_string_lossy());

            let config = config::Config::from_file(config)?;
            let key_set = cryptor::KeySet::from_config(&config)?;
            let mut reporter = cryptor::Reporter::new();
            cryptor::decrypt_directory(input, output, &key_set, &mut reporter)?;
            reporter.report();
        }
    }
    Ok(())
}
