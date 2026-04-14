use crate::define_error;

// Generate error types using the macro
define_error! (
    Error {
        #[from]
        Io(std::io::Error),
        #[from]
        Decrypt(age::DecryptError),
        #[from]
        Encrypt(age::EncryptError),
        #[from]
        TomlDe(toml::de::Error),
        #[from]
        TomlSer(toml::ser::Error),
        #[from]
        SystemTime(std::time::SystemTimeError),
        #[from]
        FromUtf8(std::string::FromUtf8Error),
        #[from]
        StripPrefix(std::path::StripPrefixError),
        Generic(&'static str)
    }
);
