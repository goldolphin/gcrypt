# gcrypt
A simple, portable folder-oriented encryption tool

## Rage Key Management

### Creating Rage Keys

To create a new rage key pair, you can use the `rage-keygen` tool, which is part of the rage encryption tool. Here's how to install rage on macOS:

```bash
# Using Homebrew
brew install rage

# Using cargo (Rust package manager)
cargo install rage
```

Once rage is installed, you can generate a new key pair:

```bash
# Generate a new rage key pair
rage-keygen -o key.txt
```

This will create a file `key.txt` containing your private key. The public key will be displayed in the terminal.

### Getting the Key ID

The key ID is the public key of your rage key pair. When you generate a key pair with `rage-keygen`, the public key is displayed in the terminal. It looks something like this:

```
# created: 2026-04-13T12:34:56+00:00
# public key: age1yt3wfvsfqx0x8g2yqz5p8m09n6f3x7d4c2v1b
AGE-SECRET-KEY-1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
```

The public key is `age1yt3wfvsfqx0x8g2yqz5p8m09n6f3x7d4c2v1b`. This is the key ID you should use with gcrypt.

### Importing and Exporting Keys

#### Exporting Keys

To export your rage key, simply copy the contents of the `key.txt` file you created with `rage-keygen`.

#### Importing Keys

To import a rage key, create a file containing the secret key and use it with gcrypt.

## Usage with gcrypt

### Encrypting a Directory

```bash
# Encrypt a directory using a rage key ID
gcrypt encrypt --input /path/to/input --output /path/to/output --id age1yt3wfvsfqx0x8g2yqz5p8m09n6f3x7d4c2v1b
```

### Decrypting a Directory

```bash
# Decrypt a directory using the same rage key ID
gcrypt decrypt --input /path/to/encrypted --output /path/to/decrypted --id age1yt3wfvsfqx0x8g2yqz5p8m09n6f3x7d4c2v1b
```

## Note

Currently, gcrypt expects the key ID to be the full rage secret key. This is a temporary implementation and will be improved in future versions to support proper key management with key IDs.