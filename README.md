# gcrypt
A simple, portable folder-oriented encryption tool

## Key Management

### Creating Keys

Once gcrypt is installed, you can generate a new key pair:

```bash
# Generate a new key pair
gcrypt keygen -o key.txt
```

This will create a file `key.txt` containing your private key with the public key in the comments.

### Getting the identity and recipient files

When you generate a key pair with `gcrypt keygen`, it looks something like this:

```
# created: 2026-04-13T12:34:56+00:00
# public key: age1yt3wfvsfqx0x8g2yqz5p8m09n6f3x7d4c2v1b
AGE-SECRET-KEY-1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
```

The public key is `age1yt3wfvsfqx0x8g2yqz5p8m09n6f3x7d4c2v1b`. You can add public keys of yours and others in a `recipients.txt` line by line. The file containing your private key (like `key.txt` created by `gcrypt keygen`) is your identity file, which is used for decryption.

### Importing and Exporting Keys

#### Exporting Keys

To export your key, simply copy the contents of the `key.txt` file you created with `gcrypt keygen`.

#### Importing Keys

To import a key, create a file containing the secret key and use it with gcrypt.

## Usage with gcrypt

### Encrypting a Directory

```bash
# Encrypt a directory using a recipients.txt
gcrypt encrypt -i /path/to/input -o /path/to/output --recipients /path/to/recipients.txt
```

### Decrypting a Directory

```bash
# Decrypt a directory using a key.txt
gcrypt decrypt -i /path/to/encrypted -o /path/to/decrypted --identity /path/to/key.txt
```