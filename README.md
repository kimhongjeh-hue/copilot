# copilot
repository for copilot

## AES-256-CBC File Encryption/Decryption Tool

A C program that encrypts and decrypts text files using OpenSSL's AES-256-CBC encryption algorithm.

### Features

- **AES-256-CBC Encryption**: Industry-standard encryption algorithm
- **Dynamic Key Generation**: Random key and IV generation for each encryption operation
- **Key Management**: Automatic key/IV storage and retrieval
- **Error Handling**: Comprehensive error handling for file I/O and OpenSSL operations
- **Easy to Use**: Simple command-line interface

### Requirements

- Linux operating system
- GCC compiler
- OpenSSL development libraries (libssl-dev)

### Installation

1. Install OpenSSL development libraries (if not already installed):
   ```bash
   sudo apt-get install libssl-dev
   ```

2. Compile the program:
   ```bash
   make
   ```

### Usage

#### Encryption
To encrypt a file using short options:
```bash
./crypto_program -e input.txt encrypted.bin
```

Or using long options:
```bash
./crypto_program --encrypt input.txt encrypted.bin
```

This will:
- Read the plaintext from `input.txt`
- Generate a random 256-bit key and 128-bit IV
- Save the key and IV to `key.bin`
- Encrypt the file using AES-256-CBC
- Write the encrypted data to `encrypted.bin`

#### Decryption
To decrypt a file using short options:
```bash
./crypto_program -d encrypted.bin output.txt
```

Or using long options:
```bash
./crypto_program --decrypt encrypted.bin output.txt
```

This will:
- Read the key and IV from `key.bin`
- Read the encrypted data from `encrypted.bin`
- Decrypt the data using AES-256-CBC
- Write the decrypted plaintext to `output.txt`

#### Help
To display usage information:
```bash
./crypto_program -h
# or
./crypto_program --help
```

### Example

```bash
# Create a test file
echo "This is a secret message!" > input.txt

# Encrypt the file (using short option)
./crypto_program -e input.txt encrypted.bin

# Decrypt the file (using short option)
./crypto_program -d encrypted.bin output.txt

# Verify the decryption
cat output.txt

# Or use long options
./crypto_program --encrypt input.txt encrypted.bin
./crypto_program --decrypt encrypted.bin output.txt
```

### Files Generated

- **key.bin**: Contains the 32-byte encryption key and 16-byte IV (total 48 bytes)
- **encrypted.bin**: The encrypted output file (binary data)
- **output.txt**: The decrypted output file

### Security Notes

- Keep `key.bin` secure - anyone with this file can decrypt your encrypted files
- The key and IV are randomly generated for each encryption operation
- Do not share or expose the `key.bin` file
- The program uses OpenSSL's EVP interface for encryption/decryption

### Error Handling

The program handles various error conditions:
- Missing or incorrect command-line arguments
- File read/write errors
- Invalid encryption/decryption operations
- OpenSSL library errors

### Cleaning Up

To remove compiled binaries and generated files:
```bash
make clean
```

### Technical Details

- **Algorithm**: AES-256-CBC (Advanced Encryption Standard with 256-bit key in Cipher Block Chaining mode)
- **Key Size**: 256 bits (32 bytes)
- **IV Size**: 128 bits (16 bytes)
- **Block Size**: 128 bits (16 bytes)
- **Library**: OpenSSL EVP interface
