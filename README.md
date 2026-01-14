# copilot
repository for copilot

## AES-256-CBC File Encryption/Decryption Tool

A C program that encrypts and decrypts text files using OpenSSL's AES-256-CBC encryption algorithm with pre-shared keys.

### Features

- **AES-256-CBC Encryption**: Industry-standard encryption algorithm
- **Pre-shared Keys**: Uses pre-agreed key and IV pairs provided via command-line options
- **Flexible Input**: Accepts keys and IVs in hexadecimal format
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

The program requires a 256-bit key (64 hexadecimal characters) and a 128-bit IV (32 hexadecimal characters) to be provided via command-line options.

#### Encryption

Using short options:
```bash
./crypto_program -e -k <KEY_HEX> -i <IV_HEX> input.txt encrypted.bin
```

Using long options:
```bash
./crypto_program --encrypt --key=<KEY_HEX> --iv=<IV_HEX> input.txt encrypted.bin
```

#### Decryption

Using short options:
```bash
./crypto_program -d -k <KEY_HEX> -i <IV_HEX> encrypted.bin output.txt
```

Using long options:
```bash
./crypto_program --decrypt --key=<KEY_HEX> --iv=<IV_HEX> encrypted.bin output.txt
```

#### Help

To display usage information:
```bash
./crypto_program -h
# or
./crypto_program --help
```

### Example

```bash
# Define your pre-shared key and IV (in hexadecimal)
KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
IV="fedcba9876543210fedcba9876543210"

# Create a test file
echo "This is a secret message!" > input.txt

# Encrypt the file
./crypto_program -e -k "$KEY" -i "$IV" input.txt encrypted.bin

# Decrypt the file
./crypto_program -d -k "$KEY" -i "$IV" encrypted.bin output.txt

# Verify the decryption
cat output.txt

# Verify the decryption
cat output.txt
```

### Command-Line Options

#### Required Options

- `-k, --key=KEY`: 256-bit encryption key in hexadecimal format (64 characters)
- `-i, --iv=IV`: 128-bit initialization vector in hexadecimal format (32 characters)

#### Mode Options (one required)

- `-e, --encrypt`: Encrypt the input file
- `-d, --decrypt`: Decrypt the input file

#### Other Options

- `-h, --help`: Display help message

### Files Generated

- **encrypted.bin**: The encrypted output file (binary data)
- **output.txt**: The decrypted output file

### Security Notes

- **Keep your keys and IVs secure** - anyone with these values can decrypt your encrypted files
- The key and IV must be pre-agreed and shared securely between parties
- Use the same key and IV pair for encryption and decryption
- Keys and IVs can be in lowercase, uppercase, or mixed case hexadecimal
- The program uses OpenSSL's EVP interface for encryption/decryption

### Error Handling

The program handles various error conditions:
- Missing key or IV options
- Invalid hexadecimal format for key or IV
- Incorrect key or IV length
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
- **Key Size**: 256 bits (32 bytes / 64 hex characters)
- **IV Size**: 128 bits (16 bytes / 32 hex characters)
- **Block Size**: 128 bits (16 bytes)
- **Library**: OpenSSL EVP interface
- **Key/IV Input**: Hexadecimal string format
