#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <ctype.h>

#define KEY_SIZE 32  // AES-256 requires 32 bytes
#define IV_SIZE 16   // AES block size is 16 bytes

// Function to handle OpenSSL errors
void handle_openssl_error(void) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Convert hex string to bytes
int hex_to_bytes(const char *hex_str, unsigned char *bytes, int expected_len) {
    int len = strlen(hex_str);
    
    // Check if hex string length is correct (2 hex chars per byte)
    if (len != expected_len * 2) {
        return 0;
    }
    
    for (int i = 0; i < expected_len; i++) {
        int high, low;
        
        // Convert high nibble
        if (isdigit(hex_str[i * 2])) {
            high = hex_str[i * 2] - '0';
        } else if (hex_str[i * 2] >= 'a' && hex_str[i * 2] <= 'f') {
            high = hex_str[i * 2] - 'a' + 10;
        } else if (hex_str[i * 2] >= 'A' && hex_str[i * 2] <= 'F') {
            high = hex_str[i * 2] - 'A' + 10;
        } else {
            return 0; // Invalid character
        }
        
        // Convert low nibble
        if (isdigit(hex_str[i * 2 + 1])) {
            low = hex_str[i * 2 + 1] - '0';
        } else if (hex_str[i * 2 + 1] >= 'a' && hex_str[i * 2 + 1] <= 'f') {
            low = hex_str[i * 2 + 1] - 'a' + 10;
        } else if (hex_str[i * 2 + 1] >= 'A' && hex_str[i * 2 + 1] <= 'F') {
            low = hex_str[i * 2 + 1] - 'A' + 10;
        } else {
            return 0; // Invalid character
        }
        
        bytes[i] = (high << 4) | low;
    }
    
    return 1;
}

// Encrypt file using AES-256-CBC
int encrypt_file(const char *input_file, const char *output_file, 
                 const unsigned char *key, const unsigned char *iv) {
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    FILE *in_fp, *out_fp;
    EVP_CIPHER_CTX *ctx;

    // Open input file
    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        perror("Error opening input file");
        return 0;
    }

    // Open output file
    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        perror("Error opening output file");
        fclose(in_fp);
        return 0;
    }

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        handle_openssl_error();
    }

    // Initialize encryption operation with AES-256-CBC
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing encryption\n");
        handle_openssl_error();
    }

    // Encrypt file in chunks
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in_fp)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Error during encryption\n");
            handle_openssl_error();
        }
        if (fwrite(outbuf, 1, outlen, out_fp) != (size_t)outlen) {
            fprintf(stderr, "Error writing encrypted data to file\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_fp);
            fclose(out_fp);
            return 0;
        }
    }

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Error finalizing encryption\n");
        handle_openssl_error();
    }
    if (fwrite(outbuf, 1, outlen, out_fp) != (size_t)outlen) {
        fprintf(stderr, "Error writing final encrypted data to file\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_fp);
        fclose(out_fp);
        return 0;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    fclose(in_fp);
    fclose(out_fp);

    printf("Encryption successful: %s -> %s\n", input_file, output_file);
    return 1;
}

// Decrypt file using AES-256-CBC
int decrypt_file(const char *input_file, const char *output_file, 
                 const unsigned char *key, const unsigned char *iv) {
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    FILE *in_fp, *out_fp;
    EVP_CIPHER_CTX *ctx;

    // Open input file
    in_fp = fopen(input_file, "rb");
    if (!in_fp) {
        perror("Error opening input file");
        return 0;
    }

    // Open output file
    out_fp = fopen(output_file, "wb");
    if (!out_fp) {
        perror("Error opening output file");
        fclose(in_fp);
        return 0;
    }

    // Create and initialize the context
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creating cipher context\n");
        handle_openssl_error();
    }

    // Initialize decryption operation with AES-256-CBC
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) != 1) {
        fprintf(stderr, "Error initializing decryption\n");
        handle_openssl_error();
    }

    // Decrypt file in chunks
    while ((inlen = fread(inbuf, 1, sizeof(inbuf), in_fp)) > 0) {
        if (EVP_DecryptUpdate(ctx, outbuf, &outlen, inbuf, inlen) != 1) {
            fprintf(stderr, "Error during decryption\n");
            handle_openssl_error();
        }
        if (fwrite(outbuf, 1, outlen, out_fp) != (size_t)outlen) {
            fprintf(stderr, "Error writing decrypted data to file\n");
            EVP_CIPHER_CTX_free(ctx);
            fclose(in_fp);
            fclose(out_fp);
            return 0;
        }
    }

    // Finalize decryption
    if (EVP_DecryptFinal_ex(ctx, outbuf, &outlen) != 1) {
        fprintf(stderr, "Error finalizing decryption\n");
        handle_openssl_error();
    }
    if (fwrite(outbuf, 1, outlen, out_fp) != (size_t)outlen) {
        fprintf(stderr, "Error writing final decrypted data to file\n");
        EVP_CIPHER_CTX_free(ctx);
        fclose(in_fp);
        fclose(out_fp);
        return 0;
    }

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    fclose(in_fp);
    fclose(out_fp);

    printf("Decryption successful: %s -> %s\n", input_file, output_file);
    return 1;
}

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage:\n");
    fprintf(stderr, "  %s [OPTIONS] <input_file> <output_file>\n", program_name);
    fprintf(stderr, "\nRequired Options:\n");
    fprintf(stderr, "  -k, --key=KEY    256-bit key in hexadecimal (64 hex characters)\n");
    fprintf(stderr, "  -i, --iv=IV      128-bit IV in hexadecimal (32 hex characters)\n");
    fprintf(stderr, "\nMode Options (one required):\n");
    fprintf(stderr, "  -e, --encrypt    Encrypt the input file\n");
    fprintf(stderr, "  -d, --decrypt    Decrypt the input file\n");
    fprintf(stderr, "\nOther Options:\n");
    fprintf(stderr, "  -h, --help       Display this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -e -k 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \\\n", program_name);
    fprintf(stderr, "        -i 0123456789abcdef0123456789abcdef input.txt encrypted.bin\n");
    fprintf(stderr, "  %s --decrypt --key=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \\\n", program_name);
    fprintf(stderr, "        --iv=0123456789abcdef0123456789abcdef encrypted.bin output.txt\n");
}

int main(int argc, char *argv[]) {
    int encrypt_mode = -1; // -1: not set, 0: decrypt, 1: encrypt
    const char *input_file = NULL;
    const char *output_file = NULL;
    const char *key_hex = NULL;
    const char *iv_hex = NULL;
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    
    // Parse options using getopt_long
    static struct option long_options[] = {
        {"encrypt", no_argument, 0, 'e'},
        {"decrypt", no_argument, 0, 'd'},
        {"key", required_argument, 0, 'k'},
        {"iv", required_argument, 0, 'i'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "edk:i:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'e':
                if (encrypt_mode != -1) {
                    fprintf(stderr, "Error: Cannot specify both encrypt and decrypt\n");
                    return EXIT_FAILURE;
                }
                encrypt_mode = 1;
                break;
            case 'd':
                if (encrypt_mode != -1) {
                    fprintf(stderr, "Error: Cannot specify both encrypt and decrypt\n");
                    return EXIT_FAILURE;
                }
                encrypt_mode = 0;
                break;
            case 'k':
                key_hex = optarg;
                break;
            case 'i':
                iv_hex = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }
    
    // Get input and output files from remaining arguments
    if (optind + 2 == argc) {
        input_file = argv[optind];
        output_file = argv[optind + 1];
    } else {
        fprintf(stderr, "Error: Missing input or output file\n\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    // Check if mode was specified
    if (encrypt_mode == -1) {
        fprintf(stderr, "Error: Must specify either -e/--encrypt or -d/--decrypt\n\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Check if key was specified
    if (key_hex == NULL) {
        fprintf(stderr, "Error: Key is required. Use -k or --key option\n\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Check if IV was specified
    if (iv_hex == NULL) {
        fprintf(stderr, "Error: IV is required. Use -i or --iv option\n\n");
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    // Convert hex strings to bytes
    if (!hex_to_bytes(key_hex, key, KEY_SIZE)) {
        fprintf(stderr, "Error: Invalid key format. Key must be %d hexadecimal characters (representing %d bytes)\n", 
                KEY_SIZE * 2, KEY_SIZE);
        return EXIT_FAILURE;
    }

    if (!hex_to_bytes(iv_hex, iv, IV_SIZE)) {
        fprintf(stderr, "Error: Invalid IV format. IV must be %d hexadecimal characters (representing %d bytes)\n", 
                IV_SIZE * 2, IV_SIZE);
        return EXIT_FAILURE;
    }

    int success = 0;
    if (encrypt_mode == 1) {
        success = encrypt_file(input_file, output_file, key, iv);
    } else {
        success = decrypt_file(input_file, output_file, key, iv);
    }

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
