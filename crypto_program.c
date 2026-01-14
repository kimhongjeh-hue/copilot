#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define KEY_SIZE 32  // AES-256 requires 32 bytes
#define IV_SIZE 16   // AES block size is 16 bytes
#define KEY_FILE "key.bin"

// Function to handle OpenSSL errors
void handle_openssl_error(void) {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

// Generate random key and IV, then save to file
int generate_and_save_key_iv(const char *key_file, unsigned char *key, unsigned char *iv) {
    FILE *fp;

    // Generate random key and IV
    if (RAND_bytes(key, KEY_SIZE) != 1) {
        fprintf(stderr, "Error generating random key\n");
        handle_openssl_error();
    }

    if (RAND_bytes(iv, IV_SIZE) != 1) {
        fprintf(stderr, "Error generating random IV\n");
        handle_openssl_error();
    }

    // Save key and IV to file
    fp = fopen(key_file, "wb");
    if (!fp) {
        perror("Error opening key file for writing");
        return 0;
    }

    if (fwrite(key, 1, KEY_SIZE, fp) != KEY_SIZE) {
        fprintf(stderr, "Error writing key to file\n");
        fclose(fp);
        return 0;
    }

    if (fwrite(iv, 1, IV_SIZE, fp) != IV_SIZE) {
        fprintf(stderr, "Error writing IV to file\n");
        fclose(fp);
        return 0;
    }

    fclose(fp);
    printf("Key and IV saved to %s\n", key_file);
    return 1;
}

// Load key and IV from file
int load_key_iv(const char *key_file, unsigned char *key, unsigned char *iv) {
    FILE *fp = fopen(key_file, "rb");
    if (!fp) {
        perror("Error opening key file for reading");
        return 0;
    }

    if (fread(key, 1, KEY_SIZE, fp) != KEY_SIZE) {
        fprintf(stderr, "Error reading key from file\n");
        fclose(fp);
        return 0;
    }

    if (fread(iv, 1, IV_SIZE, fp) != IV_SIZE) {
        fprintf(stderr, "Error reading IV from file\n");
        fclose(fp);
        return 0;
    }

    fclose(fp);
    printf("Key and IV loaded from %s\n", key_file);
    return 1;
}

// Encrypt file using AES-256-CBC
int encrypt_file(const char *input_file, const char *output_file, const char *key_file) {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    FILE *in_fp, *out_fp;
    EVP_CIPHER_CTX *ctx;

    // Generate and save key and IV directly to the buffers
    if (!generate_and_save_key_iv(key_file, key, iv)) {
        return 0;
    }

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
int decrypt_file(const char *input_file, const char *output_file, const char *key_file) {
    unsigned char key[KEY_SIZE];
    unsigned char iv[IV_SIZE];
    unsigned char inbuf[1024];
    unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    FILE *in_fp, *out_fp;
    EVP_CIPHER_CTX *ctx;

    // Load key and IV from file
    if (!load_key_iv(key_file, key, iv)) {
        return 0;
    }

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
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -e, --encrypt    Encrypt the input file\n");
    fprintf(stderr, "  -d, --decrypt    Decrypt the input file\n");
    fprintf(stderr, "  -h, --help       Display this help message\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  %s -e input.txt encrypted.bin\n", program_name);
    fprintf(stderr, "  %s --encrypt input.txt encrypted.bin\n", program_name);
    fprintf(stderr, "  %s -d encrypted.bin output.txt\n", program_name);
    fprintf(stderr, "  %s --decrypt encrypted.bin output.txt\n", program_name);
    fprintf(stderr, "\nBackward compatibility:\n");
    fprintf(stderr, "  %s encrypt <input_file> <output_file>\n", program_name);
    fprintf(stderr, "  %s decrypt <input_file> <output_file>\n", program_name);
}

int main(int argc, char *argv[]) {
    int encrypt_mode = -1; // -1: not set, 0: decrypt, 1: encrypt
    const char *input_file = NULL;
    const char *output_file = NULL;
    
    // Check for backward compatibility (old format: program encrypt/decrypt input output)
    if (argc == 4 && (strcmp(argv[1], "encrypt") == 0 || strcmp(argv[1], "decrypt") == 0)) {
        encrypt_mode = (strcmp(argv[1], "encrypt") == 0) ? 1 : 0;
        input_file = argv[2];
        output_file = argv[3];
    } else {
        // Parse options using getopt_long
        static struct option long_options[] = {
            {"encrypt", no_argument, 0, 'e'},
            {"decrypt", no_argument, 0, 'd'},
            {"help", no_argument, 0, 'h'},
            {0, 0, 0, 0}
        };
        
        int opt;
        int option_index = 0;
        
        while ((opt = getopt_long(argc, argv, "edh", long_options, &option_index)) != -1) {
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
    }

    int success = 0;
    if (encrypt_mode == 1) {
        success = encrypt_file(input_file, output_file, KEY_FILE);
    } else {
        success = decrypt_file(input_file, output_file, KEY_FILE);
    }

    return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
