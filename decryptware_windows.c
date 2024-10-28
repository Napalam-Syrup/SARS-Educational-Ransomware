#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <sys/stat.h>

#define KEYLENGTH 32
#define IVLENGTH 16

int check_extension(const char *filename, const char *extension) {
    // Find the last dot in the filename
    const char *dot = strrchr(filename, '.');
    if (!dot || dot == filename) {
        return 0; // No extension found
    }

    // Compare the file extension with the expected one
    return strcmp(dot + 1, extension) == 0;
}

int d(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
             unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Failed to create context");
        exit(1);
    }

    // Initialize the decryption operation
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        perror("Failed to initialize decryption");
        exit(1);
    }

    // Provide the ciphertext to be decrypted
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        perror("Decryption error");
        exit(1);
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        perror("Finalizing decryption error");
        unsigned long err = ERR_get_error();
        char err_msg[120];
        ERR_error_string_n(err, err_msg, sizeof(err_msg));
        fprintf(stderr, "Finalizing decryption error: %s\n", err_msg);
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

void sign(char* fn) {
    strcat(fn, ".restored");
}


void decrypt_files(const char *dir_path, unsigned char* key, unsigned char* iv) {
    struct dirent *entry;
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        perror("Error opening directory");
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char file_path[1024];
        struct stat statbuf;
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);

        if (!check_extension(file_path, "mpl")) {
            printf("Skipping non-encrypted file: %s\n", entry->d_name);
            continue;
        }

         if (stat(file_path, &statbuf) == 0) {
            if (S_ISREG(statbuf.st_mode)) {
                FILE *cipher_file = fopen(file_path, "rb");
                if (cipher_file == NULL) {
                    perror("Error opening encrypted file");
                    continue;
                }

                // Read the encrypted file size
                fseek(cipher_file, 0, SEEK_END);
                long ciphertext_len = ftell(cipher_file);
                fseek(cipher_file, 0, SEEK_SET);

                // Allocate buffer for ciphertext and read it
                unsigned char *ciphertext = (unsigned char *)malloc(ciphertext_len);
                fread(ciphertext, 1, ciphertext_len, cipher_file);
                fclose(cipher_file);

                // Decrypt the ciphertext
                unsigned char *plaintext = (unsigned char *)malloc(ciphertext_len + EVP_MAX_BLOCK_LENGTH);
                int plaintext_len = d(ciphertext, ciphertext_len, key, iv, plaintext);

                // Write the decrypted content to a new file
                char cleaned_file_path[2048];
                strcpy(cleaned_file_path, file_path);
                sign(cleaned_file_path);

                FILE *clean_file = fopen(cleaned_file_path, "wb");
                if (clean_file == NULL) {
                    perror("Error creating decrypted file");
                    free(ciphertext);
                    continue;
                }
                fwrite(plaintext, 1, plaintext_len, clean_file);
                fclose(clean_file);
                free(ciphertext);

                printf("Decrypted: %s -> %s\n", file_path, cleaned_file_path);
            }
        }
    }
    closedir(dir);
}

int main (void) {
    unsigned char key[KEYLENGTH];
    unsigned char iv[IVLENGTH];
    FILE* keys = fopen("keys.txt", "rb");  // Use binary mode
    if (keys == NULL) {
        perror("Error opening keys.txt");
        return 1;
    }

    // Ensure correct size of key and iv are read
    if (fread(key, 1, sizeof(key), keys) != sizeof(key)) {
        fprintf(stderr, "Error reading key\n");
        fclose(keys);
        return 1;
    }
    if (fread(iv, 1, sizeof(iv), keys) != sizeof(iv)) {
        fprintf(stderr, "Error reading IV\n");
        fclose(keys);
        return 1;
    }

    // debugging
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    for (int i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    decrypt_files(".", key, iv);

}