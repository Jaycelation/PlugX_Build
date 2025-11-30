#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>

void handleErrors(void) {
    printf("An error occurred during encryption/decryption.\n");
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int main(void) {
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345";

    unsigned char *plaintext = (unsigned char *)"RATCTF{Wow_AES}";
    
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];

    int decryptedtext_len, ciphertext_len;

    printf("Original: %s\n", plaintext);

    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    printf("Ciphertext length: %d\n", ciphertext_len);

    printf("Ciphertext (Hex): ");
    for(int i = 0; i < ciphertext_len; i++) printf("%02x", ciphertext[i]);
    printf("\n");
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

    decryptedtext[decryptedtext_len] = '\0';

    printf("Decrypted: %s\n", decryptedtext);

    return 0;
}