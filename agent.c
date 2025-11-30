#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

typedef int (*AESFunc)(unsigned char*, int, unsigned char*, unsigned char*, unsigned char*);

int main() {
    HMODULE hDll = LoadLibrary("lib.dll");
    if (hDll == NULL) {
        printf("[!] Loi: Khong load duoc DLL. Ma loi: %lu\n", GetLastError());
        return 1;
    }

    AESFunc encrypt_ptr = (AESFunc)GetProcAddress(hDll, "AES_Encrypt_Export");
    AESFunc decrypt_ptr = (AESFunc)GetProcAddress(hDll, "AES_Decrypt_Export");

    if (!encrypt_ptr || !decrypt_ptr) {
        printf("[!] Loi: Khong tim thay ham trong DLL\n");
        return 1;
    }

    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    unsigned char *iv = (unsigned char *)"0123456789012345"; 

    char *msg = "Lenh: ipconfig /all";
    unsigned char ciphertext[256];
    unsigned char decryptedtext[256];

    printf("Original: %s\n", msg);

    int cipher_len = encrypt_ptr((unsigned char*)msg, strlen(msg), key, iv, ciphertext);

    printf("Cipher Length: %d\n", cipher_len);
    printf("Ciphertext (Hex): ");
    for(int i = 0; i < cipher_len; i++) printf("%02x", ciphertext[i]);
    printf("\n");

    int decrypted_len = decrypt_ptr(ciphertext, cipher_len, key, iv, decryptedtext);
    decryptedtext[decrypted_len] = '\0';
    printf("Decrypted from DLL: %s\n", decryptedtext);

    FreeLibrary(hDll);
    return 0;
}