// Weak Cryptography vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include <openssl/rand.h>

void hash_password_md5(const char *password, unsigned char *digest) {
    // VULNERABLE: MD5 is broken for passwords
    MD5((unsigned char*)password, strlen(password), digest);
}

void encrypt_des(const char *data, const char *key, char *output) {
    // VULNERABLE: DES is obsolete
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, 8);
    DES_set_key(&des_key, &schedule);
    DES_ecb_encrypt((DES_cblock*)data, (DES_cblock*)output, &schedule, DES_ENCRYPT);
}

int weak_random() {
    // VULNERABLE: Using rand() for security
    return rand() % 1000000;
}

void generate_token(char *buffer, int len) {
    // VULNERABLE: Predictable random with time seed
    srand(time(NULL));
    for (int i = 0; i < len; i++) {
        buffer[i] = 'a' + rand() % 26;
    }
}

void ecb_mode_encryption(unsigned char *data, unsigned char *key) {
    // VULNERABLE: ECB mode leaks patterns
    // ECB encryption implementation
}
