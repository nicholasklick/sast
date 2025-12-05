// Insecure Cryptography vulnerabilities in C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/rc4.h>

// Test 1: Using MD5 for password hashing
void hash_password_md5(const char *password, unsigned char *output) {
    // VULNERABLE: MD5 is cryptographically broken
    MD5((unsigned char*)password, strlen(password), output);
}

// Test 2: Using SHA1 for security purposes
void hash_data_sha1(const char *data, unsigned char *output) {
    // VULNERABLE: SHA1 is deprecated for security
    SHA1((unsigned char*)data, strlen(data), output);
}

// Test 3: Using DES encryption
void encrypt_des(const char *key, const char *plaintext, char *ciphertext) {
    // VULNERABLE: DES has only 56-bit key
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key, 8);
    DES_set_key_unchecked(&des_key, &schedule);
    DES_ecb_encrypt((DES_cblock*)plaintext, (DES_cblock*)ciphertext, &schedule, DES_ENCRYPT);
}

// Test 4: ECB mode encryption
void encrypt_ecb(const unsigned char *key, const unsigned char *plaintext,
                 unsigned char *ciphertext, int len) {
    // VULNERABLE: ECB mode reveals patterns
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL);
    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, len);
    EVP_CIPHER_CTX_free(ctx);
}

// Test 5: RC4 stream cipher
void encrypt_rc4(const unsigned char *key, int key_len,
                 unsigned char *data, int data_len) {
    // VULNERABLE: RC4 has known weaknesses
    RC4_KEY rc4_key;
    RC4_set_key(&rc4_key, key_len, key);
    RC4(&rc4_key, data_len, data, data);
}

// Test 6: Hardcoded encryption key
void encrypt_with_hardcoded_key(const char *plaintext, char *ciphertext) {
    // VULNERABLE: Hardcoded key
    const unsigned char key[] = "ThisIsASecretKey";
    const unsigned char iv[] = "InitializationV";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    int outlen;
    EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext, &outlen,
                      (unsigned char*)plaintext, strlen(plaintext));
    EVP_CIPHER_CTX_free(ctx);
}

// Test 7: Static IV
void encrypt_static_iv(const unsigned char *key, const char *plaintext,
                       unsigned char *ciphertext) {
    // VULNERABLE: IV should be random
    const unsigned char iv[16] = {0};

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    int outlen;
    EVP_EncryptUpdate(ctx, ciphertext, &outlen,
                      (unsigned char*)plaintext, strlen(plaintext));
    EVP_CIPHER_CTX_free(ctx);
}

// Test 8: Insufficient key derivation
void derive_key_weak(const char *password, unsigned char *key) {
    // VULNERABLE: Direct hash instead of proper KDF
    SHA256((unsigned char*)password, strlen(password), key);
}
