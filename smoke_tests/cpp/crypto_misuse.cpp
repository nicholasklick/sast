// Cryptography Misuse vulnerabilities in C++
#include <iostream>
#include <string>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

// Test 1: Using deprecated/weak MD5
void hash_md5(const std::string& input) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    // VULNERABLE: MD5 is cryptographically broken
    MD5((unsigned char*)input.c_str(), input.length(), hash);
}

// Test 2: Using weak SHA1
void hash_sha1(const std::string& input) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    // VULNERABLE: SHA1 is deprecated for security use
    SHA1((unsigned char*)input.c_str(), input.length(), hash);
}

// Test 3: Using DES (weak)
void encrypt_des(const char* key, const char* data) {
    DES_cblock key_block;
    DES_key_schedule schedule;
    memcpy(key_block, key, 8);
    DES_set_key_unchecked(&key_block, &schedule);
    // VULNERABLE: DES has only 56-bit key
    DES_cblock output;
    DES_ecb_encrypt((DES_cblock*)data, &output, &schedule, DES_ENCRYPT);
}

// Test 4: ECB mode (pattern-preserving)
void encrypt_ecb(const unsigned char* key, const unsigned char* data, size_t len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // VULNERABLE: ECB mode reveals patterns
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr, key, nullptr);
    unsigned char output[1024];
    int outlen;
    EVP_EncryptUpdate(ctx, output, &outlen, data, len);
    EVP_CIPHER_CTX_free(ctx);
}

// Test 5: Hardcoded encryption key
void encrypt_with_hardcoded_key(const char* data) {
    // VULNERABLE: Hardcoded key
    const unsigned char key[] = "0123456789abcdef";
    const unsigned char iv[] = "abcdef0123456789";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    EVP_CIPHER_CTX_free(ctx);
}

// Test 6: Constant/predictable IV
void encrypt_with_constant_iv(const unsigned char* key, const char* data) {
    // VULNERABLE: IV should be random per encryption
    const unsigned char iv[16] = {0};  // All zeros

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    EVP_CIPHER_CTX_free(ctx);
}

// Test 7: Using rand() for cryptographic purpose
void generate_weak_key(unsigned char* key, size_t len) {
    // VULNERABLE: rand() is not cryptographically secure
    srand(time(nullptr));
    for (size_t i = 0; i < len; i++) {
        key[i] = rand() % 256;
    }
}

// Test 8: Small RSA key size
RSA* generate_weak_rsa() {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, RSA_F4);
    // VULNERABLE: 1024-bit RSA is too weak
    RSA_generate_key_ex(rsa, 1024, e, nullptr);
    BN_free(e);
    return rsa;
}

// Test 9: No authentication (encrypt without MAC)
void encrypt_without_auth(const unsigned char* key, const unsigned char* iv,
                          const unsigned char* data, size_t len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // VULNERABLE: No authentication, susceptible to tampering
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    unsigned char output[1024];
    int outlen;
    EVP_EncryptUpdate(ctx, output, &outlen, data, len);
    EVP_CIPHER_CTX_free(ctx);
}

// Test 10: Password as encryption key directly
void encrypt_with_password(const char* password, const char* data) {
    // VULNERABLE: Password should go through KDF
    unsigned char key[16];
    memcpy(key, password, std::min(strlen(password), sizeof(key)));

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = {0};
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, iv);
    EVP_CIPHER_CTX_free(ctx);
}

// Test 11: Insufficient PBKDF2 iterations
void derive_key_weak(const char* password, unsigned char* key) {
    unsigned char salt[8] = {1,2,3,4,5,6,7,8};
    // VULNERABLE: Too few iterations
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, 8,
                       1000,  // Should be much higher (100000+)
                       EVP_sha256(), 32, key);
}

// Test 12: Static salt
void hash_password_static_salt(const char* password) {
    // VULNERABLE: Salt should be random per password
    const unsigned char static_salt[] = "constant_salt_value";
    unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password),
                       static_salt, sizeof(static_salt) - 1,
                       100000, EVP_sha256(), 32, hash);
}
