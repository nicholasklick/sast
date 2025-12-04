// Weak Cryptography vulnerabilities in C++
#include <iostream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <openssl/md5.h>
#include <openssl/des.h>

std::string hash_md5(const std::string& input) {
    // VULNERABLE: MD5 is cryptographically broken
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)input.c_str(), input.length(), digest);
    return std::string((char*)digest, MD5_DIGEST_LENGTH);
}

void encrypt_des(const std::string& data, const std::string& key) {
    // VULNERABLE: DES is obsolete
    DES_cblock des_key;
    DES_key_schedule schedule;
    memcpy(des_key, key.c_str(), 8);
    DES_set_key(&des_key, &schedule);
}

int generate_token() {
    // VULNERABLE: Non-cryptographic random
    srand(time(NULL));
    return rand();
}

class WeakPRNG {
public:
    int next() {
        // VULNERABLE: Predictable random
        return std::rand() % 1000000;
    }
};

std::string weak_session_id() {
    // VULNERABLE: Predictable session ID
    srand(time(nullptr));
    return std::to_string(rand());
}
