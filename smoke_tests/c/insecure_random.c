// Insecure Random Number Generation in C
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

// Test 1: Using rand() for security-sensitive purposes
void generate_session_token(char *token, int length) {
    // VULNERABLE: rand() is not cryptographically secure
    for (int i = 0; i < length; i++) {
        token[i] = 'a' + (rand() % 26);
    }
    token[length] = '\0';
}

// Test 2: Predictable seed with time()
void init_random() {
    // VULNERABLE: Predictable seed
    srand(time(NULL));
}

// Test 3: Using rand() for password generation
void generate_password(char *password, int length) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%";
    // VULNERABLE: rand() for password generation
    for (int i = 0; i < length; i++) {
        password[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    password[length] = '\0';
}

// Test 4: Using rand() for cryptographic key
void generate_key(unsigned char *key, int key_length) {
    // VULNERABLE: rand() for crypto key
    for (int i = 0; i < key_length; i++) {
        key[i] = rand() % 256;
    }
}

// Test 5: Constant seed
void init_with_constant_seed() {
    // VULNERABLE: Constant seed makes output predictable
    srand(12345);
}

// Test 6: Using random() without srandom()
int get_random_id() {
    // VULNERABLE: random() without proper seeding
    return random() % 10000;
}

// Test 7: rand() for nonce generation
void generate_nonce(unsigned char *nonce, int size) {
    // VULNERABLE: Nonces must be unpredictable
    for (int i = 0; i < size; i++) {
        nonce[i] = rand() & 0xFF;
    }
}
