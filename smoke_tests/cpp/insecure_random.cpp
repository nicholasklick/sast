// Insecure Random Number Generation in C++
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <random>
#include <string>

// Test 1: Using rand() for security purposes
std::string generate_token_rand(int length) {
    std::string token;
    // VULNERABLE: rand() is not cryptographically secure
    for (int i = 0; i < length; i++) {
        token += 'a' + (rand() % 26);
    }
    return token;
}

// Test 2: Predictable seed with time
void seed_with_time() {
    // VULNERABLE: Predictable seed
    srand(time(nullptr));
}

// Test 3: Using std::default_random_engine for security
std::string generate_password_default() {
    std::default_random_engine gen;
    std::uniform_int_distribution<> dist(0, 25);

    std::string password;
    // VULNERABLE: default_random_engine is not cryptographically secure
    for (int i = 0; i < 16; i++) {
        password += 'A' + dist(gen);
    }
    return password;
}

// Test 4: mt19937 without proper seeding
std::string generate_key_mt() {
    std::mt19937 gen;  // VULNERABLE: Default seeded, predictable
    std::uniform_int_distribution<> dist(0, 255);

    std::string key;
    for (int i = 0; i < 32; i++) {
        key += static_cast<char>(dist(gen));
    }
    return key;
}

// Test 5: Linear congruential generator for crypto
int generate_nonce_lcg() {
    std::minstd_rand gen(42);
    // VULNERABLE: LCG is predictable
    return gen();
}

// Test 6: Seeding mt19937 with single 32-bit value
std::string generate_session_id() {
    // VULNERABLE: Single 32-bit seed for 19937-bit state
    std::mt19937 gen(std::random_device{}());
    std::uniform_int_distribution<> dist(0, 15);

    std::string session;
    for (int i = 0; i < 32; i++) {
        int n = dist(gen);
        session += (n < 10) ? ('0' + n) : ('a' + n - 10);
    }
    return session;
}

// Test 7: Using rand_r (still not crypto-safe)
unsigned int generate_random_rand_r(unsigned int* seed) {
    // VULNERABLE: rand_r is not cryptographically secure
    return rand_r(seed);
}

// Test 8: std::random_shuffle uses rand internally
void shuffle_insecure(std::vector<int>& vec) {
    // VULNERABLE: random_shuffle may use rand()
    // Note: Deprecated in C++14, removed in C++17
    // std::random_shuffle(vec.begin(), vec.end());
    srand(time(nullptr));
    for (size_t i = vec.size() - 1; i > 0; i--) {
        size_t j = rand() % (i + 1);
        std::swap(vec[i], vec[j]);
    }
}
