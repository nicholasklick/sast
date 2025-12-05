// Insecure Randomness vulnerabilities in Groovy
package com.example.security

import java.util.Random

class InsecureRandomVulnerabilities {

    // Test 1: java.util.Random for security
    String generateToken() {
        // VULNERABLE: Not cryptographically secure
        def random = new Random()
        (1..32).collect { String.format("%02x", random.nextInt(256)) }.join()
    }

    // Test 2: Math.random for security
    String generateOtp() {
        // VULNERABLE: Math.random not crypto secure
        def otp = (Math.random() * 1000000) as int
        String.format("%06d", otp)
    }

    // Test 3: Seeded random with predictable seed
    int generateWithSeed() {
        // VULNERABLE: Time-based seed is predictable
        def random = new Random(System.currentTimeMillis())
        random.nextInt()
    }

    // Test 4: Predictable UUID-like ID
    String generateId(int userId) {
        // VULNERABLE: Predictable ID generation
        "${userId}-${System.currentTimeMillis()}"
    }

    // Test 5: Weak password generation
    String generatePassword(int length) {
        def chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        // VULNERABLE: Non-secure random
        def random = new Random()
        (1..length).collect { chars[random.nextInt(chars.length())] }.join()
    }

    // Test 6: IV generation
    byte[] generateIV() {
        // VULNERABLE: IV should use SecureRandom
        def random = new Random()
        def iv = new byte[16]
        random.nextBytes(iv)
        iv
    }

    // Test 7: Salt generation
    byte[] generateSalt() {
        // VULNERABLE: Salt should use SecureRandom
        def random = new Random()
        def salt = new byte[32]
        random.nextBytes(salt)
        salt
    }

    // Test 8: Nonce generation
    long generateNonce() {
        // VULNERABLE: Predictable nonce
        System.nanoTime()
    }

    // Test 9: CSRF token
    String generateCsrfToken() {
        // VULNERABLE: Not crypto random
        new Random().nextLong().toString()
    }

    // Test 10: Shuffling for security
    List shuffleSecure(List items) {
        // VULNERABLE: shuffle uses non-secure random
        Collections.shuffle(items)
        items
    }

    // Test 11: Email verification code
    String generateVerificationCode() {
        // VULNERABLE: Predictable code
        def random = new Random()
        (1..6).collect { random.nextInt(10) }.join()
    }

    // Test 12: Groovy random methods
    int groovyRandom(int max) {
        // VULNERABLE: Groovy random extension
        new Random().nextInt(max)
    }

    // Test 13: ThreadLocalRandom for secrets
    String generateApiKey() {
        // VULNERABLE: Not designed for cryptography
        def random = java.util.concurrent.ThreadLocalRandom.current()
        def bytes = new byte[32]
        random.nextBytes(bytes)
        bytes.collect { String.format("%02x", it) }.join()
    }

    // Secure alternative
    byte[] secureRandom(int size) {
        def random = new java.security.SecureRandom()
        def bytes = new byte[size]
        random.nextBytes(bytes)
        bytes
    }
}
