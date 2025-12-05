// Insecure Randomness vulnerabilities in Kotlin
package com.example.security

import java.util.Random
import kotlin.random.Random as KotlinRandom

class InsecureRandomVulnerabilities {

    // Test 1: java.util.Random for security
    fun generateToken(): String {
        // VULNERABLE: Not cryptographically secure
        val random = Random()
        return (1..32).map { random.nextInt(256).toString(16).padStart(2, '0') }.joinToString("")
    }

    // Test 2: Math.random() for security
    fun generateOtp(): String {
        // VULNERABLE: Math.random not crypto secure
        val otp = (Math.random() * 1000000).toInt()
        return otp.toString().padStart(6, '0')
    }

    // Test 3: Seeded random with predictable seed
    fun generateWithSeed(): Int {
        // VULNERABLE: Time-based seed is predictable
        val random = Random(System.currentTimeMillis())
        return random.nextInt()
    }

    // Test 4: Kotlin Random for secrets
    fun generateSessionId(): String {
        // VULNERABLE: kotlin.random may not be secure
        return (1..32).map { KotlinRandom.nextInt(0, 16).toString(16) }.joinToString("")
    }

    // Test 5: ThreadLocalRandom for security
    fun generateApiKey(): String {
        // VULNERABLE: Not designed for cryptography
        val random = java.util.concurrent.ThreadLocalRandom.current()
        val bytes = ByteArray(32)
        random.nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // Test 6: Predictable UUID
    fun generateId(userId: Int): String {
        // VULNERABLE: Predictable ID generation
        return "$userId-${System.currentTimeMillis()}"
    }

    // Test 7: Weak password generation
    fun generatePassword(length: Int): String {
        val chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        // VULNERABLE: Non-secure random
        val random = Random()
        return (1..length).map { chars[random.nextInt(chars.length)] }.joinToString("")
    }

    // Test 8: IV generation
    fun generateIV(): ByteArray {
        // VULNERABLE: IV should use SecureRandom
        val random = Random()
        val iv = ByteArray(16)
        random.nextBytes(iv)
        return iv
    }

    // Test 9: Salt generation
    fun generateSalt(): ByteArray {
        // VULNERABLE: Salt should use SecureRandom
        val random = Random()
        val salt = ByteArray(32)
        random.nextBytes(salt)
        return salt
    }

    // Test 10: Nonce generation
    fun generateNonce(): Long {
        // VULNERABLE: Predictable nonce
        return System.nanoTime()
    }

    // Test 11: CSRF token
    fun generateCsrfToken(): String {
        // VULNERABLE: Not crypto random
        val random = Random()
        return random.nextLong().toString(16)
    }

    // Test 12: Shuffling for security
    fun shuffleSecure(items: List<String>): List<String> {
        // VULNERABLE: shuffle uses non-secure random
        return items.shuffled()
    }

    // Test 13: Email verification code
    fun generateVerificationCode(): String {
        // VULNERABLE: Predictable code
        val random = Random()
        return (1..6).map { random.nextInt(10) }.joinToString("")
    }

    // Secure alternative (for reference)
    fun secureRandom(size: Int): ByteArray {
        val random = java.security.SecureRandom()
        val bytes = ByteArray(size)
        random.nextBytes(bytes)
        return bytes
    }
}
