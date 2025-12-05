// Authentication vulnerabilities in Kotlin
package com.example.security

import java.security.MessageDigest
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class AuthenticationVulnerabilities {

    // Test 1: Hardcoded credentials
    fun authenticate(username: String, password: String): Boolean {
        // VULNERABLE: Hardcoded credentials
        return username == "admin" && password == "admin123"
    }

    // Test 2: MD5 password hashing
    fun hashPasswordMd5(password: String): String {
        // VULNERABLE: MD5 is cryptographically broken
        val md = MessageDigest.getInstance("MD5")
        val digest = md.digest(password.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    // Test 3: SHA1 without salt
    fun hashPasswordSha1(password: String): String {
        // VULNERABLE: Unsalted SHA1
        val md = MessageDigest.getInstance("SHA-1")
        val digest = md.digest(password.toByteArray())
        return digest.joinToString("") { "%02x".format(it) }
    }

    // Test 4: Password in logs
    fun loginWithLogging(username: String, password: String): Boolean {
        // VULNERABLE: Password logged
        println("Login attempt: $username / $password")
        return authenticate(username, password)
    }

    // Test 5: Timing attack vulnerable comparison
    fun verifyPassword(input: String, stored: String): Boolean {
        // VULNERABLE: Non-constant time comparison
        return input == stored
    }

    // Test 6: Weak password requirements
    fun validatePassword(password: String): Boolean {
        // VULNERABLE: Too weak requirements
        return password.length >= 4
    }

    // Test 7: Predictable session token
    fun generateSessionToken(userId: Int): String {
        // VULNERABLE: Predictable token
        val timestamp = System.currentTimeMillis()
        return "$userId-$timestamp"
    }

    // Test 8: No account lockout
    private val failedAttempts = mutableMapOf<String, Int>()

    fun login(username: String, password: String): Boolean {
        // VULNERABLE: No lockout after failed attempts
        return checkCredentials(username, password)
    }

    // Test 9: Password stored in plaintext
    fun storePassword(userId: Int, password: String) {
        // VULNERABLE: Plaintext storage
        database.save("user_$userId", password)
    }

    // Test 10: Weak PBKDF2 iterations
    fun hashPasswordPbkdf2(password: String, salt: ByteArray): ByteArray {
        // VULNERABLE: Too few iterations
        val spec = PBEKeySpec(password.toCharArray(), salt, 100, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }

    // Test 11: JWT with weak secret
    fun createJwt(userId: Int): String {
        // VULNERABLE: Weak signing secret
        val secret = "secret"
        val header = Base64.getEncoder().encodeToString("""{"alg":"HS256","typ":"JWT"}""".toByteArray())
        val payload = Base64.getEncoder().encodeToString("""{"userId":$userId}""".toByteArray())
        return "$header.$payload.signature"
    }

    // Test 12: Remember me with weak token
    fun generateRememberToken(userId: Int): String {
        // VULNERABLE: Predictable remember me token
        return Base64.getEncoder().encodeToString("$userId:${System.currentTimeMillis()}".toByteArray())
    }

    // Test 13: Password reset token weak
    fun generateResetToken(email: String): String {
        // VULNERABLE: Predictable reset token
        return email.hashCode().toString() + System.currentTimeMillis()
    }

    private fun checkCredentials(username: String, password: String): Boolean = false
    private val database = object {
        fun save(key: String, value: String) {}
    }
}
