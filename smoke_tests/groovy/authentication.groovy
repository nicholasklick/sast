// Authentication vulnerabilities in Groovy
package com.example.security

import java.security.MessageDigest
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

class AuthenticationVulnerabilities {

    // Test 1: Hardcoded credentials
    boolean authenticate(String username, String password) {
        // VULNERABLE: Hardcoded credentials
        username == "admin" && password == "admin123"
    }

    // Test 2: MD5 password hashing
    String hashPasswordMd5(String password) {
        // VULNERABLE: MD5 is cryptographically broken
        def md = MessageDigest.getInstance("MD5")
        def digest = md.digest(password.bytes)
        digest.collect { String.format("%02x", it) }.join()
    }

    // Test 3: SHA1 without salt
    String hashPasswordSha1(String password) {
        // VULNERABLE: Unsalted SHA1
        def md = MessageDigest.getInstance("SHA-1")
        def digest = md.digest(password.bytes)
        digest.collect { String.format("%02x", it) }.join()
    }

    // Test 4: Password in logs
    boolean loginWithLogging(String username, String password) {
        // VULNERABLE: Password logged
        println "Login attempt: ${username} / ${password}"
        authenticate(username, password)
    }

    // Test 5: Timing attack vulnerable comparison
    boolean verifyPassword(String input, String stored) {
        // VULNERABLE: Non-constant time comparison
        input == stored
    }

    // Test 6: Weak password requirements
    boolean validatePassword(String password) {
        // VULNERABLE: Too weak requirements
        password.length() >= 4
    }

    // Test 7: Predictable session token
    String generateSessionToken(int userId) {
        // VULNERABLE: Predictable token
        def timestamp = System.currentTimeMillis()
        "${userId}-${timestamp}"
    }

    // Test 8: Weak PBKDF2 iterations
    byte[] hashPasswordPbkdf2(String password, byte[] salt) {
        // VULNERABLE: Too few iterations
        def spec = new PBEKeySpec(password.toCharArray(), salt, 100, 256)
        def factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        factory.generateSecret(spec).encoded
    }

    // Test 9: JWT with weak secret
    String createJwt(int userId) {
        // VULNERABLE: Weak signing secret
        def secret = "secret"
        def header = '{"alg":"HS256","typ":"JWT"}'.bytes.encodeBase64().toString()
        def payload = """{"userId":${userId}}""".bytes.encodeBase64().toString()
        "${header}.${payload}.signature"
    }

    // Test 10: Remember me with weak token
    String generateRememberToken(int userId) {
        // VULNERABLE: Predictable remember me token
        "${userId}:${System.currentTimeMillis()}".bytes.encodeBase64().toString()
    }

    // Test 11: No account lockout
    boolean login(String username, String password) {
        // VULNERABLE: No failed attempt tracking
        checkCredentials(username, password)
    }

    // Test 12: Password stored in plaintext
    void storePassword(int userId, String password) {
        // VULNERABLE: Plaintext storage
        database.save("user_${userId}", password)
    }

    // Test 13: Password reset token weak
    String generateResetToken(String email) {
        // VULNERABLE: Predictable reset token
        email.hashCode().toString() + System.currentTimeMillis()
    }

    private boolean checkCredentials(String username, String password) { false }
    private def database = [save: { k, v -> }]
}
