// Sensitive Data Exposure vulnerabilities in Kotlin
package com.example.security

import java.io.File
import java.util.Properties

class SensitiveDataExposure {

    // Test 1: Hardcoded API key
    fun makeApiCall() {
        // VULNERABLE: Hardcoded API key
        val apiKey = "sk-live-abcd1234567890xyz"
        // Use API key
    }

    // Test 2: Hardcoded database credentials
    fun connectToDatabase() {
        // VULNERABLE: Hardcoded credentials
        val username = "admin"
        val password = "SuperSecret123!"
        val connectionString = "jdbc:mysql://db.example.com/production?user=$username&password=$password"
    }

    // Test 3: Private key in code
    fun signData(data: ByteArray) {
        // VULNERABLE: Private key embedded
        val privateKey = """
            -----BEGIN RSA PRIVATE KEY-----
            MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
            -----END RSA PRIVATE KEY-----
        """.trimIndent()
    }

    // Test 4: Sensitive data in URL
    fun fetchUserData(userId: String, ssn: String) {
        // VULNERABLE: SSN in URL
        val url = "https://api.example.com/user/$userId?ssn=$ssn"
    }

    // Test 5: Credit card in logs
    fun processPayment(cardNumber: String, cvv: String) {
        // VULNERABLE: Card data logged
        println("Processing card: $cardNumber")
    }

    // Test 6: PII stored unencrypted
    fun storePii(ssn: String, dob: String) {
        // VULNERABLE: Plaintext storage
        val prefs = Properties()
        prefs.setProperty("user_ssn", ssn)
        prefs.setProperty("user_dob", dob)
        prefs.store(File("user.properties").outputStream(), null)
    }

    // Test 7: Password in error message
    fun validateCredentials(username: String, password: String) {
        // VULNERABLE: Password in error
        if (!isValidPassword(password)) {
            throw IllegalArgumentException("Invalid password: $password")
        }
    }

    // Test 8: AWS credentials
    fun configureAws() {
        // VULNERABLE: AWS credentials in code
        val accessKey = "AKIAIOSFODNN7EXAMPLE"
        val secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }

    // Test 9: Session token in response
    fun handleAuthResponse(): Map<String, String> {
        val token = generateToken()
        val refreshToken = generateRefreshToken()
        // VULNERABLE: Exposing all tokens
        return mapOf(
            "access_token" to token,
            "refresh_token" to refreshToken,
            "internal_id" to "internal-123"
        )
    }

    // Test 10: Encryption key hardcoded
    fun encryptData(data: ByteArray): ByteArray {
        // VULNERABLE: Hardcoded encryption key
        val key = "MySecretEncryptionKey123"
        return encrypt(data, key)
    }

    // Test 11: Database connection string
    fun getConnectionString(): String {
        // VULNERABLE: Full connection string with password
        return "Server=db.example.com;Database=prod;User Id=admin;Password=P@ssw0rd123;"
    }

    // Test 12: OAuth client secret
    fun getOAuthConfig(): Map<String, String> {
        // VULNERABLE: Client secret in code
        return mapOf(
            "client_id" to "app-client-id",
            "client_secret" to "super-secret-oauth-client-secret"
        )
    }

    // Test 13: Health data unencrypted
    fun saveHealthRecord(patientId: String, diagnosis: String) {
        // VULNERABLE: Health data in plaintext
        File("health_records/$patientId.txt").writeText(diagnosis)
    }

    // Test 14: Cookie without secure flag
    fun setSessionCookie(token: String): String {
        // VULNERABLE: Missing Secure flag
        return "session=$token; Path=/; HttpOnly"
    }

    private fun isValidPassword(password: String): Boolean = true
    private fun generateToken(): String = "token"
    private fun generateRefreshToken(): String = "refresh"
    private fun encrypt(data: ByteArray, key: String): ByteArray = data
}
