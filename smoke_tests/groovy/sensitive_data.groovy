// Sensitive Data Exposure vulnerabilities in Groovy
package com.example.security

class SensitiveDataExposure {

    // Test 1: Hardcoded API key
    void makeApiCall() {
        // VULNERABLE: Hardcoded API key
        def apiKey = "sk-live-abcd1234567890xyz"
        // Use API key
    }

    // Test 2: Hardcoded database credentials
    void connectToDatabase() {
        // VULNERABLE: Hardcoded credentials
        def username = "admin"
        def password = "SuperSecret123!"
        def connectionString = "jdbc:mysql://db.example.com/production?user=${username}&password=${password}"
    }

    // Test 3: Private key in code
    void signData(byte[] data) {
        // VULNERABLE: Private key embedded
        def privateKey = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----"""
    }

    // Test 4: Sensitive data in URL
    void fetchUserData(String userId, String ssn) {
        // VULNERABLE: SSN in URL
        def url = "https://api.example.com/user/${userId}?ssn=${ssn}"
    }

    // Test 5: Credit card in logs
    void processPayment(String cardNumber, String cvv) {
        // VULNERABLE: Card data logged
        println "Processing card: ${cardNumber}"
    }

    // Test 6: PII stored unencrypted
    void storePii(String ssn, String dob) {
        // VULNERABLE: Plaintext storage
        new File("user_data.txt").text = "ssn=${ssn}\ndob=${dob}"
    }

    // Test 7: Password in error message
    void validateCredentials(String username, String password) {
        // VULNERABLE: Password in error
        if (!isValidPassword(password)) {
            throw new IllegalArgumentException("Invalid password: ${password}")
        }
    }

    // Test 8: AWS credentials
    void configureAws() {
        // VULNERABLE: AWS credentials in code
        def accessKey = "AKIAIOSFODNN7EXAMPLE"
        def secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }

    // Test 9: Session token in response
    Map handleAuthResponse() {
        def token = generateToken()
        def refreshToken = generateRefreshToken()
        // VULNERABLE: Exposing all tokens
        [
            access_token: token,
            refresh_token: refreshToken,
            internal_id: "internal-123"
        ]
    }

    // Test 10: Encryption key hardcoded
    byte[] encryptData(byte[] data) {
        // VULNERABLE: Hardcoded encryption key
        def key = "MySecretEncryptionKey123"
        encrypt(data, key)
    }

    // Test 11: Database connection string
    String getConnectionString() {
        // VULNERABLE: Full connection string with password
        "Server=db.example.com;Database=prod;User Id=admin;Password=P@ssw0rd123;"
    }

    // Test 12: OAuth client secret
    Map getOAuthConfig() {
        // VULNERABLE: Client secret in code
        [
            client_id: "app-client-id",
            client_secret: "super-secret-oauth-client-secret"
        ]
    }

    // Test 13: Cookie without secure flag
    String setSessionCookie(String token) {
        // VULNERABLE: Missing Secure flag
        "session=${token}; Path=/; HttpOnly"
    }

    private boolean isValidPassword(String password) { true }
    private String generateToken() { "token" }
    private String generateRefreshToken() { "refresh" }
    private byte[] encrypt(byte[] data, String key) { data }
}
