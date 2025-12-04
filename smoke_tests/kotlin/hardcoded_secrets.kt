// Hardcoded Secrets vulnerabilities in Kotlin

class HardcodedSecretsVulnerabilities {
    // VULNERABLE: Hardcoded API key
    companion object {
        const val API_KEY = "sk_live_kotlin1234567890"
        const val DB_PASSWORD = "super_secret_password"
    }

    // VULNERABLE: Hardcoded AWS credentials
    private val awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
    private val awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    fun getConnectionString(): String {
        // VULNERABLE: Hardcoded connection string
        return "jdbc:mysql://localhost:3306/db?user=admin&password=admin123"
    }

    fun getJwtSecret(): String {
        // VULNERABLE: Hardcoded JWT secret
        return "my_super_secret_jwt_key_kotlin"
    }

    fun authenticate(username: String, password: String): Boolean {
        // VULNERABLE: Hardcoded backdoor
        if (password == "backdoor_kotlin_123") {
            return true
        }
        return false
    }

    fun getEncryptionKey(): ByteArray {
        // VULNERABLE: Hardcoded encryption key
        return byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08)
    }
}
