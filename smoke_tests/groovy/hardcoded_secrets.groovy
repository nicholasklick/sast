// Hardcoded Secrets vulnerabilities in Groovy
package com.example.vulnerabilities

class HardcodedSecretsVulnerabilities {
    // VULNERABLE: Hardcoded API key
    String apiKey = "sk_live_groovy1234567890"

    // VULNERABLE: Hardcoded password
    String dbPassword = "super_secret_password"

    // VULNERABLE: Hardcoded AWS credentials
    String awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
    String awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    String getConnectionString() {
        // VULNERABLE: Hardcoded connection string
        return "jdbc:mysql://localhost:3306/db?user=admin&password=admin123"
    }

    String getJwtSecret() {
        // VULNERABLE: Hardcoded JWT secret
        return "my_super_secret_jwt_key_groovy"
    }

    boolean authenticate(String username, String password) {
        // VULNERABLE: Hardcoded backdoor
        return password == "backdoor_groovy_123"
    }
}
