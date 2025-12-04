// Hardcoded Secrets vulnerabilities in Swift
import Foundation

class HardcodedSecretsVulnerabilities {
    // VULNERABLE: Hardcoded API key
    let apiKey = "sk_live_swift1234567890"

    // VULNERABLE: Hardcoded password
    let dbPassword = "super_secret_password"

    // VULNERABLE: Hardcoded AWS credentials
    let awsAccessKey = "AKIAIOSFODNN7EXAMPLE"
    let awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

    func getConnectionString() -> String {
        // VULNERABLE: Hardcoded connection string
        return "mysql://admin:password123@localhost:3306/myapp"
    }

    func getJwtSecret() -> String {
        // VULNERABLE: Hardcoded JWT secret
        return "my_super_secret_jwt_key_swift"
    }

    func authenticate(username: String, password: String) -> Bool {
        // VULNERABLE: Hardcoded backdoor
        if password == "backdoor_swift_123" {
            return true
        }
        return false
    }

    func getEncryptionKey() -> Data {
        // VULNERABLE: Hardcoded encryption key
        return Data([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    }
}
