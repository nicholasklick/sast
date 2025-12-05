// Sensitive Data Exposure vulnerabilities in Swift
import Foundation

class SensitiveDataExposure {

    // Test 1: Hardcoded API key
    func makeApiCall() {
        // VULNERABLE: Hardcoded API key
        let apiKey = "sk-live-abcd1234567890xyz"
        var request = URLRequest(url: URL(string: "https://api.example.com")!)
        request.setValue(apiKey, forHTTPHeaderField: "Authorization")
    }

    // Test 2: Credentials in source code
    func connectToDatabase() {
        // VULNERABLE: Hardcoded credentials
        let username = "admin"
        let password = "SuperSecret123!"
        let connectionString = "mysql://\(username):\(password)@db.example.com/production"
    }

    // Test 3: Private key in code
    func signData(data: Data) {
        // VULNERABLE: Private key embedded
        let privateKey = """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
        -----END RSA PRIVATE KEY-----
        """
    }

    // Test 4: Sensitive data in URL
    func fetchUserData(userId: String, ssn: String) {
        // VULNERABLE: SSN in URL
        let url = URL(string: "https://api.example.com/user/\(userId)?ssn=\(ssn)")!
        URLSession.shared.dataTask(with: url).resume()
    }

    // Test 5: Credit card in logs
    func processPayment(cardNumber: String, cvv: String) {
        // VULNERABLE: Card data logged
        print("Processing card: \(cardNumber)")
        NSLog("CVV: %@", cvv)
    }

    // Test 6: PII stored unencrypted
    func storePii(ssn: String, dob: String) {
        // VULNERABLE: Sensitive data in UserDefaults
        UserDefaults.standard.set(ssn, forKey: "user_ssn")
        UserDefaults.standard.set(dob, forKey: "user_dob")
    }

    // Test 7: Password in error message
    func validateCredentials(username: String, password: String) throws {
        // VULNERABLE: Password in error
        if !isValidPassword(password) {
            throw NSError(domain: "Auth", code: 1,
                         userInfo: [NSLocalizedDescriptionKey: "Invalid password: \(password)"])
        }
    }

    // Test 8: Token exposure in response
    func handleAuthResponse() -> [String: Any] {
        let token = generateToken()
        let refreshToken = generateRefreshToken()
        // VULNERABLE: Exposing all tokens
        return [
            "access_token": token,
            "refresh_token": refreshToken,
            "token_type": "Bearer"
        ]
    }

    // Test 9: Health data without encryption
    func storeHealthRecord(data: HealthRecord) {
        // VULNERABLE: Health data stored plaintext
        let encoder = JSONEncoder()
        if let encoded = try? encoder.encode(data) {
            try? encoded.write(to: URL(fileURLWithPath: "/data/health.json"))
        }
    }

    // Test 10: Biometric template stored insecurely
    func storeBiometricTemplate(template: Data) {
        // VULNERABLE: Biometric data in plaintext
        UserDefaults.standard.set(template, forKey: "biometric_template")
    }

    // Test 11: Session token in cookie without secure flag
    func setSessionCookie(token: String) -> String {
        // VULNERABLE: Missing Secure and HttpOnly flags
        return "session=\(token); Path=/"
    }

    // Test 12: AWS credentials
    func configureAws() {
        // VULNERABLE: AWS credentials in code
        let accessKey = "AKIAIOSFODNN7EXAMPLE"
        let secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    }

    // Test 13: Encryption key hardcoded
    func encryptData(data: Data) -> Data? {
        // VULNERABLE: Hardcoded encryption key
        let key = "MySecretEncryptionKey123"
        return encrypt(data: data, key: key)
    }

    // Test 14: Backup with sensitive data
    func backupUserData() {
        let userData = [
            "email": "user@example.com",
            "password": "userPassword123",  // VULNERABLE
            "creditCard": "4111111111111111"  // VULNERABLE
        ]
        // Backup to iCloud
    }

    private func isValidPassword(_ password: String) -> Bool { true }
    private func generateToken() -> String { "token" }
    private func generateRefreshToken() -> String { "refresh" }
    private func encrypt(data: Data, key: String) -> Data? { nil }
}

struct HealthRecord: Codable {
    var patientId: String
    var diagnosis: String
    var medications: [String]
}
