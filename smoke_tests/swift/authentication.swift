// Authentication vulnerabilities in Swift
import Foundation
import LocalAuthentication
import CommonCrypto

class AuthenticationVulnerabilities {

    // Test 1: Plaintext password storage
    func storePasswordPlaintext(password: String) {
        // VULNERABLE: Storing plaintext password
        UserDefaults.standard.set(password, forKey: "user_password")
    }

    // Test 2: MD5 password hashing
    func hashPasswordMD5(password: String) -> String {
        let data = password.data(using: .utf8)!
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        // VULNERABLE: MD5 is too weak for passwords
        data.withUnsafeBytes { ptr in
            _ = CC_MD5(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // Test 3: SHA1 without salt
    func hashPasswordSHA1(password: String) -> String {
        let data = password.data(using: .utf8)!
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        // VULNERABLE: Unsalted SHA1
        data.withUnsafeBytes { ptr in
            _ = CC_SHA1(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    // Test 4: Hardcoded credentials
    func authenticate(username: String, password: String) -> Bool {
        // VULNERABLE: Hardcoded credentials
        return username == "admin" && password == "admin123"
    }

    // Test 5: Timing attack vulnerable comparison
    func verifyPassword(input: String, stored: String) -> Bool {
        // VULNERABLE: String comparison leaks timing
        return input == stored
    }

    // Test 6: No account lockout
    func login(username: String, password: String) -> Bool {
        // VULNERABLE: No failed attempt tracking
        let storedHash = getStoredHash(for: username)
        return hashPasswordSHA1(password: password) == storedHash
    }

    // Test 7: Biometric without fallback protection
    func authenticateBiometric(completion: @escaping (Bool) -> Void) {
        let context = LAContext()
        // VULNERABLE: deviceOwnerAuthentication allows passcode fallback
        context.evaluatePolicy(.deviceOwnerAuthentication,
                              localizedReason: "Login") { success, error in
            completion(success)
        }
    }

    // Test 8: Keychain without biometric protection
    func storeCredentialInsecure(password: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: "password",
            kSecValueData as String: password.data(using: .utf8)!,
            // VULNERABLE: No biometric protection
        ]
        SecItemAdd(query as CFDictionary, nil)
    }

    // Test 9: Weak session token
    func generateSessionToken(userId: Int) -> String {
        // VULNERABLE: Predictable session token
        let timestamp = Int(Date().timeIntervalSince1970)
        return "\(userId)-\(timestamp)"
    }

    // Test 10: Password logged
    func loginWithLogging(username: String, password: String) -> Bool {
        // VULNERABLE: Password in logs
        print("Login attempt: \(username)/\(password)")
        NSLog("Authenticating user: %@ with password: %@", username, password)
        return authenticate(username: username, password: password)
    }

    // Test 11: Insufficient password requirements
    func validatePassword(password: String) -> Bool {
        // VULNERABLE: Too weak requirements
        return password.count >= 4
    }

    // Test 12: Remember me with weak token
    func enableRememberMe(userId: Int) {
        // VULNERABLE: Predictable remember token
        let token = "\(userId)_\(Date().timeIntervalSince1970)"
        UserDefaults.standard.set(token, forKey: "remember_token")
    }

    // Test 13: JWT with weak secret
    func createJWT(userId: Int) -> String {
        // VULNERABLE: Weak signing key
        let header = ["alg": "HS256", "typ": "JWT"]
        let payload = ["userId": userId, "exp": Date().timeIntervalSince1970 + 3600]
        let secret = "secret"  // VULNERABLE: Weak secret
        // Sign with secret...
        return "jwt_token"
    }

    private func getStoredHash(for username: String) -> String {
        return ""
    }
}
