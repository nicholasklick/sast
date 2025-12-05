// Insecure Randomness vulnerabilities in Swift
import Foundation
import Security

class InsecureRandom {

    // Test 1: arc4random for security token (older systems)
    func generateTokenArc4() -> String {
        // VULNERABLE: arc4random may not be crypto-secure on all platforms
        var token = ""
        for _ in 0..<32 {
            token += String(format: "%02x", arc4random_uniform(256))
        }
        return token
    }

    // Test 2: drand48 for security purposes
    func generateTokenDrand48() -> Double {
        // VULNERABLE: drand48 is not cryptographically secure
        srand48(Int(Date().timeIntervalSince1970))
        return drand48()
    }

    // Test 3: random() for security
    func generateWeakRandom() -> Int {
        // VULNERABLE: random() is predictable
        srandom(UInt32(time(nil)))
        return random()
    }

    // Test 4: Time-based seed
    func generateTimeSeeded() -> UInt32 {
        // VULNERABLE: Time-based seed is predictable
        srand(UInt32(time(nil)))
        return UInt32(rand())
    }

    // Test 5: UUID for secrets
    func generateUUIDToken() -> String {
        // VULNERABLE: UUID v4 may not be crypto random on all implementations
        return UUID().uuidString
    }

    // Test 6: Int.random for crypto
    func generateIntRandom() -> Int {
        // Note: Swift's Int.random uses a secure generator, but pattern is risky
        // VULNERABLE: Depending on usage context
        return Int.random(in: 0..<1000000)
    }

    // Test 7: Array shuffling for security
    func shuffleForSecurity<T>(array: [T]) -> [T] {
        // VULNERABLE: shuffle() may not use crypto random on all platforms
        var mutableArray = array
        mutableArray.shuffle()
        return mutableArray
    }

    // Test 8: rand() from C library
    func cRand() -> Int32 {
        // VULNERABLE: C rand() is not secure
        return rand()
    }

    // Test 9: Predictable session ID
    func generateSessionId(userId: Int) -> String {
        // VULNERABLE: Predictable session ID
        let timestamp = Int(Date().timeIntervalSince1970)
        return "\(userId)-\(timestamp)"
    }

    // Test 10: Weak OTP generation
    func generateOTP() -> String {
        // VULNERABLE: Using non-crypto random for OTP
        let otp = arc4random_uniform(1000000)
        return String(format: "%06d", otp)
    }

    // Test 11: Password generation with weak random
    func generatePassword(length: Int) -> String {
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        var password = ""
        // VULNERABLE: Not guaranteed crypto-secure on all platforms
        for _ in 0..<length {
            let index = Int(arc4random_uniform(UInt32(chars.count)))
            password += String(chars[chars.index(chars.startIndex, offsetBy: index)])
        }
        return password
    }

    // Test 12: IV generation with weak random
    func generateIV() -> Data {
        // VULNERABLE: IV should use SecRandomCopyBytes
        var iv = Data(count: 16)
        for i in 0..<16 {
            iv[i] = UInt8(arc4random_uniform(256))
        }
        return iv
    }

    // Test 13: Salt generation with weak random
    func generateSalt() -> Data {
        // VULNERABLE: Salt should use crypto random
        var salt = Data(count: 32)
        for i in 0..<32 {
            salt[i] = UInt8(arc4random_uniform(256))
        }
        return salt
    }

    // Secure alternative (for reference):
    func secureRandom(count: Int) -> Data? {
        var bytes = [UInt8](repeating: 0, count: count)
        let status = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return status == errSecSuccess ? Data(bytes) : nil
    }
}
