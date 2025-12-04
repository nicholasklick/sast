// Weak Cryptography vulnerabilities in Swift
import Foundation
import CommonCrypto

class WeakCryptoVulnerabilities {
    func hashMd5(input: String) -> String {
        // VULNERABLE: MD5 is cryptographically broken
        let data = input.data(using: .utf8)!
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_MD5($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    func hashSha1(input: String) -> String {
        // VULNERABLE: SHA1 is deprecated
        let data = input.data(using: .utf8)!
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA1($0.baseAddress, CC_LONG(data.count), &digest)
        }
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    func generateToken() -> Int {
        // VULNERABLE: Non-cryptographic random
        return Int.random(in: 0..<1000000)
    }

    func weakSessionId() -> String {
        // VULNERABLE: Predictable session ID
        return String(Date().timeIntervalSince1970)
    }

    func weakRandom() -> UInt32 {
        // VULNERABLE: arc4random without bounds
        return arc4random()
    }
}
