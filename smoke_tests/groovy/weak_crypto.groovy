// Weak Cryptography vulnerabilities in Groovy
package com.example.vulnerabilities

class WeakCryptoVulnerabilities {
    String hashMd5(String input) {
        // VULNERABLE: MD5 is cryptographically broken
        return java.security.MessageDigest.getInstance("MD5").digest(input.bytes).encodeHex().toString()
    }

    String hashSha1(String input) {
        // VULNERABLE: SHA1 is deprecated
        return java.security.MessageDigest.getInstance("SHA-1").digest(input.bytes).encodeHex().toString()
    }

    int generateToken() {
        // VULNERABLE: Non-cryptographic random
        return new Random().nextInt(1000000)
    }

    String weakSessionId() {
        // VULNERABLE: Predictable session ID
        return System.currentTimeMillis().toString()
    }

    int weakRandom() {
        // VULNERABLE: Math.random is not secure
        return Math.random() * 1000000
    }
}
