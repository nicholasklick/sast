<?php
// Weak Cryptography vulnerabilities in PHP

class WeakCryptoVulnerabilities {
    public function hashMd5($input) {
        // VULNERABLE: MD5 is cryptographically broken
        return md5($input);
    }

    public function hashSha1($input) {
        // VULNERABLE: SHA1 is deprecated
        return sha1($input);
    }

    public function encryptDes($data, $key) {
        // VULNERABLE: DES is obsolete
        return openssl_encrypt($data, 'DES-ECB', $key);
    }

    public function generateToken() {
        // VULNERABLE: Non-cryptographic random
        return rand(0, 1000000);
    }

    public function weakSessionId() {
        // VULNERABLE: Predictable session ID
        return time();
    }

    public function ecbEncryption($data, $key) {
        // VULNERABLE: ECB mode
        return openssl_encrypt($data, 'AES-128-ECB', $key);
    }

    public function weakRandom() {
        // VULNERABLE: mt_rand is not cryptographically secure
        return mt_rand();
    }

    public function insecureHash($password) {
        // VULNERABLE: Unsalted hash
        return hash('sha256', $password);
    }
}
