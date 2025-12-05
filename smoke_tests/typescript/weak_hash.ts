// Weak Hash (MD5/SHA1) Test Cases

import * as crypto from 'crypto';

// Test 1: MD5 hash usage
function hashPasswordMD5(password: string): string {
    // VULNERABLE: MD5 is cryptographically broken
    return crypto.createHash('md5').update(password).digest('hex');
}

// Test 2: SHA1 hash usage
function hashPasswordSHA1(password: string): string {
    // VULNERABLE: SHA1 is cryptographically weak
    return crypto.createHash('sha1').update(password).digest('hex');
}

// Test 3: MD5 for file integrity
function calculateFileChecksumMD5(data: Buffer): string {
    // VULNERABLE: MD5 should not be used for security purposes
    const hash = crypto.createHash('md5');
    hash.update(data);
    return hash.digest('hex');
}

// Test 4: SHA1 for token generation
function generateTokenSHA1(userId: string): string {
    const timestamp = Date.now().toString();
    // VULNERABLE: SHA1 is not suitable for security tokens
    return crypto.createHash('sha1').update(userId + timestamp).digest('hex');
}

// Test 5: MD5 in HMAC (still weak)
function createHMACMD5(data: string, key: string): string {
    // VULNERABLE: Even in HMAC, MD5 is not recommended
    return crypto.createHmac('md5', key).update(data).digest('hex');
}
