// Hardcoded Cryptographic Key Test Cases

import * as crypto from 'crypto';

// Test 1: Hardcoded AES encryption key
function encryptDataWithHardcodedKey(data: string): string {
    // VULNERABLE: Hardcoded encryption key
    const key = Buffer.from('0123456789abcdef0123456789abcdef', 'hex');
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Test 2: Hardcoded JWT secret
function generateJWT(payload: any): string {
    const jwt = require('jsonwebtoken');
    // VULNERABLE: Hardcoded JWT secret
    const secret = 'my-super-secret-jwt-key-12345';
    return jwt.sign(payload, secret);
}

// Test 3: Hardcoded HMAC key
function createSignature(message: string): string {
    // VULNERABLE: Hardcoded HMAC key
    const secretKey = 'hardcoded-hmac-secret-key';
    return crypto.createHmac('sha256', secretKey).update(message).digest('hex');
}

// Test 4: Hardcoded encryption password
function encryptWithPassword(plaintext: string): string {
    // VULNERABLE: Hardcoded password for encryption
    const password = 'myEncryptionPassword123!';
    const key = crypto.scryptSync(password, 'salt', 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// Test 5: Hardcoded API encryption key
const API_ENCRYPTION_KEY = 'a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6'; // VULNERABLE: Hardcoded

function encryptAPIPayload(payload: any): string {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(API_ENCRYPTION_KEY, 'utf8').slice(0, 32), iv);
    return cipher.update(JSON.stringify(payload), 'utf8', 'hex') + cipher.final('hex');
}
