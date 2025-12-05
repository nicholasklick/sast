// Weak Cipher (DES/RC4/ECB) Test Cases

import * as crypto from 'crypto';

// Test 1: DES encryption
function encryptWithDES(data: string, key: Buffer): string {
    // VULNERABLE: DES is obsolete and insecure
    const cipher = crypto.createCipheriv('des', key, Buffer.alloc(8));
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Test 2: 3DES encryption
function encryptWith3DES(data: string, key: Buffer): string {
    // VULNERABLE: 3DES is deprecated and slow
    const cipher = crypto.createCipheriv('des-ede3', key, Buffer.alloc(8));
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Test 3: RC4 encryption
function encryptWithRC4(data: string, key: Buffer): string {
    // VULNERABLE: RC4 has known vulnerabilities
    const cipher = crypto.createCipheriv('rc4', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Test 4: AES-ECB mode
function encryptWithECB(data: string, key: Buffer): string {
    // VULNERABLE: ECB mode is not semantically secure
    const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}

// Test 5: AES-256-ECB mode
function encryptWithAES256ECB(data: string, key: Buffer): string {
    // VULNERABLE: ECB mode leaks patterns even with AES-256
    const cipher = crypto.createCipheriv('aes-256-ecb', key, null);
    return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
}
