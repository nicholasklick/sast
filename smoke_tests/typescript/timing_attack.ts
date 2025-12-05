// Timing Attack Test Cases

import * as crypto from 'crypto';

// Test 1: String comparison for authentication
function authenticateWithStringComparison(providedToken: string, validToken: string): boolean {
    // VULNERABLE: Early return on mismatch reveals information via timing
    if (providedToken.length !== validToken.length) {
        return false;
    }
    for (let i = 0; i < providedToken.length; i++) {
        if (providedToken[i] !== validToken[i]) {
            return false;
        }
    }
    return true;
}

// Test 2: Password comparison using ===
function checkPassword(inputPassword: string, storedPassword: string): boolean {
    // VULNERABLE: Direct string comparison is timing-unsafe
    return inputPassword === storedPassword;
}

// Test 3: API key validation
function validateAPIKey(providedKey: string, validKey: string): boolean {
    // VULNERABLE: Character-by-character comparison leaks timing info
    if (providedKey.length !== validKey.length) return false;

    let matches = true;
    for (let i = 0; i < validKey.length; i++) {
        if (providedKey.charCodeAt(i) !== validKey.charCodeAt(i)) {
            matches = false;
            break; // Early exit reveals position of mismatch
        }
    }
    return matches;
}

// Test 4: Token verification with ==
function verifyToken(userToken: string, serverToken: string): boolean {
    // VULNERABLE: Equality operator is not constant-time
    return userToken == serverToken;
}

// Test 5: HMAC comparison without constant-time
function verifyHMAC(message: string, providedHMAC: string, key: string): boolean {
    const expectedHMAC = crypto.createHmac('sha256', key).update(message).digest('hex');
    // VULNERABLE: Direct comparison of HMAC values
    return providedHMAC === expectedHMAC;
}
