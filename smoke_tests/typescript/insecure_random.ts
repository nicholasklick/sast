// Insecure Random Test Cases

// Test 1: Math.random() for security token
function generateSessionToken(): string {
    // VULNERABLE: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// Test 2: Math.random() for password reset token
function createPasswordResetToken(userId: string): string {
    const randomPart = Math.random().toString(36);
    // VULNERABLE: Predictable random number generation
    return `${userId}-${randomPart}-${Date.now()}`;
}

// Test 3: Math.random() for CSRF token
function generateCSRFToken(): string {
    // VULNERABLE: Math.random() can be predicted
    return Math.random().toString(16).slice(2) + Math.random().toString(16).slice(2);
}

// Test 4: Date-based random for security
function generateAPIKey(): string {
    const timestamp = Date.now();
    const random = Math.floor(Math.random() * 1000000);
    // VULNERABLE: Predictable combination
    return `${timestamp}-${random}`;
}

// Test 5: Simple random for encryption key
function generateEncryptionKey(): Buffer {
    const key = Buffer.alloc(32);
    for (let i = 0; i < key.length; i++) {
        // VULNERABLE: Using Math.random() for cryptographic key
        key[i] = Math.floor(Math.random() * 256);
    }
    return key;
}
