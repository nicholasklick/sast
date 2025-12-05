// Insecure TLS Test Cases

import * as https from 'https';
import * as tls from 'tls';

// Test 1: Disabling certificate validation
function makeInsecureRequest(url: string): void {
    // VULNERABLE: Certificate validation disabled
    const options = {
        rejectUnauthorized: false
    };
    https.get(url, options, (res) => {
        console.log('Response received');
    });
}

// Test 2: Accepting self-signed certificates globally
function disableGlobalCertValidation(): void {
    // VULNERABLE: Globally disabling certificate validation
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
}

// Test 3: Using outdated TLS version
function createInsecureTLSServer(): void {
    const options = {
        // VULNERABLE: TLS 1.0 is deprecated and insecure
        minVersion: 'TLSv1' as any,
        maxVersion: 'TLSv1' as any
    };
    tls.createServer(options, (socket) => {
        socket.write('Hello');
    });
}

// Test 4: Weak cipher suites
function createServerWithWeakCiphers(): void {
    const options = {
        // VULNERABLE: Including weak cipher suites
        ciphers: 'DES-CBC3-SHA:RC4-SHA:AES128-SHA'
    };
    https.createServer(options, (req, res) => {
        res.end('Hello');
    });
}

// Test 5: Custom checkServerIdentity that accepts all
function makeRequestWithoutHostnameValidation(url: string): void {
    const options = {
        // VULNERABLE: Bypassing hostname validation
        checkServerIdentity: () => undefined
    };
    https.get(url, options, (res) => {
        console.log('Connected');
    });
}
