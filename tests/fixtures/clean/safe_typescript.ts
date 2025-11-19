// Clean TypeScript code with no vulnerabilities
import * as crypto from 'crypto';
import * as path from 'path';
import { Pool } from 'pg';

class SafeTypeScriptCode {

    // 1. Safe SQL Query - Parameterized
    async getUserById(pool: Pool, userId: number): Promise<string | null> {
        const query = 'SELECT * FROM users WHERE id = $1';
        const result = await pool.query(query, [userId]);
        return result.rows.length > 0 ? result.rows[0].name : null;
    }

    // 2. Safe File Access - Path validation
    readFile(filename: string): string {
        const basePath = path.resolve('/var/data');
        const filePath = path.resolve(path.join(basePath, filename));

        if (!filePath.startsWith(basePath)) {
            throw new Error('Path traversal detected');
        }

        const fs = require('fs');
        return fs.readFileSync(filePath, 'utf8');
    }

    // 3. Safe Configuration
    getApiKey(): string {
        const apiKey = process.env.API_KEY;
        if (!apiKey) {
            throw new Error('API_KEY not set');
        }
        return apiKey;
    }

    // 4. Safe Cryptography - AES-256-GCM
    encryptData(data: string, key: Buffer): string {
        const algorithm = 'aes-256-gcm';
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipheriv(algorithm, key, iv);

        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const authTag = cipher.getAuthTag();

        return JSON.stringify({
            iv: iv.toString('hex'),
            authTag: authTag.toString('hex'),
            encrypted: encrypted
        });
    }

    // 5. Safe Hashing - SHA-256
    hashPassword(password: string): string {
        return crypto.createHash('sha256').update(password).digest('hex');
    }

    // 6. Safe Random Generation
    generateSecureToken(): string {
        return crypto.randomBytes(32).toString('hex');
    }

    // 7. Safe Command Execution - Array form
    listFiles(directory: string): string {
        const allowedDirs = ['/tmp', '/var/log'];
        if (!allowedDirs.includes(directory)) {
            throw new Error('Directory not allowed');
        }

        const { execFileSync } = require('child_process');
        return execFileSync('ls', ['-la', directory], { encoding: 'utf8' });
    }

    // 8. Safe Output - HTML escaping
    displayUserInput(userInput: string): string {
        return userInput
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    }

    // 9. Safe Input Validation
    validateAndSanitize(input: string): string {
        return input.replace(/[^a-zA-Z0-9_-]/g, '');
    }

    // 10. Safe URL Fetching - Whitelist validation
    async fetchUrl(url: string): Promise<string> {
        const allowedHosts = ['api.example.com', 'data.example.com'];
        const parsedUrl = new URL(url);

        if (!allowedHosts.includes(parsedUrl.hostname)) {
            throw new Error('Host not allowed');
        }

        const https = require('https');
        return new Promise((resolve, reject) => {
            https.get(url, {
                rejectUnauthorized: true  // Verify SSL certificates
            }, (res: any) => {
                let data = '';
                res.on('data', (chunk: string) => data += chunk);
                res.on('end', () => resolve(data));
            }).on('error', reject);
        });
    }

    // 11. Safe Type Checking - Strict comparison
    strictTypeCheck(value: any): boolean {
        return value === "0";
    }

    // 12. Safe Array Access
    safeArrayAccess<T>(array: T[], index: number): T | null {
        return index >= 0 && index < array.length ? array[index] : null;
    }

    // 13. Safe JSON Parsing
    safeJsonParse(jsonString: string): any {
        try {
            return JSON.parse(jsonString);
        } catch (e) {
            throw new Error('Invalid JSON');
        }
    }

    // 14. Safe RegExp - No ReDoS vulnerability
    safePatternMatch(input: string): boolean {
        // Using simple, non-backtracking pattern
        return /^[a-zA-Z0-9]+$/.test(input);
    }

    // 15. Safe Cookie Handling
    setSecureCookie(response: any, name: string, value: string): void {
        response.cookie(name, value, {
            httpOnly: true,
            secure: true,
            sameSite: 'strict',
            maxAge: 3600000
        });
    }

    // 16. Safe JWT Validation
    validateJwt(token: string, secret: string): any {
        const jwt = require('jsonwebtoken');
        try {
            return jwt.verify(token, secret, {
                algorithms: ['HS256'],
                maxAge: '1h'
            });
        } catch (e) {
            throw new Error('Invalid token');
        }
    }

    // 17. Safe Database Connection
    createSecurePool(): Pool {
        return new Pool({
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            host: process.env.DB_HOST,
            database: process.env.DB_NAME,
            port: parseInt(process.env.DB_PORT || '5432'),
            ssl: {
                rejectUnauthorized: true
            }
        });
    }
}

export default SafeTypeScriptCode;
