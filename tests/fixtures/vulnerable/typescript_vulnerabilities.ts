// TypeScript vulnerabilities test file
import * as crypto from 'crypto';
import { Pool } from 'pg';

class VulnerableTypeScriptCode {
    private apiKey = "sk-1234567890abcdef"; // Hardcoded secret

    // 1. SQL Injection - String concatenation
    async getUserByIdUnsafe(pool: Pool, userId: string): Promise<any> {
        const query = `SELECT * FROM users WHERE id = '${userId}'`;
        const result = await pool.query(query);
        return result.rows[0];
    }

    // 2. Command Injection
    executeCommand(userInput: string): string {
        const { execSync } = require('child_process');
        return execSync(`ls -la ${userInput}`).toString();
    }

    // 3. Path Traversal
    readUserFile(filename: string): string {
        const fs = require('fs');
        return fs.readFileSync(`/var/data/${filename}`, 'utf8');
    }

    // 4. Weak Cryptography - MD5
    hashWithMD5(data: string): string {
        return crypto.createHash('md5').update(data).digest('hex');
    }

    // 5. Insecure Random
    generateToken(): string {
        return Math.random().toString(36).substring(2);
    }

    // 6. eval() usage
    evaluateCode(code: string): any {
        return eval(code);
    }

    // 7. XSS - innerHTML
    displayUserContent(userHtml: string): void {
        document.getElementById('content')!.innerHTML = userHtml;
    }

    // 8. Insecure Deserialization
    deserializeData(jsonString: string): any {
        return JSON.parse(jsonString); // Without validation
    }

    // 9. SSRF - Unvalidated URL fetch
    async fetchUrl(url: string): Promise<string> {
        const response = await fetch(url);
        return response.text();
    }

    // 10. NoSQL Injection
    async findUser(username: string): Promise<any> {
        const mongo = require('mongodb');
        const db = await mongo.connect('mongodb://localhost');
        return db.collection('users').findOne({ username: username });
    }

    // 11. Insecure Cookie
    setCookie(name: string, value: string): void {
        document.cookie = `${name}=${value}`; // No httpOnly, no secure
    }

    // 12. Weak Crypto - DES
    encryptWithDES(data: string, key: Buffer): string {
        const cipher = crypto.createCipheriv('des', key, Buffer.alloc(8));
        return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
    }

    // 13. Hardcoded JWT Secret
    private jwtSecret = "my-secret-key";

    // 14. Disabled SSL Verification
    fetchWithoutSSLVerify(url: string): Promise<any> {
        const https = require('https');
        const agent = new https.Agent({ rejectUnauthorized: false });
        return fetch(url, { agent });
    }

    // 15. Type Coercion Bug
    compareValues(a: any, b: any): boolean {
        return a == b; // Should use ===
    }
}

export default VulnerableTypeScriptCode;
