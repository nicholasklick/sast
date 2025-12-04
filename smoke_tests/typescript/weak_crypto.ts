// Weak Cryptography vulnerabilities in TypeScript
import * as crypto from 'crypto';

class WeakCryptoVulnerabilities {
    hashMd5(input: string): string {
        // VULNERABLE: MD5 is cryptographically broken
        return crypto.createHash('md5').update(input).digest('hex');
    }

    hashSha1(input: string): string {
        // VULNERABLE: SHA1 is deprecated
        return crypto.createHash('sha1').update(input).digest('hex');
    }

    encryptDes(data: string, key: string): string {
        // VULNERABLE: DES is obsolete
        const cipher = crypto.createCipheriv('des-ecb', key, null);
        return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
    }

    generateToken(): number {
        // VULNERABLE: Non-cryptographic random
        return Math.random() * 1000000;
    }

    weakSessionId(): string {
        // VULNERABLE: Predictable session ID
        return Date.now().toString();
    }

    ecbEncryption(data: string, key: Buffer): string {
        // VULNERABLE: ECB mode
        const cipher = crypto.createCipheriv('aes-128-ecb', key, null);
        return cipher.update(data, 'utf8', 'hex') + cipher.final('hex');
    }

    weakPrng(): number {
        // VULNERABLE: Math.random is not cryptographically secure
        return Math.floor(Math.random() * 100);
    }
}

export { WeakCryptoVulnerabilities };
