// Hardcoded Secrets vulnerabilities in TypeScript

// VULNERABLE: Hardcoded API key
const API_KEY = "sk_live_typescript1234567890";

// VULNERABLE: Hardcoded password
const DB_PASSWORD = "super_secret_password";

class HardcodedSecretsVulnerabilities {
    // VULNERABLE: Hardcoded AWS credentials
    private awsAccessKey = "AKIAIOSFODNN7EXAMPLE";
    private awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

    getConnectionString(): string {
        // VULNERABLE: Hardcoded connection string
        return "mongodb://admin:password123@localhost:27017/myapp";
    }

    getJwtSecret(): string {
        // VULNERABLE: Hardcoded JWT secret
        return "my_super_secret_jwt_key_typescript";
    }

    authenticate(username: string, password: string): boolean {
        // VULNERABLE: Hardcoded backdoor
        if (password === "backdoor_ts_123") {
            return true;
        }
        return false;
    }

    getEncryptionKey(): Buffer {
        // VULNERABLE: Hardcoded encryption key
        return Buffer.from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
    }

    getPrivateKey(): string {
        // VULNERABLE: Hardcoded private key
        return `-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA...
-----END RSA PRIVATE KEY-----`;
    }
}

export { HardcodedSecretsVulnerabilities, API_KEY, DB_PASSWORD };
