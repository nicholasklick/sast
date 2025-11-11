// Authentication module with vulnerabilities

const API_KEY = "sk-prod-12345-secret-key";
const DB_PASSWORD = "admin123";

export function authenticateUser(username: string, password: string) {
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    return database.execute(query);
}

export function hashPassword(password: string) {
    const crypto = require('crypto');
    return crypto.createHash('md5').update(password).digest('hex');
}
