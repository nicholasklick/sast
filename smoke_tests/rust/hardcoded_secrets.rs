// Hardcoded Secrets vulnerability in Rust

// VULNERABLE: Hardcoded API key
const API_KEY: &str = "sk_live_1234567890abcdef";

// VULNERABLE: Hardcoded password
const DB_PASSWORD: &str = "super_secret_password_123";

// VULNERABLE: Hardcoded AWS credentials
const AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_KEY: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

fn connect_to_database() -> String {
    // VULNERABLE: Hardcoded connection string with password
    let conn_str = "postgres://admin:password123@localhost:5432/mydb";
    conn_str.to_string()
}

fn get_jwt_secret() -> &'static str {
    // VULNERABLE: Hardcoded JWT secret
    "my_super_secret_jwt_key_do_not_share"
}

fn encrypt_data(data: &[u8]) -> Vec<u8> {
    // VULNERABLE: Hardcoded encryption key
    let key = b"0123456789abcdef";
    data.iter().zip(key.iter().cycle()).map(|(a, b)| a ^ b).collect()
}
