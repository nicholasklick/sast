// Weak Hash (MD5/SHA1) Test Cases

use md5;
use sha1::{Sha1, Digest};

// Test 1: MD5 for password hashing
fn hash_password_md5(password: &str) -> String {
    // VULNERABLE: MD5 is cryptographically broken
    format!("{:x}", md5::compute(password.as_bytes()))
}

// Test 2: SHA1 for password hashing
fn hash_password_sha1(password: &str) -> String {
    // VULNERABLE: SHA1 is cryptographically weak
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

// Test 3: MD5 for token generation
fn generate_token_md5(user_id: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let data = format!("{}{}", user_id, timestamp);
    // VULNERABLE: MD5 should not be used for security tokens
    format!("{:x}", md5::compute(data.as_bytes()))
}

// Test 4: SHA1 for file integrity checking
fn calculate_file_checksum_sha1(data: &[u8]) -> String {
    // VULNERABLE: SHA1 is not suitable for security purposes
    let mut hasher = Sha1::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

// Test 5: MD5 digest for API signatures
fn create_api_signature_md5(payload: &str, secret: &str) -> String {
    let combined = format!("{}{}", payload, secret);
    // VULNERABLE: MD5 is not suitable for cryptographic signatures
    format!("{:x}", md5::compute(combined.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weak_hashes() {
        let _ = hash_password_md5("password123");
        let _ = hash_password_sha1("secret");
    }
}
