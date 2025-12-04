// Weak Cryptography vulnerability in Rust
use md5;
use sha1;

fn hash_password_md5(password: &str) -> String {
    // VULNERABLE: MD5 is cryptographically broken
    let digest = md5::compute(password.as_bytes());
    format!("{:x}", digest)
}

fn hash_data_sha1(data: &[u8]) -> String {
    // VULNERABLE: SHA1 is deprecated for security use
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    hasher.digest().to_string()
}

fn weak_random_token() -> u32 {
    // VULNERABLE: Using non-cryptographic random
    rand::random::<u32>()
}

fn insecure_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // VULNERABLE: XOR "encryption" is not secure
    data.iter().zip(key.iter().cycle()).map(|(a, b)| a ^ b).collect()
}
