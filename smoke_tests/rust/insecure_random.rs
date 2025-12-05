// Insecure Random Test Cases

use rand::Rng;

// Test 1: Using thread_rng for security token
fn generate_session_token() -> String {
    let mut rng = rand::thread_rng();
    // VULNERABLE: thread_rng is not cryptographically secure
    let token: u64 = rng.gen();
    format!("{:x}", token)
}

// Test 2: Random password reset token
fn create_password_reset_token(user_id: &str) -> String {
    let mut rng = rand::thread_rng();
    let random_part: u64 = rng.gen();
    // VULNERABLE: Predictable random number generation
    format!("{}-{:x}", user_id, random_part)
}

// Test 3: CSRF token generation
fn generate_csrf_token() -> String {
    let mut rng = rand::thread_rng();
    // VULNERABLE: Not cryptographically secure
    let token: u128 = rng.gen();
    format!("{:032x}", token)
}

// Test 4: API key generation with weak RNG
fn generate_api_key() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let mut rng = rand::thread_rng();
    let random: u32 = rng.gen();
    // VULNERABLE: Combination of predictable values
    format!("{}-{}", timestamp, random)
}

// Test 5: Encryption key with insecure random
fn generate_encryption_key() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut key = vec![0u8; 32];
    // VULNERABLE: Using non-cryptographic RNG for encryption key
    rng.fill(&mut key[..]);
    key
}
