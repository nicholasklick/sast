// Timing Attack Test Cases

// Test 1: String comparison for authentication
fn authenticate_with_string_comparison(provided_token: &str, valid_token: &str) -> bool {
    // VULNERABLE: Early return on mismatch reveals information via timing
    if provided_token.len() != valid_token.len() {
        return false;
    }
    for (a, b) in provided_token.chars().zip(valid_token.chars()) {
        if a != b {
            return false; // Early exit leaks timing info
        }
    }
    true
}

// Test 2: Password comparison using ==
fn check_password(input_password: &str, stored_password: &str) -> bool {
    // VULNERABLE: Direct string comparison is timing-unsafe
    input_password == stored_password
}

// Test 3: API key validation
fn validate_api_key(provided_key: &str, valid_key: &str) -> bool {
    // VULNERABLE: Byte-by-byte comparison leaks timing info
    if provided_key.len() != valid_key.len() {
        return false;
    }

    let mut matches = true;
    for (a, b) in provided_key.bytes().zip(valid_key.bytes()) {
        if a != b {
            matches = false;
            break; // Early exit reveals position of mismatch
        }
    }
    matches
}

// Test 4: Token verification with eq
fn verify_token(user_token: &[u8], server_token: &[u8]) -> bool {
    // VULNERABLE: Slice comparison is not constant-time
    user_token == server_token
}

// Test 5: HMAC comparison without constant-time
fn verify_hmac(message: &str, provided_hmac: &str, key: &[u8]) -> bool {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).unwrap();
    mac.update(message.as_bytes());
    let expected_hmac = format!("{:x}", mac.finalize().into_bytes());

    // VULNERABLE: Direct comparison of HMAC values
    provided_hmac == expected_hmac
}
