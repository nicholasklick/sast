// Hardcoded Cryptographic Key Test Cases

use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

// Test 1: Hardcoded AES encryption key
fn encrypt_data_with_hardcoded_key(data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    // VULNERABLE: Hardcoded encryption key
    let key = b"0123456789abcdef0123456789abcdef";
    let iv = b"fedcba9876543210";

    let cipher = Aes256Cbc::new_from_slices(key, iv)?;
    Ok(cipher.encrypt_vec(data))
}

// Test 2: Hardcoded JWT secret
fn generate_jwt(payload: &str) -> String {
    use jsonwebtoken::{encode, Header, EncodingKey};
    use serde::{Serialize};

    #[derive(Serialize)]
    struct Claims {
        sub: String,
    }

    // VULNERABLE: Hardcoded JWT secret
    let secret = "my-super-secret-jwt-key-12345";
    let claims = Claims { sub: payload.to_string() };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes()))
        .unwrap_or_default()
}

// Test 3: Hardcoded HMAC key
fn create_signature(message: &str) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    // VULNERABLE: Hardcoded HMAC key
    let secret_key = b"hardcoded-hmac-secret-key";
    let mut mac = HmacSha256::new_from_slice(secret_key).unwrap();
    mac.update(message.as_bytes());

    format!("{:x}", mac.finalize().into_bytes())
}

// Test 4: Hardcoded encryption password
fn encrypt_with_password(plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    use argon2::Argon2;

    // VULNERABLE: Hardcoded password for encryption
    let password = b"myEncryptionPassword123!";
    let salt = b"somesalt";

    let mut key = [0u8; 32];
    Argon2::default().hash_password_into(password, salt, &mut key)?;

    let iv = b"fedcba9876543210";
    let cipher = Aes256Cbc::new_from_slices(&key, iv)?;
    Ok(cipher.encrypt_vec(plaintext))
}

// Test 5: Hardcoded API encryption key constant
const API_ENCRYPTION_KEY: &[u8; 32] = b"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"; // VULNERABLE

fn encrypt_api_payload(payload: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let iv = b"1234567890123456";
    let cipher = Aes256Cbc::new_from_slices(API_ENCRYPTION_KEY, iv)?;
    Ok(cipher.encrypt_vec(payload))
}
