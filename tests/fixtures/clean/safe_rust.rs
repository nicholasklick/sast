// Clean Rust code with no vulnerabilities
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::env;

/// Safe File Access - Path validation
fn read_file(filename: &str) -> Result<String, std::io::Error> {
    let base_path = PathBuf::from("/var/data");
    let file_path = base_path.join(filename);

    // Canonicalize and validate
    let canonical_path = file_path.canonicalize()?;
    let canonical_base = base_path.canonicalize()?;

    if !canonical_path.starts_with(canonical_base) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Path traversal detected",
        ));
    }

    let mut file = File::open(canonical_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

/// Safe Configuration - Environment variable
fn get_api_key() -> Result<String, String> {
    env::var("API_KEY").map_err(|_| "API_KEY not set".to_string())
}

/// Safe Hashing - SHA-256
use sha2::{Sha256, Digest};

fn hash_password(password: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Safe Random Generation
use rand::RngCore;

fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Safe Input Validation
fn validate_and_sanitize(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

/// Safe Vector Access
fn safe_vector_access(vec: &Vec<i32>, index: usize) -> Option<i32> {
    vec.get(index).copied()
}

/// Safe String Operations
fn safe_string_slice(s: &str, start: usize, end: usize) -> Option<&str> {
    s.get(start..end)
}

/// Safe Integer Operations
fn safe_add(a: i32, b: i32) -> Option<i32> {
    a.checked_add(b)
}

/// Safe Pointer Usage (proper ownership)
fn safe_pointer_usage(value: i32) -> i32 {
    let boxed = Box::new(value);
    *boxed
}

/// Thread-safe Counter
use std::sync::{Arc, Mutex};

struct SafeCounter {
    count: Arc<Mutex<i32>>,
}

impl SafeCounter {
    fn new() -> Self {
        SafeCounter {
            count: Arc::new(Mutex::new(0)),
        }
    }

    fn increment(&self) {
        let mut count = self.count.lock().unwrap();
        *count += 1;
    }
}
