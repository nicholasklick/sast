// Path Traversal vulnerability in Rust
use std::fs;
use std::path::Path;

fn read_file_unsafe(filename: &str) -> Result<String, std::io::Error> {
    // VULNERABLE: No path validation
    let path = format!("/var/data/{}", filename);
    fs::read_to_string(path)
}

fn serve_file_unsafe(user_path: &str) -> Result<Vec<u8>, std::io::Error> {
    // VULNERABLE: Direct path concatenation
    let base = "/public/files/";
    let full_path = format!("{}{}", base, user_path);
    fs::read(full_path)
}

fn delete_file_unsafe(filename: &str) -> Result<(), std::io::Error> {
    // VULNERABLE: Arbitrary file deletion
    let path = Path::new("/uploads").join(filename);
    fs::remove_file(path)
}
