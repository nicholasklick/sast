// Rust Vulnerability Test Fixtures
use std::process::Command;
use std::fs::File;
use std::io::Read;

// 1. Command Injection - shell command
fn command_injection_shell(filename: &str) -> std::io::Result<std::process::Output> {
    Command::new("sh")
        .arg("-c")
        .arg(format!("cat {}", filename))
        .output()
}

// 2. Path Traversal
fn path_traversal(filename: &str) -> std::io::Result<String> {
    let path = format!("/var/data/{}", filename);
    let mut file = File::open(path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    Ok(contents)
}

// 3. Hardcoded Credentials - API Key
const API_KEY: &str = "sk_live_rust1234567890abcdef";

// 4. Hardcoded Credentials - Database
fn connect_to_database() -> String {
    let password = "RustSecret789!";
    format!("postgresql://admin:{}@localhost/db", password)
}

// 5. Unsafe Block - Dereferencing raw pointer
fn unsafe_dereference(ptr: *const i32) -> i32 {
    unsafe {
        // Unsafe dereference without null check
        *ptr
    }
}

// 6. Unsafe Block - Mutable static
static mut COUNTER: i32 = 0;

fn increment_counter() {
    unsafe {
        // Mutable static without synchronization
        COUNTER += 1;
    }
}

// 7. Weak Random Number Generation
use rand::Rng;

fn generate_token() -> String {
    let mut rng = rand::thread_rng();
    // Using predictable RNG for security token
    rng.gen::<u64>().to_string()
}

// 8. SQL Injection - String concatenation
fn sql_injection_concat(user_id: &str) -> String {
    format!("SELECT * FROM users WHERE id = '{}'", user_id)
}

// 9. Unsafe transmute
fn unsafe_transmute<T, U>(value: T) -> U {
    unsafe {
        // Unsafe transmute without size/alignment checks
        std::mem::transmute_copy(&value)
    }
}

// 10. Memory leak - forget
fn memory_leak(data: Vec<u8>) {
    std::mem::forget(data); // Intentionally leak memory
}

// 11. Unsafe FFI call
extern "C" {
    fn dangerous_c_function(ptr: *const u8, len: usize) -> i32;
}

fn unsafe_ffi_call(data: &[u8]) -> i32 {
    unsafe {
        // Calling C function without validation
        dangerous_c_function(data.as_ptr(), data.len())
    }
}

// 12. Race condition with RefCell
use std::cell::RefCell;
use std::rc::Rc;

fn race_condition() {
    let data = Rc::new(RefCell::new(0));
    let data_clone = Rc::clone(&data);

    // Potential race if used in multi-threaded context
    *data.borrow_mut() += 1;
    *data_clone.borrow_mut() += 1;
}

// 13. Buffer overflow potential (unsafe)
fn buffer_overflow(src: &[u8], dst: &mut [u8]) {
    unsafe {
        // No bounds checking
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst.as_mut_ptr(), src.len());
    }
}

// 14. Use after free
fn use_after_free() {
    let mut v = vec![1, 2, 3];
    let ptr = v.as_ptr();
    drop(v);
    unsafe {
        // Using pointer after vector is dropped
        println!("{}", *ptr);
    }
}

// 15. Weak Cryptography - MD5
use md5::{Md5, Digest};

fn weak_hash_md5(input: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    format!("{:x}", hasher.finalize())
}

// 16. SSRF Vulnerability
fn fetch_url(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let response = reqwest::blocking::get(url)?;
    let body = response.text()?;
    Ok(body)
}

// 17. Open Redirect
fn redirect(url: &str) -> String {
    format!("Redirecting to: {}", url)
}

// 18. Template Injection
fn render_template(user_input: &str) -> String {
    format!("<html><body><h1>Welcome {}</h1></body></html>", user_input)
}

// 19. Unsafe Send/Sync implementation
struct UnsafeWrapper(*mut i32);

unsafe impl Send for UnsafeWrapper {}
unsafe impl Sync for UnsafeWrapper {}

// 20. Unchecked indexing
fn unchecked_indexing(vec: Vec<i32>, index: usize) -> i32 {
    unsafe {
        // No bounds check
        *vec.get_unchecked(index)
    }
}
