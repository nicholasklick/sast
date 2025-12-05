// Race Condition Test Cases

use std::fs;
use std::path::Path;
use std::sync::Mutex;

// Test 1: Check-then-use file operation
fn read_file_if_exists(file_path: &Path) -> Option<String> {
    // VULNERABLE: File could be deleted/modified between check and read
    if file_path.exists() {
        return fs::read_to_string(file_path).ok();
    }
    None
}

// Test 2: Non-atomic balance check and update
lazy_static::lazy_static! {
    static ref ACCOUNT_BALANCE: Mutex<i32> = Mutex::new(1000);
}

fn withdraw(amount: i32) -> bool {
    let mut balance = ACCOUNT_BALANCE.lock().unwrap();
    // VULNERABLE: Not truly atomic - balance could change
    if *balance >= amount {
        // Simulating some processing time
        *balance -= amount;
        return true;
    }
    false
}

// Test 3: File creation race
fn create_unique_file(base_path: &Path) -> std::io::Result<String> {
    let mut counter = 0;
    loop {
        let file_path = base_path.join(format!("file-{}.txt", counter));
        // VULNERABLE: File could be created between exists check and creation
        if !file_path.exists() {
            fs::write(&file_path, "data")?;
            return Ok(file_path.to_string_lossy().to_string());
        }
        counter += 1;
    }
}

// Test 4: Shared resource without proper locking
struct SharedCounter {
    count: i32,
}

impl SharedCounter {
    fn increment(&mut self) {
        // VULNERABLE: Read-modify-write is not atomic without proper synchronization
        let current_value = self.count;
        self.count = current_value + 1;
    }

    fn get_count(&self) -> i32 {
        self.count
    }
}

// Test 5: Temp file creation vulnerability
fn create_temp_file(data: &str) -> std::io::Result<String> {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let temp_path = format!("/tmp/tempfile-{}.txt", timestamp);

    // VULNERABLE: Predictable filename + race between check and create
    if !Path::new(&temp_path).exists() {
        fs::write(&temp_path, data)?;
    }
    Ok(temp_path)
}
