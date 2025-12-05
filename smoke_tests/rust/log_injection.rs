// Log Injection Test Cases

// Test 1: Direct user input in log
fn log_user_action(username: &str, action: &str) {
    // VULNERABLE: username could contain newlines to inject fake log entries
    println!("User {} performed action: {}", username, action);
}

// Test 2: Logging user input without sanitization
fn log_login_attempt(email: &str, ip_address: &str, success: bool) {
    // VULNERABLE: email could be "admin\nSUCCESS: User admin logged in"
    eprintln!("Login attempt - Email: {}, IP: {}, Success: {}", email, ip_address, success);
}

// Test 3: Error logging with user data
fn log_error(user_id: &str, error_message: &str) {
    // VULNERABLE: error_message could contain ANSI codes or newlines
    eprintln!("[ERROR] User {}: {}", user_id, error_message);
}

// Test 4: Structured logging with user input (using log crate)
fn log_event(event_type: &str, user_agent: &str) {
    use log::info;
    // VULNERABLE: user_agent could inject malicious log entries
    info!("Event: {}, UserAgent: {}", event_type, user_agent);
}

// Test 5: File logging with user input
fn write_to_log_file(username: &str, message: &str) -> std::io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Write;
    use chrono::Utc;

    let timestamp = Utc::now().to_rfc3339();
    // VULNERABLE: Both username and message could contain injection attacks
    let log_line = format!("{} - {}: {}\n", timestamp, username, message);

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("/var/log/app.log")?;

    file.write_all(log_line.as_bytes())?;
    Ok(())
}
