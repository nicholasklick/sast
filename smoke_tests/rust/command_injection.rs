// Command Injection vulnerability in Rust
use std::process::Command;

fn run_command_unsafe(user_input: &str) {
    // VULNERABLE: User input passed directly to shell
    Command::new("sh")
        .arg("-c")
        .arg(format!("ls {}", user_input))
        .output()
        .expect("Failed to execute command");
}

fn execute_script_unsafe(script_name: &str) {
    // VULNERABLE: Unsanitized script execution
    Command::new("bash")
        .arg(script_name)
        .spawn()
        .expect("Failed to run script");
}

fn ping_host_unsafe(host: &str) {
    // VULNERABLE: Command injection via ping
    let cmd = format!("ping -c 1 {}", host);
    Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .expect("Ping failed");
}
