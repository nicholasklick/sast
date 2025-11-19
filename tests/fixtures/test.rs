// Simple test file
fn main() {
    let x = 42;
    println!("Hello, world! {}", x);
}

fn execute_query(sql: String) {
    // Potential SQL injection
    database.execute(&sql);
}

fn process_command(cmd: String) {
    // Potential command injection
    std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .spawn();
}
