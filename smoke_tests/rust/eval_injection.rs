// Eval Injection Test Cases

// Test 1: Dynamic code execution with user input
fn execute_user_code(code: &str) -> Result<i32, String> {
    // VULNERABLE: Executing arbitrary code from user input
    // Rust doesn't have eval, but this simulates using external interpreters
    use std::process::Command;

    let output = Command::new("sh")
        .arg("-c")
        .arg(code) // User-controlled code execution
        .output()
        .map_err(|e| e.to_string())?;

    Ok(output.status.code().unwrap_or(-1))
}

// Test 2: Lua script execution from user input
fn run_lua_script(script: &str) -> Result<String, String> {
    use std::process::Command;

    // VULNERABLE: Running user-provided Lua script
    let output = Command::new("lua")
        .arg("-e")
        .arg(script)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Test 3: Python eval via subprocess
fn eval_python_expression(expr: &str) -> Result<String, String> {
    use std::process::Command;

    // VULNERABLE: Evaluating arbitrary Python expressions
    let code = format!("print({})", expr);
    let output = Command::new("python3")
        .arg("-c")
        .arg(&code)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Test 4: JavaScript execution
fn run_javascript(js_code: &str) -> Result<String, String> {
    use std::process::Command;

    // VULNERABLE: Executing user-provided JavaScript
    let output = Command::new("node")
        .arg("-e")
        .arg(js_code)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// Test 5: Shell command interpolation
fn run_shell_with_user_input(user_input: &str) -> Result<String, String> {
    use std::process::Command;

    // VULNERABLE: User input in shell command
    let command = format!("echo {}", user_input);
    let output = Command::new("sh")
        .arg("-c")
        .arg(&command)
        .output()
        .map_err(|e| e.to_string())?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}
