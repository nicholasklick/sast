//! CLI Integration Tests
//!
//! Comprehensive end-to-end tests for the gittera-sast CLI interface.
//! Tests cover basic commands, output formats, query options, baseline/cache features,
//! error handling, and exit codes.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

// ============================================================================
// SECTION 1: BASIC COMMANDS (5 tests)
// ============================================================================

#[test]
fn test_cli_version() {
    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("--version");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("0.1.0"));
}

#[test]
fn test_cli_help() {
    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("High-performance SAST engine"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("scan"))
        .stdout(predicate::str::contains("list-queries"));
}

#[test]
fn test_cli_scan_file_with_vulnerabilities() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");

    // Create file with known vulnerability (user input to eval)
    // Use a proper taint source pattern the analyzer recognizes
    fs::write(&test_file, r#"
const input = req.query.code;
eval(input);
"#).unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&test_file)
        .arg("--format")
        .arg("text");

    // Should exit with code 1 (findings detected)
    cmd.assert()
        .code(1)
        .stdout(predicate::str::contains("Finding").or(predicate::str::contains("eval")).or(predicate::str::contains("injection")));
}

#[test]
fn test_cli_scan_clean_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("clean.js");

    // Create clean file with no vulnerabilities
    fs::write(&test_file, "const x = 42;\nconsole.log(x);").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&test_file)
        .arg("--format")
        .arg("text");

    // Should exit with code 0 (no findings)
    cmd.assert().success();
}

#[test]
fn test_cli_list_queries() {
    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("list-queries");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Gittera Extended Query Library"))
        .stdout(predicate::str::contains("Query Suites:"));
}

// ============================================================================
// SECTION 2: OUTPUT FORMATS (3 tests)
// ============================================================================

#[test]
fn test_cli_output_format_json() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");
    fs::write(&test_file, "eval(userInput);").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&test_file)
        .arg("--format")
        .arg("json");

    cmd.assert()
        .code(predicate::in_iter([0, 1])) // Either findings or no findings
        .stdout(predicate::str::contains("{").and(predicate::str::contains("}")));
}

#[test]
fn test_cli_output_format_sarif() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");
    fs::write(&test_file, "eval(userInput);").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&test_file)
        .arg("--format")
        .arg("sarif");

    cmd.assert()
        .code(predicate::in_iter([0, 1]))
        .stdout(predicate::str::contains("$schema"))
        .stdout(predicate::str::contains("version"))
        .stdout(predicate::str::contains("2.1.0")); // SARIF version
}

#[test]
fn test_cli_output_to_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");
    let output_file = temp_dir.path().join("results.json");

    fs::write(&test_file, "eval(userInput);").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&test_file)
        .arg("--format")
        .arg("json")
        .arg("--output")
        .arg(&output_file);

    cmd.assert().code(predicate::in_iter([0, 1]));

    // Verify output file was created and contains JSON
    assert!(output_file.exists(), "Output file should exist");
    let content = fs::read_to_string(&output_file).unwrap();
    assert!(content.contains("{"), "Output should be JSON");
}

// ============================================================================
// SECTION 3: QUERY OPTIONS (3 tests)
// ============================================================================

#[test]
fn test_cli_validate_query_valid() {
    let temp_dir = TempDir::new().unwrap();
    let query_file = temp_dir.path().join("test.gql");

    // Create valid GQL query
    fs::write(
        &query_file,
        r#"FROM CallExpression AS call
WHERE call.callee == "eval"
SELECT call, "Dangerous eval usage""#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("validate-query").arg(&query_file);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("✓ Query is valid"));
}

#[test]
fn test_cli_validate_query_invalid() {
    let temp_dir = TempDir::new().unwrap();
    let query_file = temp_dir.path().join("invalid.gql");

    // Create invalid GQL query (missing SELECT)
    fs::write(
        &query_file,
        r#"FROM CallExpression AS call
WHERE call.callee == "eval""#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("validate-query").arg(&query_file);

    // Should fail (exit code 1 or 2)
    cmd.assert().failure();
}

#[test]
fn test_cli_scan_with_custom_query() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");
    let query_file = temp_dir.path().join("custom.gql");

    fs::write(&test_file, "eval(userInput);").unwrap();
    fs::write(
        &query_file,
        r#"FROM CallExpression AS call
WHERE call.callee == "eval"
SELECT call, "Custom eval detection""#,
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("analyze")
        .arg(&test_file)
        .arg("--query")
        .arg(&query_file)
        .arg("--format")
        .arg("text");

    cmd.assert().code(predicate::in_iter([0, 1]));
}

// ============================================================================
// SECTION 4: BASELINE & CACHE (3 tests)
// ============================================================================

#[test]
fn test_cli_incremental_scan() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let file1 = src_dir.join("file1.js");
    let file2 = src_dir.join("file2.js");

    fs::write(&file1, "eval(userInput);").unwrap();
    fs::write(&file2, "const x = 42;").unwrap();

    // First scan (should scan all files)
    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&src_dir)
        .arg("--incremental")
        .arg("--format")
        .arg("json");

    cmd.assert().code(predicate::in_iter([0, 1]));

    // Second scan (should use cache)
    let mut cmd2 = Command::cargo_bin("gittera-sast").unwrap();
    cmd2.arg("scan")
        .arg(&src_dir)
        .arg("--incremental")
        .arg("--format")
        .arg("json");

    cmd2.assert().code(predicate::in_iter([0, 1]));
}

#[test]
fn test_cli_baseline_create() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");
    fs::write(&test_file, "eval(userInput);").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&test_file)
        .arg("--baseline-create")
        .arg("--format")
        .arg("text");

    cmd.assert().code(predicate::in_iter([0, 1]));
}

#[test]
fn test_cli_baseline_use() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    let test_file = src_dir.join("test.js");
    fs::write(&test_file, "eval(userInput);").unwrap();

    // Create baseline first
    let mut cmd1 = Command::cargo_bin("gittera-sast").unwrap();
    cmd1.arg("scan")
        .arg(&src_dir)
        .arg("--baseline-create")
        .arg("--format")
        .arg("json");

    cmd1.assert().code(predicate::in_iter([0, 1]));

    // Scan with baseline (should suppress baseline findings)
    let mut cmd2 = Command::cargo_bin("gittera-sast").unwrap();
    cmd2.arg("scan")
        .arg(&src_dir)
        .arg("--baseline-use")
        .arg("--format")
        .arg("json");

    cmd2.assert().success(); // Should be 0 as baseline findings are suppressed
}

// ============================================================================
// SECTION 5: ERROR HANDLING (3 tests)
// ============================================================================

#[test]
fn test_cli_invalid_path() {
    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan").arg("/nonexistent/path/file.js");

    cmd.assert().failure();
}

#[test]
fn test_cli_invalid_format() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");
    fs::write(&test_file, "const x = 42;").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&test_file)
        .arg("--format")
        .arg("invalid_format");

    // Should still work but default to text format
    cmd.assert().code(predicate::in_iter([0, 1]));
}

#[test]
fn test_cli_invalid_query_file() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.js");
    fs::write(&test_file, "const x = 42;").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("analyze")
        .arg(&test_file)
        .arg("--query")
        .arg("/nonexistent/query.gql");

    cmd.assert().failure();
}

// ============================================================================
// SECTION 6: EXIT CODES (3 tests)
// ============================================================================

#[test]
fn test_cli_exit_code_no_findings() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("clean.js");

    // Create clean file
    fs::write(&test_file, "const x = 42;\nconsole.log(x);").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan").arg(&test_file);

    // Exit code 0 for no findings
    cmd.assert().code(0);
}

#[test]
fn test_cli_exit_code_has_findings() {
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("vuln.js");

    // Create file with vulnerability (proper taint source to sink)
    fs::write(&test_file, r#"
const userInput = req.body.code;
eval(userInput);
"#).unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan").arg(&test_file);

    // Exit code 1 for findings detected
    cmd.assert().code(1);
}

#[test]
fn test_cli_exit_code_error() {
    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan").arg("/nonexistent/file.js");

    // Exit code != 0 for errors (should be 1 or 2)
    cmd.assert().failure();
}

// ============================================================================
// SECTION 7: DIRECTORY SCANNING (2 tests)
// ============================================================================

#[test]
fn test_cli_scan_directory() {
    let temp_dir = TempDir::new().unwrap();
    let src_dir = temp_dir.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();

    // Create multiple files
    fs::write(src_dir.join("file1.js"), "eval(userInput);").unwrap();
    fs::write(src_dir.join("file2.js"), "const x = 42;").unwrap();
    fs::write(src_dir.join("file3.js"), "console.log('safe');").unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan")
        .arg(&src_dir)
        .arg("--format")
        .arg("json");

    cmd.assert().code(predicate::in_iter([0, 1]));
}

#[test]
fn test_cli_scan_empty_directory() {
    let temp_dir = TempDir::new().unwrap();
    let empty_dir = temp_dir.path().join("empty");
    fs::create_dir_all(&empty_dir).unwrap();

    let mut cmd = Command::cargo_bin("gittera-sast").unwrap();
    cmd.arg("scan").arg(&empty_dir);

    // Should succeed with no findings
    cmd.assert().code(0);
}
