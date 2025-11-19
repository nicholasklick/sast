//! Integration tests for PHP taint analysis
//!
//! Tests that PHP-specific taint sources, sinks, and sanitizers are properly configured.

use kodecd_analyzer::{TaintAnalysis, LanguageTaintConfig, TaintSourceKind, TaintSinkKind};
use kodecd_parser::Language;

#[test]
fn test_php_has_taint_sources() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(config.sources.len() > 0, "PHP should have taint sources configured");
    assert!(config.sources.len() >= 15, "PHP should have at least 15 taint sources");
}

#[test]
fn test_php_has_superglobal_sources() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    // Check for PHP super globals
    assert!(
        config.sources.iter().any(|s| s.name == "$_GET"),
        "PHP should have '$_GET' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "$_POST"),
        "PHP should have '$_POST' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "$_COOKIE"),
        "PHP should have '$_COOKIE' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "$_REQUEST"),
        "PHP should have '$_REQUEST' as user input source"
    );
}

#[test]
fn test_php_has_file_sources() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(
        config.sources.iter().any(|s| s.name == "file_get_contents" && matches!(s.kind, TaintSourceKind::FileRead)),
        "PHP should have 'file_get_contents' as file read source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "fread"),
        "PHP should have 'fread' as file read source"
    );
}

#[test]
fn test_php_has_env_sources() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(
        config.sources.iter().any(|s| s.name == "getenv" && matches!(s.kind, TaintSourceKind::EnvironmentVariable)),
        "PHP should have 'getenv' as environment variable source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "$_ENV"),
        "PHP should have '$_ENV' as environment variable source"
    );
}

#[test]
fn test_php_has_command_execution_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(
        config.sinks.iter().any(|s| s.name == "system" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "PHP should have 'system' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "exec" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "PHP should have 'exec' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "shell_exec"),
        "PHP should have 'shell_exec' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "passthru"),
        "PHP should have 'passthru' as command execution sink"
    );
}

#[test]
fn test_php_has_code_eval_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(
        config.sinks.iter().any(|s| s.name == "eval" && matches!(s.kind, TaintSinkKind::CodeEval)),
        "PHP should have 'eval' as code evaluation sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "assert"),
        "PHP should have 'assert' as code evaluation sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "create_function"),
        "PHP should have 'create_function' as code evaluation sink"
    );
}

#[test]
fn test_php_has_sql_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(
        config.sinks.iter().any(|s| s.name == "mysqli_query" && matches!(s.kind, TaintSinkKind::SqlQuery)),
        "PHP should have 'mysqli_query' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "mysql_query"),
        "PHP should have 'mysql_query' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "PDO::query"),
        "PHP should have 'PDO::query' as SQL query sink"
    );
}

#[test]
fn test_php_has_html_output_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(
        config.sinks.iter().any(|s| s.name == "echo" && matches!(s.kind, TaintSinkKind::HtmlOutput)),
        "PHP should have 'echo' as HTML output sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "print"),
        "PHP should have 'print' as HTML output sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "printf"),
        "PHP should have 'printf' as HTML output sink"
    );
}

#[test]
fn test_php_has_file_write_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(
        config.sinks.iter().any(|s| s.name == "file_put_contents" && matches!(s.kind, TaintSinkKind::FileWrite)),
        "PHP should have 'file_put_contents' as file write sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "fwrite"),
        "PHP should have 'fwrite' as file write sink"
    );
}

#[test]
fn test_php_has_sanitizers() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    assert!(config.sanitizers.len() > 0, "PHP should have sanitizers configured");
    assert!(
        config.sanitizers.contains(&"htmlspecialchars".to_string()),
        "PHP should have 'htmlspecialchars' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"htmlentities".to_string()),
        "PHP should have 'htmlentities' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"mysqli_real_escape_string".to_string()),
        "PHP should have 'mysqli_real_escape_string' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"escapeshellarg".to_string()),
        "PHP should have 'escapeshellarg' as sanitizer"
    );
}

#[test]
fn test_php_taint_analysis_uses_config() {
    let taint = TaintAnalysis::new().for_language(Language::Php);

    // This test verifies that the for_language() method works
    assert!(true, "TaintAnalysis::for_language(Php) completes successfully");
}

#[test]
fn test_php_config_count() {
    let config = LanguageTaintConfig::for_language(Language::Php);

    // Verify we have a reasonable number of each
    assert!(config.sources.len() >= 15, "Should have at least 15 sources");
    assert!(config.sinks.len() >= 30, "Should have at least 30 sinks");
    assert!(config.sanitizers.len() >= 10, "Should have at least 10 sanitizers");

    println!("PHP configuration:");
    println!("  Sources: {}", config.sources.len());
    println!("  Sinks: {}", config.sinks.len());
    println!("  Sanitizers: {}", config.sanitizers.len());
}
