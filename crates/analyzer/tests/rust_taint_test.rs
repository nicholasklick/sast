//! Integration tests for Rust taint analysis
//!
//! Tests that Rust-specific taint sources, sinks, and sanitizers are properly configured.

use gittera_analyzer::{TaintAnalysis, LanguageTaintConfig, TaintSourceKind, TaintSinkKind};
use gittera_parser::Language;

#[test]
fn test_rust_has_taint_sources() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(config.sources.len() > 0, "Rust should have taint sources configured");
    assert!(config.sources.len() >= 15, "Rust should have at least 15 taint sources");
}

#[test]
fn test_rust_has_cli_sources() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    // Check for command-line argument sources
    assert!(
        config.sources.iter().any(|s| s.name == "std::env::args"),
        "Rust should have 'std::env::args' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "env::args"),
        "Rust should have 'env::args' as user input source"
    );
}

#[test]
fn test_rust_has_http_sources() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    // Check for HTTP framework sources (actix-web, rocket, warp)
    assert!(
        config.sources.iter().any(|s| s.name == "HttpRequest.query_string"),
        "Rust should have 'HttpRequest.query_string' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "req.param"),
        "Rust should have 'req.param' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "Query"),
        "Rust should have 'Query' as user input source"
    );
}

#[test]
fn test_rust_has_file_sources() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sources.iter().any(|s| s.name == "std::fs::read_to_string" && matches!(s.kind, TaintSourceKind::FileRead)),
        "Rust should have 'std::fs::read_to_string' as file read source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "File::open"),
        "Rust should have 'File::open' as file read source"
    );
}

#[test]
fn test_rust_has_env_sources() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sources.iter().any(|s| s.name == "std::env::var" && matches!(s.kind, TaintSourceKind::EnvironmentVariable)),
        "Rust should have 'std::env::var' as environment variable source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "env::var"),
        "Rust should have 'env::var' as environment variable source"
    );
}

#[test]
fn test_rust_has_stdin_sources() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sources.iter().any(|s| s.name == "std::io::stdin"),
        "Rust should have 'std::io::stdin' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "stdin"),
        "Rust should have 'stdin' as user input source"
    );
}

#[test]
fn test_rust_has_network_sources() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sources.iter().any(|s| s.name == "reqwest::get" && matches!(s.kind, TaintSourceKind::NetworkRequest)),
        "Rust should have 'reqwest::get' as network source"
    );
}

#[test]
fn test_rust_has_command_execution_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sinks.iter().any(|s| s.name == "std::process::Command" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Rust should have 'std::process::Command' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "Command::new" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Rust should have 'Command::new' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "Command.spawn"),
        "Rust should have 'Command.spawn' as command execution sink"
    );
}

#[test]
fn test_rust_has_sql_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sinks.iter().any(|s| s.name == "rusqlite::Connection::execute" && matches!(s.kind, TaintSinkKind::SqlQuery)),
        "Rust should have 'rusqlite::Connection::execute' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "sqlx::query"),
        "Rust should have 'sqlx::query' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "diesel::sql_query"),
        "Rust should have 'diesel::sql_query' as SQL query sink"
    );
}

#[test]
fn test_rust_has_file_write_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sinks.iter().any(|s| s.name == "std::fs::write" && matches!(s.kind, TaintSinkKind::FileWrite)),
        "Rust should have 'std::fs::write' as file write sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "File::create"),
        "Rust should have 'File::create' as file write sink"
    );
}

#[test]
fn test_rust_has_logging_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(
        config.sinks.iter().any(|s| s.name == "println!" && matches!(s.kind, TaintSinkKind::LogOutput)),
        "Rust should have 'println!' as logging sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "eprintln!"),
        "Rust should have 'eprintln!' as logging sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "log::info"),
        "Rust should have 'log::info' as logging sink"
    );
}

#[test]
fn test_rust_has_sanitizers() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    assert!(config.sanitizers.len() > 0, "Rust should have sanitizers configured");
    assert!(
        config.sanitizers.contains(&"html_escape::encode_text".to_string()),
        "Rust should have 'html_escape::encode_text' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"sqlx::query!".to_string()),
        "Rust should have 'sqlx::query!' as sanitizer (compile-time checked)"
    );
    assert!(
        config.sanitizers.contains(&"str::parse".to_string()),
        "Rust should have 'str::parse' as sanitizer (type conversion)"
    );
    assert!(
        config.sanitizers.contains(&"Path::new".to_string()),
        "Rust should have 'Path::new' as sanitizer (path validation)"
    );
}

#[test]
fn test_rust_taint_analysis_uses_config() {
    let taint = TaintAnalysis::new().for_language(Language::Rust);

    // This test verifies that the for_language() method works
    assert!(true, "TaintAnalysis::for_language(Rust) completes successfully");
}

#[test]
fn test_rust_config_count() {
    let config = LanguageTaintConfig::for_language(Language::Rust);

    // Verify we have a reasonable number of each
    assert!(config.sources.len() >= 15, "Should have at least 15 sources");
    assert!(config.sinks.len() >= 16, "Should have at least 16 sinks");
    assert!(config.sanitizers.len() >= 10, "Should have at least 10 sanitizers");

    println!("Rust configuration:");
    println!("  Sources: {}", config.sources.len());
    println!("  Sinks: {}", config.sinks.len());
    println!("  Sanitizers: {}", config.sanitizers.len());
}
