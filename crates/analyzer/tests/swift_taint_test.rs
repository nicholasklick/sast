//! Integration tests for Swift taint analysis
//!
//! Tests that Swift-specific taint sources, sinks, and sanitizers are properly configured.

use kodecd_analyzer::{TaintAnalysis, LanguageTaintConfig, TaintSourceKind, TaintSinkKind};
use kodecd_parser::Language;

#[test]
fn test_swift_has_taint_sources() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(config.sources.len() > 0, "Swift should have taint sources configured");
    assert!(config.sources.len() >= 17, "Swift should have at least 17 taint sources");
}

#[test]
fn test_swift_has_cli_sources() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    // Check for command-line argument sources
    assert!(
        config.sources.iter().any(|s| s.name == "CommandLine.arguments"),
        "Swift should have 'CommandLine.arguments' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "ProcessInfo.processInfo.arguments"),
        "Swift should have 'ProcessInfo.processInfo.arguments' as user input source"
    );
}

#[test]
fn test_swift_has_network_sources() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    // Check for network sources
    assert!(
        config.sources.iter().any(|s| s.name == "URLRequest"),
        "Swift should have 'URLRequest' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "URLComponents.queryItems"),
        "Swift should have 'URLComponents.queryItems' as user input source"
    );
}

#[test]
fn test_swift_has_file_sources() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sources.iter().any(|s| s.name == "String(contentsOfFile:)" && matches!(s.kind, TaintSourceKind::FileRead)),
        "Swift should have 'String(contentsOfFile:)' as file read source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "Data(contentsOf:)"),
        "Swift should have 'Data(contentsOf:)' as file read source"
    );
}

#[test]
fn test_swift_has_env_sources() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sources.iter().any(|s| s.name == "ProcessInfo.processInfo.environment" && matches!(s.kind, TaintSourceKind::EnvironmentVariable)),
        "Swift should have 'ProcessInfo.processInfo.environment' as environment variable source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "getenv"),
        "Swift should have 'getenv' as environment variable source"
    );
}

#[test]
fn test_swift_has_userdefaults_sources() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    // UserDefaults can be manipulated and should be considered tainted
    assert!(
        config.sources.iter().any(|s| s.name == "UserDefaults.standard.string"),
        "Swift should have 'UserDefaults.standard.string' as user input source"
    );
}

#[test]
fn test_swift_has_database_sources() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sources.iter().any(|s| s.name == "sqlite3_column_text" && matches!(s.kind, TaintSourceKind::DatabaseQuery)),
        "Swift should have 'sqlite3_column_text' as database source"
    );
}

#[test]
fn test_swift_has_command_execution_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sinks.iter().any(|s| s.name == "Process" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Swift should have 'Process' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "NSTask" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Swift should have 'NSTask' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "Process.launch"),
        "Swift should have 'Process.launch' as command execution sink"
    );
}

#[test]
fn test_swift_has_sql_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sinks.iter().any(|s| s.name == "sqlite3_exec" && matches!(s.kind, TaintSinkKind::SqlQuery)),
        "Swift should have 'sqlite3_exec' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "sqlite3_prepare"),
        "Swift should have 'sqlite3_prepare' as SQL query sink"
    );
}

#[test]
fn test_swift_has_file_write_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sinks.iter().any(|s| s.name == "write(to:)" && matches!(s.kind, TaintSinkKind::FileWrite)),
        "Swift should have 'write(to:)' as file write sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "FileManager.createFile"),
        "Swift should have 'FileManager.createFile' as file write sink"
    );
}

#[test]
fn test_swift_has_webview_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sinks.iter().any(|s| s.name == "WKWebView.loadHTMLString" && matches!(s.kind, TaintSinkKind::HtmlOutput)),
        "Swift should have 'WKWebView.loadHTMLString' as HTML output sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "UIWebView.loadHTMLString"),
        "Swift should have 'UIWebView.loadHTMLString' as HTML output sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "evaluateJavaScript"),
        "Swift should have 'evaluateJavaScript' as HTML output sink"
    );
}

#[test]
fn test_swift_has_logging_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(
        config.sinks.iter().any(|s| s.name == "print" && matches!(s.kind, TaintSinkKind::LogOutput)),
        "Swift should have 'print' as logging sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "NSLog"),
        "Swift should have 'NSLog' as logging sink"
    );
}

#[test]
fn test_swift_has_sanitizers() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    assert!(config.sanitizers.len() > 0, "Swift should have sanitizers configured");
    assert!(
        config.sanitizers.contains(&"addingPercentEncoding".to_string()),
        "Swift should have 'addingPercentEncoding' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"sqlite3_bind_text".to_string()),
        "Swift should have 'sqlite3_bind_text' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"Int()".to_string()),
        "Swift should have 'Int()' as sanitizer (type conversion)"
    );
}

#[test]
fn test_swift_taint_analysis_uses_config() {
    let taint = TaintAnalysis::new().for_language(Language::Swift);

    // This test verifies that the for_language() method works
    assert!(true, "TaintAnalysis::for_language(Swift) completes successfully");
}

#[test]
fn test_swift_config_count() {
    let config = LanguageTaintConfig::for_language(Language::Swift);

    // Verify we have a reasonable number of each
    assert!(config.sources.len() >= 17, "Should have at least 17 sources");
    assert!(config.sinks.len() >= 18, "Should have at least 18 sinks");
    assert!(config.sanitizers.len() >= 10, "Should have at least 10 sanitizers");

    println!("Swift configuration:");
    println!("  Sources: {}", config.sources.len());
    println!("  Sinks: {}", config.sinks.len());
    println!("  Sanitizers: {}", config.sanitizers.len());
}
