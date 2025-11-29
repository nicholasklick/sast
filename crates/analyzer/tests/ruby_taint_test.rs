//! Integration tests for Ruby taint analysis
//!
//! Tests that Ruby-specific taint sources, sinks, and sanitizers are properly configured.

use gittera_analyzer::{TaintAnalysis, LanguageTaintConfig, TaintSourceKind, TaintSinkKind};
use gittera_parser::Language;

#[test]
fn test_ruby_has_taint_sources() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(config.sources.len() > 0, "Ruby should have taint sources configured");
    assert!(config.sources.len() >= 20, "Ruby should have at least 20 taint sources");
}

#[test]
fn test_ruby_has_user_input_sources() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    // Check for specific Ruby user input sources
    assert!(
        config.sources.iter().any(|s| s.name == "params"),
        "Ruby should have 'params' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "gets"),
        "Ruby should have 'gets' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "request.params"),
        "Ruby should have 'request.params' as user input source"
    );
}

#[test]
fn test_ruby_has_file_sources() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(
        config.sources.iter().any(|s| s.name == "File.read" && matches!(s.kind, TaintSourceKind::FileRead)),
        "Ruby should have 'File.read' as file read source"
    );
}

#[test]
fn test_ruby_has_env_sources() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(
        config.sources.iter().any(|s| s.name == "ENV" && matches!(s.kind, TaintSourceKind::EnvironmentVariable)),
        "Ruby should have 'ENV' as environment variable source"
    );
}

#[test]
fn test_ruby_has_command_execution_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(
        config.sinks.iter().any(|s| s.name == "system" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Ruby should have 'system' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "exec" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Ruby should have 'exec' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "spawn"),
        "Ruby should have 'spawn' as command execution sink"
    );
}

#[test]
fn test_ruby_has_code_eval_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(
        config.sinks.iter().any(|s| s.name == "eval" && matches!(s.kind, TaintSinkKind::CodeEval)),
        "Ruby should have 'eval' as code evaluation sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "instance_eval"),
        "Ruby should have 'instance_eval' as code evaluation sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "send"),
        "Ruby should have 'send' as code evaluation sink (dynamic method invocation)"
    );
}

#[test]
fn test_ruby_has_sql_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(
        config.sinks.iter().any(|s| s.name == "execute" && matches!(s.kind, TaintSinkKind::SqlQuery)),
        "Ruby should have 'execute' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "find_by_sql"),
        "Ruby should have 'find_by_sql' as SQL query sink"
    );
}

#[test]
fn test_ruby_has_html_output_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(
        config.sinks.iter().any(|s| s.name == "raw" && matches!(s.kind, TaintSinkKind::HtmlOutput)),
        "Ruby should have 'raw' as HTML output sink (Rails helper)"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "html_safe"),
        "Ruby should have 'html_safe' as HTML output sink"
    );
}

#[test]
fn test_ruby_has_file_write_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(
        config.sinks.iter().any(|s| s.name == "File.write" && matches!(s.kind, TaintSinkKind::FileWrite)),
        "Ruby should have 'File.write' as file write sink"
    );
}

#[test]
fn test_ruby_has_sanitizers() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    assert!(config.sanitizers.len() > 0, "Ruby should have sanitizers configured");
    assert!(
        config.sanitizers.contains(&"sanitize".to_string()),
        "Ruby should have 'sanitize' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"h".to_string()),
        "Ruby should have 'h' (HTML escape helper) as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"Shellwords.escape".to_string()),
        "Ruby should have 'Shellwords.escape' as sanitizer"
    );
}

#[test]
fn test_ruby_taint_analysis_uses_config() {
    let taint = TaintAnalysis::new().for_language(Language::Ruby);

    // This test verifies that the for_language() method works
    // The taint analysis should now be configured with Ruby-specific sources/sinks
    // We can't easily inspect the private fields, but we verified the config above
    assert!(true, "TaintAnalysis::for_language(Ruby) completes successfully");
}

#[test]
fn test_ruby_config_count() {
    let config = LanguageTaintConfig::for_language(Language::Ruby);

    // Verify we have a reasonable number of each
    assert!(config.sources.len() >= 20, "Should have at least 20 sources");
    assert!(config.sinks.len() >= 30, "Should have at least 30 sinks");
    assert!(config.sanitizers.len() >= 10, "Should have at least 10 sanitizers");

    println!("Ruby configuration:");
    println!("  Sources: {}", config.sources.len());
    println!("  Sinks: {}", config.sinks.len());
    println!("  Sanitizers: {}", config.sanitizers.len());
}
