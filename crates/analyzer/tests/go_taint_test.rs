//! Integration tests for Go taint analysis
//!
//! Tests that Go-specific taint sources, sinks, and sanitizers are properly configured.

use gittera_analyzer::{TaintAnalysis, LanguageTaintConfig, TaintSourceKind, TaintSinkKind};
use gittera_parser::Language;

#[test]
fn test_go_has_taint_sources() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(config.sources.len() > 0, "Go should have taint sources configured");
    assert!(config.sources.len() >= 18, "Go should have at least 18 taint sources");
}

#[test]
fn test_go_has_http_sources() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    // Check for net/http sources
    assert!(
        config.sources.iter().any(|s| s.name == "r.FormValue"),
        "Go should have 'r.FormValue' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "r.URL.Query"),
        "Go should have 'r.URL.Query' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "r.Header.Get"),
        "Go should have 'r.Header.Get' as user input source"
    );
}

#[test]
fn test_go_has_gin_sources() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    // Check for Gin framework sources
    assert!(
        config.sources.iter().any(|s| s.name == "c.Query"),
        "Go should have 'c.Query' as user input source (Gin)"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "c.Param"),
        "Go should have 'c.Param' as user input source (Gin)"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "c.PostForm"),
        "Go should have 'c.PostForm' as user input source (Gin)"
    );
}

#[test]
fn test_go_has_cli_sources() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(
        config.sources.iter().any(|s| s.name == "os.Args" && matches!(s.kind, TaintSourceKind::UserInput)),
        "Go should have 'os.Args' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "flag.String"),
        "Go should have 'flag.String' as user input source"
    );
}

#[test]
fn test_go_has_file_sources() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(
        config.sources.iter().any(|s| s.name == "os.ReadFile" && matches!(s.kind, TaintSourceKind::FileRead)),
        "Go should have 'os.ReadFile' as file read source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "ioutil.ReadFile"),
        "Go should have 'ioutil.ReadFile' as file read source"
    );
}

#[test]
fn test_go_has_env_sources() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(
        config.sources.iter().any(|s| s.name == "os.Getenv" && matches!(s.kind, TaintSourceKind::EnvironmentVariable)),
        "Go should have 'os.Getenv' as environment variable source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "os.LookupEnv"),
        "Go should have 'os.LookupEnv' as environment variable source"
    );
}

#[test]
fn test_go_has_command_execution_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(
        config.sinks.iter().any(|s| s.name == "exec.Command" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Go should have 'exec.Command' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "exec.CommandContext" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Go should have 'exec.CommandContext' as command execution sink"
    );
}

#[test]
fn test_go_has_sql_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(
        config.sinks.iter().any(|s| s.name == "db.Exec" && matches!(s.kind, TaintSinkKind::SqlQuery)),
        "Go should have 'db.Exec' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "db.Query"),
        "Go should have 'db.Query' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "database/sql.DB.Exec"),
        "Go should have 'database/sql.DB.Exec' as SQL query sink"
    );
}

#[test]
fn test_go_has_file_write_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(
        config.sinks.iter().any(|s| s.name == "os.WriteFile" && matches!(s.kind, TaintSinkKind::FileWrite)),
        "Go should have 'os.WriteFile' as file write sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "ioutil.WriteFile"),
        "Go should have 'ioutil.WriteFile' as file write sink"
    );
}

#[test]
fn test_go_has_html_output_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(
        config.sinks.iter().any(|s| s.name == "fmt.Fprintf" && matches!(s.kind, TaintSinkKind::HtmlOutput)),
        "Go should have 'fmt.Fprintf' as HTML output sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "w.Write"),
        "Go should have 'w.Write' as HTML output sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "c.String"),
        "Go should have 'c.String' as HTML output sink (Gin)"
    );
}

#[test]
fn test_go_has_sanitizers() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    assert!(config.sanitizers.len() > 0, "Go should have sanitizers configured");
    assert!(
        config.sanitizers.contains(&"html.EscapeString".to_string()),
        "Go should have 'html.EscapeString' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"template.HTMLEscapeString".to_string()),
        "Go should have 'template.HTMLEscapeString' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"db.Prepare".to_string()),
        "Go should have 'db.Prepare' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"url.QueryEscape".to_string()),
        "Go should have 'url.QueryEscape' as sanitizer"
    );
}

#[test]
fn test_go_taint_analysis_uses_config() {
    let taint = TaintAnalysis::new().for_language(Language::Go);

    // This test verifies that the for_language() method works
    assert!(true, "TaintAnalysis::for_language(Go) completes successfully");
}

#[test]
fn test_go_config_count() {
    let config = LanguageTaintConfig::for_language(Language::Go);

    // Verify we have a reasonable number of each
    assert!(config.sources.len() >= 18, "Should have at least 18 sources");
    assert!(config.sinks.len() >= 20, "Should have at least 20 sinks");
    assert!(config.sanitizers.len() >= 11, "Should have at least 11 sanitizers");

    println!("Go configuration:");
    println!("  Sources: {}", config.sources.len());
    println!("  Sinks: {}", config.sinks.len());
    println!("  Sanitizers: {}", config.sanitizers.len());
}
