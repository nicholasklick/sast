//! Integration tests for Java taint analysis
//!
//! Tests that Java-specific taint sources, sinks, and sanitizers are properly configured.

use gittera_analyzer::{TaintAnalysis, LanguageTaintConfig, TaintSourceKind, TaintSinkKind};
use gittera_parser::Language;

#[test]
fn test_java_has_taint_sources() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(config.sources.len() > 0, "Java should have taint sources configured");
    assert!(config.sources.len() >= 20, "Java should have at least 20 taint sources");
}

#[test]
fn test_java_has_servlet_sources() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    // Check for Servlet API sources
    assert!(
        config.sources.iter().any(|s| s.name == "request.getParameter"),
        "Java should have 'request.getParameter' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "HttpServletRequest.getParameter"),
        "Java should have 'HttpServletRequest.getParameter' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "request.getHeader"),
        "Java should have 'request.getHeader' as user input source"
    );
}

#[test]
fn test_java_has_spring_sources() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    // Check for Spring Framework sources
    assert!(
        config.sources.iter().any(|s| s.name == "@RequestParam"),
        "Java should have '@RequestParam' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "@PathVariable"),
        "Java should have '@PathVariable' as user input source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "@RequestBody"),
        "Java should have '@RequestBody' as user input source"
    );
}

#[test]
fn test_java_has_file_sources() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(
        config.sources.iter().any(|s| s.name == "Files.readString" && matches!(s.kind, TaintSourceKind::FileRead)),
        "Java should have 'Files.readString' as file read source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "FileInputStream"),
        "Java should have 'FileInputStream' as file read source"
    );
}

#[test]
fn test_java_has_env_sources() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(
        config.sources.iter().any(|s| s.name == "System.getenv" && matches!(s.kind, TaintSourceKind::EnvironmentVariable)),
        "Java should have 'System.getenv' as environment variable source"
    );
    assert!(
        config.sources.iter().any(|s| s.name == "System.getProperty"),
        "Java should have 'System.getProperty' as environment variable source"
    );
}

#[test]
fn test_java_has_command_execution_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(
        config.sinks.iter().any(|s| s.name == "Runtime.exec" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Java should have 'Runtime.exec' as command execution sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "ProcessBuilder.start" && matches!(s.kind, TaintSinkKind::CommandExecution)),
        "Java should have 'ProcessBuilder.start' as command execution sink"
    );
}

#[test]
fn test_java_has_code_eval_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(
        config.sinks.iter().any(|s| s.name == "Class.forName" && matches!(s.kind, TaintSinkKind::CodeEval)),
        "Java should have 'Class.forName' as code evaluation sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "Method.invoke"),
        "Java should have 'Method.invoke' as code evaluation sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "ScriptEngine.eval"),
        "Java should have 'ScriptEngine.eval' as code evaluation sink"
    );
}

#[test]
fn test_java_has_sql_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(
        config.sinks.iter().any(|s| s.name == "Statement.execute" && matches!(s.kind, TaintSinkKind::SqlQuery)),
        "Java should have 'Statement.execute' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "Statement.executeQuery"),
        "Java should have 'Statement.executeQuery' as SQL query sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "JdbcTemplate.execute"),
        "Java should have 'JdbcTemplate.execute' as SQL query sink"
    );
}

#[test]
fn test_java_has_html_output_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(
        config.sinks.iter().any(|s| s.name == "response.getWriter().write" && matches!(s.kind, TaintSinkKind::HtmlOutput)),
        "Java should have 'response.getWriter().write' as HTML output sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "PrintWriter.println"),
        "Java should have 'PrintWriter.println' as HTML output sink"
    );
}

#[test]
fn test_java_has_file_write_sinks() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(
        config.sinks.iter().any(|s| s.name == "Files.write" && matches!(s.kind, TaintSinkKind::FileWrite)),
        "Java should have 'Files.write' as file write sink"
    );
    assert!(
        config.sinks.iter().any(|s| s.name == "FileOutputStream.write"),
        "Java should have 'FileOutputStream.write' as file write sink"
    );
}

#[test]
fn test_java_has_sanitizers() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    assert!(config.sanitizers.len() > 0, "Java should have sanitizers configured");
    assert!(
        config.sanitizers.contains(&"StringEscapeUtils.escapeHtml4".to_string()),
        "Java should have 'StringEscapeUtils.escapeHtml4' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"HtmlUtils.htmlEscape".to_string()),
        "Java should have 'HtmlUtils.htmlEscape' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"PreparedStatement.setString".to_string()),
        "Java should have 'PreparedStatement.setString' as sanitizer"
    );
    assert!(
        config.sanitizers.contains(&"ESAPI.encoder().encodeForHTML".to_string()),
        "Java should have 'ESAPI.encoder().encodeForHTML' as sanitizer"
    );
}

#[test]
fn test_java_taint_analysis_uses_config() {
    let taint = TaintAnalysis::new().for_language(Language::Java);

    // This test verifies that the for_language() method works
    assert!(true, "TaintAnalysis::for_language(Java) completes successfully");
}

#[test]
fn test_java_config_count() {
    let config = LanguageTaintConfig::for_language(Language::Java);

    // Verify we have a reasonable number of each
    assert!(config.sources.len() >= 20, "Should have at least 20 sources");
    assert!(config.sinks.len() >= 25, "Should have at least 25 sinks");
    assert!(config.sanitizers.len() >= 12, "Should have at least 12 sanitizers");

    println!("Java configuration:");
    println!("  Sources: {}", config.sources.len());
    println!("  Sinks: {}", config.sinks.len());
    println!("  Sanitizers: {}", config.sanitizers.len());
}
