//! Sanitizer Handling for Taint Analysis
//!
//! Provides detection and flow-state-aware sanitization for taint analysis.
//! Sanitizers are functions that remove or neutralize tainted data for specific contexts.

use std::collections::HashSet;
use crate::taint::FlowState;
use gittera_parser::ast::AstNode;

/// Common sanitizer patterns for different languages
pub static UNIVERSAL_SANITIZERS: &[&str] = &[
    "escape", "sanitize", "validate", "filter", "clean", "purify",
    "encode", "htmlspecialchars", "strip_tags", "addslashes",
];

/// SQL-specific sanitizers
pub static SQL_SANITIZERS: &[&str] = &[
    "escape_string", "real_escape_string", "quote_identifier",
    "prepared_statement", "parameterize", "bind_param",
];

/// HTML/XSS-specific sanitizers
pub static HTML_SANITIZERS: &[&str] = &[
    "escapeHtml", "encodeForHTML", "htmlEscape", "HtmlUtils.htmlEscape",
    "StringEscapeUtils.escapeHtml", "Encode.forHtml", "Encode.forJavaScript",
    "bleach.clean", "DOMPurify.sanitize",
];

/// Command injection sanitizers
pub static COMMAND_SANITIZERS: &[&str] = &[
    "escapeshellarg", "escapeshellcmd", "shlex.quote",
];

/// Path traversal sanitizers
pub static PATH_SANITIZERS: &[&str] = &[
    "realpath", "canonical", "normalize", "getCanonicalPath",
    "basename", "secure_filename",
];

/// Check if a function name matches a sanitizer pattern
pub fn is_sanitizer_name(name: &str) -> bool {
    let name_lower = name.to_lowercase();

    // Check universal patterns
    for pattern in UNIVERSAL_SANITIZERS {
        if name_lower.contains(pattern) {
            return true;
        }
    }

    // Check SQL patterns
    for pattern in SQL_SANITIZERS {
        if name_lower.contains(&pattern.to_lowercase()) {
            return true;
        }
    }

    // Check HTML patterns
    for pattern in HTML_SANITIZERS {
        if name_lower.contains(&pattern.to_lowercase()) {
            return true;
        }
    }

    // Check command patterns
    for pattern in COMMAND_SANITIZERS {
        if name_lower.contains(&pattern.to_lowercase()) {
            return true;
        }
    }

    // Check path patterns
    for pattern in PATH_SANITIZERS {
        if name_lower.contains(&pattern.to_lowercase()) {
            return true;
        }
    }

    false
}

/// Get the flow states that a sanitizer is effective against
pub fn get_sanitizer_flow_states(name: &str) -> Option<HashSet<FlowState>> {
    let name_lower = name.to_lowercase();

    // HTML/XSS sanitizers
    if name_lower.contains("html")
        || name_lower.contains("xss")
        || name_lower.contains("forhtml")
        || name_lower.contains("forjavascript")
        || name_lower.contains("dompurify")
        || name_lower.contains("bleach")
    {
        let mut states = HashSet::new();
        states.insert(FlowState::Html);
        return Some(states);
    }

    // SQL sanitizers
    if name_lower.contains("sql")
        || name_lower.contains("escape_string")
        || name_lower.contains("quote")
        || name_lower.contains("parameterize")
        || name_lower.contains("bind")
    {
        let mut states = HashSet::new();
        states.insert(FlowState::Sql);
        return Some(states);
    }

    // Command sanitizers
    if name_lower.contains("shell")
        || name_lower.contains("shlex")
        || name_lower.contains("cmd")
    {
        let mut states = HashSet::new();
        states.insert(FlowState::Shell);
        return Some(states);
    }

    // Path sanitizers
    if name_lower.contains("path")
        || name_lower.contains("realpath")
        || name_lower.contains("canonical")
        || name_lower.contains("basename")
    {
        let mut states = HashSet::new();
        states.insert(FlowState::Path);
        return Some(states);
    }

    // Universal sanitizers sanitize all states
    for pattern in UNIVERSAL_SANITIZERS {
        if name_lower.contains(pattern) {
            let mut states = HashSet::new();
            states.insert(FlowState::Generic);
            states.insert(FlowState::Sql);
            states.insert(FlowState::Html);
            states.insert(FlowState::Shell);
            states.insert(FlowState::Path);
            return Some(states);
        }
    }

    None
}

/// Check if a node represents quote escaping (e.g., replacing ' with '')
pub fn is_quote_escaping_pattern(node: &AstNode) -> bool {
    let text = &node.text;

    // Common patterns for quote escaping
    let patterns = [
        ".replace(\"'\", \"''\")",
        ".replace('\"', '\\\\\"')",
        ".replaceAll(\"'\", \"''\")",
        ".replaceAll(\"'\", \"\\\\'\")",
        "str_replace(\"'\", \"''\"",
        "str_replace('\"', '\\\\\"'",
    ];

    for pattern in &patterns {
        if text.contains(pattern) {
            return true;
        }
    }

    false
}

/// Check if a condition validates input and the branch returns safely
pub fn detect_validation_guard(condition: &AstNode, _then_branch: &AstNode) -> Option<String> {
    // Look for common validation patterns in conditions
    let text = &condition.text;

    // Pattern: if (input.isEmpty() || input.isBlank())
    if text.contains("isEmpty") || text.contains("isBlank") || text.contains("length == 0") {
        return Some("empty-check".to_string());
    }

    // Pattern: if (input == null)
    if text.contains("== null") || text.contains("=== null") || text.contains("is None") {
        return Some("null-check".to_string());
    }

    // Pattern: if (input.matches(pattern)) - regex validation
    if text.contains("matches(") || text.contains("Pattern.") || text.contains("re.match") {
        return Some("regex-validation".to_string());
    }

    // Pattern: if (isValid(input))
    if text.contains("isValid") || text.contains("validate") {
        return Some("validation-function".to_string());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_sanitizer_name() {
        assert!(is_sanitizer_name("escapeHtml"));
        assert!(is_sanitizer_name("sanitizeInput"));
        assert!(is_sanitizer_name("validateUser"));
        assert!(is_sanitizer_name("mysql_real_escape_string"));
        assert!(!is_sanitizer_name("getUserInput"));
        assert!(!is_sanitizer_name("processData"));
    }

    #[test]
    fn test_get_sanitizer_flow_states() {
        let html_states = get_sanitizer_flow_states("escapeHtml").unwrap();
        assert!(html_states.contains(&FlowState::Html));
        assert!(!html_states.contains(&FlowState::Sql));

        let sql_states = get_sanitizer_flow_states("escape_string").unwrap();
        assert!(sql_states.contains(&FlowState::Sql));

        let universal_states = get_sanitizer_flow_states("sanitize").unwrap();
        assert!(universal_states.contains(&FlowState::Html));
        assert!(universal_states.contains(&FlowState::Sql));
        assert!(universal_states.contains(&FlowState::Shell));
    }
}
