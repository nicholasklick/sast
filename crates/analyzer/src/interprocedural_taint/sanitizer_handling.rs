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
    "basename", "secure_filename", "file_name",  // Rust's equivalent of basename
    "filepath.Base", "path.Base",  // Go's path/filepath.Base functions
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
        || name_lower.contains("file_name")  // Rust's Path::file_name()
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

// =============================================================================
// Impl block methods for InterproceduralTaintAnalysis
// =============================================================================

use super::InterproceduralTaintAnalysis;
use crate::taint_config::get_yaml_sanitizer_flow_states;

impl InterproceduralTaintAnalysis {
    /// Check if a function/method is a sanitizer
    pub(super) fn is_sanitizer_function(&self, name: &str) -> bool {
        // Check flow registry first
        if let Some(summary) = self.flow_registry.get(name) {
            if summary.is_sanitizer {
                return true;
            }
        }
        // Also check by just the method name
        let method_name = name.split('.').last().unwrap_or(name);
        if let Some(summary) = self.flow_registry.get(method_name) {
            if summary.is_sanitizer {
                return true;
            }
        }

        // Fall back to legacy sanitizers
        let name_lower = name.to_lowercase();
        self.sanitizers.iter().any(|s| {
            let sanitizer_lower = s.to_lowercase();
            name_lower.contains(&sanitizer_lower)
        })
    }

    /// Get the FlowStates that a sanitizer function is effective for.
    /// Returns None if not a sanitizer, Some(empty) for universal sanitizers,
    /// or Some(states) for context-specific sanitizers.
    pub(super) fn get_sanitizer_flow_states(&self, name: &str) -> Option<HashSet<FlowState>> {
        let name_lower = name.to_lowercase();

        // HTML/XSS sanitizers
        if name_lower.contains("escapehtml") || name_lower.contains("htmlescape")
            || name_lower.contains("htmlspecialchars") || name_lower.contains("htmlentities")
            || name_lower.contains("encodeforhtml") || name_lower.contains("sanitizehtml")
            || (name_lower.contains("escape") && name_lower.contains("html"))
        {
            let mut states = HashSet::new();
            states.insert(FlowState::Html);
            return Some(states);
        }

        // SQL sanitizers
        if name_lower.contains("escapesql") || name_lower.contains("encodeforsql")
            || name_lower.contains("sanitizesql") || name_lower.contains("quotesql")
            || name_lower.contains("preparedstatement.set")
        {
            let mut states = HashSet::new();
            states.insert(FlowState::Sql);
            return Some(states);
        }

        // Command/Shell sanitizers
        if name_lower.contains("escapeshell") || name_lower.contains("shellwords")
            || name_lower.contains("escapejava") || name_lower.contains("encodeforcommand")
            || name_lower.contains("processbuilder")
        {
            let mut states = HashSet::new();
            states.insert(FlowState::Shell);
            return Some(states);
        }

        // Path traversal sanitizers
        if name_lower.contains("canonicalpath") || name_lower.contains("normalize")
            || name_lower.contains("realpath") || name_lower.contains("escapepath")
            || name_lower.contains("file_name") || name_lower.contains("basename")
            || name_lower.contains("filepath.base") || name_lower.contains("path.base")  // Go's filepath.Base/path.Base
        {
            let mut states = HashSet::new();
            states.insert(FlowState::Path);
            return Some(states);
        }

        // LDAP sanitizers
        if name_lower.contains("escapeldap") || name_lower.contains("encodeforldn")
            || name_lower.contains("encodefordistinguishedname")
            || name_lower.contains("escape_filter") || name_lower.contains("escapefilter")
            || name_lower.contains("ldap_escape") || name_lower.contains("ldapescape")
        {
            let mut states = HashSet::new();
            states.insert(FlowState::Ldap);
            return Some(states);
        }

        // XML/XPath sanitizers
        if name_lower.contains("escapexml") || name_lower.contains("encodeforxml")
            || name_lower.contains("escapexpath")
        {
            let mut states = HashSet::new();
            states.insert(FlowState::Xml);
            return Some(states);
        }

        // Type conversion functions are universal sanitizers
        if name_lower.contains("parseint") || name_lower.contains("parselong")
            || name_lower.contains("parsedouble") || name_lower.contains("parsefloat")
            || name_lower.contains("parseboolean")
            || name_lower == "int" || name_lower == "float" || name_lower == "long" || name_lower == "double"
            || name_lower.contains("atoi") || name_lower.contains("atol") || name_lower.contains("atof")
            || name_lower == "number" || name_lower == "boolean"
            || name_lower == "to_i" || name_lower == "to_f" || name_lower == "to_s"
            || name_lower.contains("strconv.atoi") || name_lower.contains("strconv.parseint")
            || name_lower.contains("strconv.parsefloat") || name_lower.contains("strconv.parsebool")
            || name_lower.contains("valueof")
        {
            return Some(HashSet::new());
        }

        // Universal sanitizers (validation, encoding)
        if name_lower.contains("validate") || name_lower.contains("isvalid")
            || name_lower.contains("whitelist") || name_lower.contains("allowlist")
        {
            return Some(HashSet::new());
        }

        // Check if it's a sanitizer via is_sanitizer_function
        if self.is_sanitizer_function(name) {
            return Some(HashSet::new());
        }

        // Check YAML config
        if let Some(states) = get_yaml_sanitizer_flow_states(self.language_handler.language(), name) {
            return Some(states);
        }

        None
    }

    /// Check if a .replace() call is a quote escaping pattern
    pub(super) fn is_quote_escaping_pattern_method(&self, node: &AstNode) -> bool {
        is_quote_escaping_pattern(node)
    }
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
