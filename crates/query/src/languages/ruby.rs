//! Ruby-specific security queries
//!
//! Patterns specific to Ruby frameworks and APIs:
//! - Rails and Sinatra web frameworks
//! - ActiveRecord for database access
//! - Marshal for serialization
//! - ERB for templating

use super::{QueryDefinition, LanguageQueries};
use crate::ast::{Query, FromClause, WhereClause, SelectClause, SelectItem, Predicate, EntityType, ComparisonOp};
use crate::metadata::{QueryMetadata, QueryCategory, QuerySeverity, QueryPrecision};

pub struct RubyQueries;

impl LanguageQueries for RubyQueries {
    fn language() -> &'static str {
        "ruby"
    }

    fn queries() -> Vec<QueryDefinition> {
        vec![
            Self::sql_injection_query(),
            Self::command_injection_query(),
            Self::path_traversal_query(),
            Self::xss_query(),
            Self::code_injection_query(),
            Self::insecure_deserialization_query(),
            Self::open_redirect_query(),
        ]
    }
}

impl RubyQueries {
    /// SQL Injection via ActiveRecord
    /// Detects: where(), find_by_sql(), execute() with tainted input
    fn sql_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "ruby/sql-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Ruby/Rails database patterns
                        value: r"(?i)(where|find_by_sql|execute|select|from|joins|having|group|order|pluck)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "SQL injection - untrusted data in database query".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("ruby/sql-injection", "SQL Injection")
                .description("Detects SQL injection in Ruby/Rails ActiveRecord code")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![89])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["ruby".to_string()])
                .build(),
        }
    }

    /// Command Injection via system/exec/backticks
    fn command_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "ruby/command-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Ruby command execution
                        value: r"(?i)\b(system|exec|spawn|popen|Open3\.(capture|popen)|Kernel\.system|IO\.popen)\b".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Command injection - untrusted data in system command".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("ruby/command-injection", "Command Injection")
                .description("Detects OS command injection in Ruby")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![78])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["ruby".to_string()])
                .build(),
        }
    }

    /// Path Traversal via File operations
    fn path_traversal_query() -> QueryDefinition {
        QueryDefinition {
            id: "ruby/path-traversal",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Ruby file operations
                        value: r"(?i)(File\.(open|read|write|readlines|new)|send_file|send_data)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Path traversal - untrusted data in file path".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("ruby/path-traversal", "Path Traversal")
                .description("Detects path traversal in Ruby file operations")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![22])
                .owasp("A01:2021 - Broken Access Control")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["ruby".to_string()])
                .build(),
        }
    }

    /// XSS via Rails/Sinatra response
    fn xss_query() -> QueryDefinition {
        QueryDefinition {
            id: "ruby/xss",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Ruby web framework response methods
                        value: r"(?i)(render|html_safe|raw|content_tag|concat)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Cross-site scripting (XSS) - untrusted data in response".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("ruby/xss", "Cross-Site Scripting")
                .description("Detects XSS in Ruby/Rails responses")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["ruby".to_string()])
                .build(),
        }
    }

    /// Code Injection via eval/instance_eval
    fn code_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "ruby/code-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Ruby code execution
                        value: r"(?i)\b(eval|instance_eval|class_eval|module_eval|send|public_send|__send__)\b".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Code injection - untrusted data in eval".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("ruby/code-injection", "Code Injection")
                .description("Detects code injection via eval in Ruby")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![94, 95])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["ruby".to_string()])
                .build(),
        }
    }

    /// Insecure Deserialization via Marshal/YAML
    fn insecure_deserialization_query() -> QueryDefinition {
        QueryDefinition {
            id: "ruby/insecure-deserialization",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Ruby deserialization - Marshal.load, YAML.load (unsafe)
                        value: r"(?i)(Marshal\.load|YAML\.load|YAML\.unsafe_load|Psych\.load)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Insecure deserialization - untrusted data in deserialize".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("ruby/insecure-deserialization", "Insecure Deserialization")
                .description("Detects insecure deserialization in Ruby (Marshal, YAML)")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![502])
                .owasp("A08:2021 - Software and Data Integrity Failures")
                .uses_taint()
                .languages(vec!["ruby".to_string()])
                .build(),
        }
    }

    /// Open Redirect
    fn open_redirect_query() -> QueryDefinition {
        QueryDefinition {
            id: "ruby/open-redirect",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Ruby redirect methods
                        value: r"(?i)\b(redirect_to|redirect)\b".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Open redirect - untrusted data in redirect URL".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("ruby/open-redirect", "Open Redirect")
                .description("Detects open redirect vulnerabilities in Ruby/Rails")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Medium)
                .precision(QueryPrecision::High)
                .cwes(vec![601])
                .owasp("A01:2021 - Broken Access Control")
                .uses_taint()
                .languages(vec!["ruby".to_string()])
                .build(),
        }
    }
}
