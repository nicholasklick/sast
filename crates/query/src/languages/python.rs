//! Python-specific security queries
//!
//! Patterns specific to Python frameworks and APIs:
//! - Flask, Django web frameworks
//! - subprocess, os.system for command execution
//! - pickle, yaml for deserialization
//! - hashlib for cryptography

use super::{QueryDefinition, LanguageQueries};
use crate::ast::{Query, FromClause, WhereClause, SelectClause, SelectItem, Predicate, EntityType, ComparisonOp};
use crate::metadata::{QueryMetadata, QueryCategory, QuerySeverity, QueryPrecision};

pub struct PythonQueries;

impl LanguageQueries for PythonQueries {
    fn language() -> &'static str {
        "python"
    }

    fn queries() -> Vec<QueryDefinition> {
        vec![
            Self::sql_injection_query(),
            Self::command_injection_query(),
            Self::path_traversal_query(),
            Self::xss_query(),
            Self::code_injection_query(),
            Self::insecure_deserialization_query(),
            Self::ssrf_query(),
        ]
    }
}

impl PythonQueries {
    /// SQL Injection via Python DB APIs
    /// Detects: cursor.execute(), raw SQL in Django/SQLAlchemy
    fn sql_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "python/sql-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Python DB-API patterns
                        value: r"(?i)(execute|executemany|executescript|raw|RawSQL)".to_string(),
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
            metadata: QueryMetadata::builder("python/sql-injection", "SQL Injection")
                .description("Detects SQL injection in Python database code")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![89])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["python".to_string()])
                .build(),
        }
    }

    /// Command Injection via subprocess/os
    fn command_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "python/command-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Python subprocess/os patterns
                        value: r"(?i)(subprocess\.(call|run|Popen|check_output|check_call)|os\.(system|popen|spawn)|commands\.(getoutput|getstatusoutput))".to_string(),
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
            metadata: QueryMetadata::builder("python/command-injection", "Command Injection")
                .description("Detects OS command injection in Python")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![78])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["python".to_string()])
                .build(),
        }
    }

    /// Path Traversal via file operations
    fn path_traversal_query() -> QueryDefinition {
        QueryDefinition {
            id: "python/path-traversal",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Python file operations
                        value: r"(?i)(open|read|write|send_file|send_from_directory|safe_join)".to_string(),
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
            metadata: QueryMetadata::builder("python/path-traversal", "Path Traversal")
                .description("Detects path traversal in Python file operations")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![22])
                .owasp("A01:2021 - Broken Access Control")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["python".to_string()])
                .build(),
        }
    }

    /// XSS via Flask/Django response
    fn xss_query() -> QueryDefinition {
        QueryDefinition {
            id: "python/xss",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Python web framework response methods
                        value: r"(?i)(render_template_string|Markup|mark_safe|format_html|Response)".to_string(),
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
            metadata: QueryMetadata::builder("python/xss", "Cross-Site Scripting")
                .description("Detects XSS in Python web framework responses")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["python".to_string()])
                .build(),
        }
    }

    /// Code Injection via eval/exec
    fn code_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "python/code-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Python code execution
                        value: r"(?i)\b(eval|exec|compile)\b".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Code injection - untrusted data in eval/exec".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("python/code-injection", "Code Injection")
                .description("Detects code injection via eval/exec in Python")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![94, 95])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["python".to_string()])
                .build(),
        }
    }

    /// Insecure Deserialization via pickle/yaml
    fn insecure_deserialization_query() -> QueryDefinition {
        QueryDefinition {
            id: "python/insecure-deserialization",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Python deserialization - pickle.loads, yaml.load (unsafe), etc.
                        value: r"(?i)(pickle\.loads?|yaml\.load|yaml\.unsafe_load|marshal\.loads?|shelve\.open)".to_string(),
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
            metadata: QueryMetadata::builder("python/insecure-deserialization", "Insecure Deserialization")
                .description("Detects insecure deserialization in Python (pickle, yaml)")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![502])
                .owasp("A08:2021 - Software and Data Integrity Failures")
                .uses_taint()
                .languages(vec!["python".to_string()])
                .build(),
        }
    }

    /// SSRF via requests/urllib
    fn ssrf_query() -> QueryDefinition {
        QueryDefinition {
            id: "python/ssrf",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Python HTTP client patterns
                        value: r"(?i)(requests\.(get|post|put|delete|patch|head|options)|urllib\.request\.urlopen|urlopen|http\.client\.(HTTPConnection|HTTPSConnection))".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Server-side request forgery (SSRF) - untrusted URL".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("python/ssrf", "Server-Side Request Forgery")
                .description("Detects SSRF in Python HTTP requests")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![918])
                .owasp("A10:2021 - Server-Side Request Forgery")
                .uses_taint()
                .languages(vec!["python".to_string()])
                .build(),
        }
    }
}
