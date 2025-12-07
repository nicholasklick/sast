//! Java-specific security queries
//!
//! Patterns specific to Java frameworks and APIs:
//! - Servlet API (HttpServletRequest, HttpServletResponse)
//! - JDBC (PreparedStatement, Statement)
//! - Java crypto APIs (MessageDigest, Cipher)

use super::{QueryDefinition, LanguageQueries};
use crate::ast::{Query, FromClause, WhereClause, SelectClause, SelectItem, Predicate, EntityType, ComparisonOp};
use crate::metadata::{QueryMetadata, QueryCategory, QuerySeverity, QueryPrecision};

pub struct JavaQueries;

impl LanguageQueries for JavaQueries {
    fn language() -> &'static str {
        "java"
    }

    fn queries() -> Vec<QueryDefinition> {
        vec![
            Self::sql_injection_query(),
            Self::command_injection_query(),
            Self::path_traversal_query(),
            Self::xss_query(),
            Self::ldap_injection_query(),
            Self::xpath_injection_query(),
        ]
    }
}

impl JavaQueries {
    /// SQL Injection via JDBC
    /// Detects: Statement.execute(), Statement.executeQuery() with tainted input
    fn sql_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "java/sql-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Java JDBC patterns
                        value: r"(?i)(executeQuery|executeUpdate|execute|prepareStatement|prepareCall)".to_string(),
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
            metadata: QueryMetadata::builder("java/sql-injection", "SQL Injection")
                .description("Detects SQL injection in Java JDBC code")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![89])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build(),
        }
    }

    /// Command Injection via Runtime/ProcessBuilder
    fn command_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "java/command-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Java Runtime.exec, ProcessBuilder patterns
                        value: r"(?i)(exec|start|command|ProcessBuilder)".to_string(),
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
            metadata: QueryMetadata::builder("java/command-injection", "Command Injection")
                .description("Detects OS command injection in Java")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![78])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build(),
        }
    }

    /// Path Traversal via File APIs
    fn path_traversal_query() -> QueryDefinition {
        QueryDefinition {
            id: "java/path-traversal",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Java file operations
                        value: r"(?i)(FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|File|Paths\.get|Files\.(read|write|copy|move))".to_string(),
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
            metadata: QueryMetadata::builder("java/path-traversal", "Path Traversal")
                .description("Detects path traversal in Java file operations")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![22])
                .owasp("A01:2021 - Broken Access Control")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build(),
        }
    }

    /// XSS via Servlet response
    fn xss_query() -> QueryDefinition {
        QueryDefinition {
            id: "java/xss",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Java Servlet response methods
                        value: r"(?i)(getWriter|getOutputStream|println|print|write)".to_string(),
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
            metadata: QueryMetadata::builder("java/xss", "Cross-Site Scripting")
                .description("Detects XSS in Java Servlet responses")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build(),
        }
    }

    /// LDAP Injection
    fn ldap_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "java/ldap-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Java LDAP operations
                        value: r"(?i)(search|lookup|DirContext)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "LDAP injection - untrusted data in LDAP query".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("java/ldap-injection", "LDAP Injection")
                .description("Detects LDAP injection in Java")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![90])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build(),
        }
    }

    /// XPath Injection
    fn xpath_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "java/xpath-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Java XPath operations
                        value: r"(?i)(evaluate|compile|XPath)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "XPath injection - untrusted data in XPath query".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("java/xpath-injection", "XPath Injection")
                .description("Detects XPath injection in Java")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![643])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["java".to_string()])
                .build(),
        }
    }
}
