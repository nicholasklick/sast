//! JavaScript/TypeScript-specific security queries
//!
//! Patterns specific to JavaScript/TypeScript frameworks and APIs:
//! - DOM manipulation (innerHTML, document.write)
//! - Node.js APIs (child_process, fs)
//! - React, Angular, Vue framework patterns
//! - Express.js web framework

use super::{QueryDefinition, LanguageQueries};
use crate::ast::{Query, FromClause, WhereClause, SelectClause, SelectItem, Predicate, Expression, EntityType, ComparisonOp};
use crate::metadata::{QueryMetadata, QueryCategory, QuerySeverity, QueryPrecision};

pub struct JavaScriptQueries;

impl LanguageQueries for JavaScriptQueries {
    fn language() -> &'static str {
        "javascript"
    }

    fn queries() -> Vec<QueryDefinition> {
        vec![
            Self::sql_injection_query(),
            Self::command_injection_query(),
            Self::path_traversal_query(),
            Self::dom_xss_query(),
            Self::unsafe_innerhtml_query(),
            Self::document_write_xss_query(),
            Self::react_dangerous_html_query(),
            Self::code_injection_query(),
            Self::ssrf_query(),
            Self::insecure_deserialization_query(),
            Self::weak_cipher_query(),
        ]
    }
}

impl JavaScriptQueries {
    /// SQL Injection via database clients
    fn sql_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/sql-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // JS database patterns: mysql, pg, sequelize, knex
                        value: r"(?i)(query|execute|raw|knex\.raw|sequelize\.query)".to_string(),
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
            metadata: QueryMetadata::builder("js/sql-injection", "SQL Injection")
                .description("Detects SQL injection in JavaScript/TypeScript database code")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![89])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// Command Injection via child_process
    fn command_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/command-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Node.js command execution
                        value: r"(?i)(exec|execSync|spawn|spawnSync|execFile|execFileSync|fork)".to_string(),
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
            metadata: QueryMetadata::builder("js/command-injection", "Command Injection")
                .description("Detects OS command injection in Node.js")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![78])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// Path Traversal via fs operations
    fn path_traversal_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/path-traversal",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Node.js file operations
                        value: r"(?i)(readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|sendFile|download)".to_string(),
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
            metadata: QueryMetadata::builder("js/path-traversal", "Path Traversal")
                .description("Detects path traversal in Node.js file operations")
                .category(QueryCategory::PathTraversal)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![22])
                .owasp("A01:2021 - Broken Access Control")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// DOM-based XSS
    fn dom_xss_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/dom-xss",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // DOM XSS sinks
                        value: r"(?i)(innerHTML|outerHTML|insertAdjacentHTML|document\.write|document\.writeln)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "DOM-based XSS - untrusted data in DOM manipulation".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("js/dom-xss", "DOM-based XSS")
                .description("Detects DOM-based cross-site scripting")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// Unsafe innerHTML assignment
    fn unsafe_innerhtml_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/unsafe-innerhtml",
            query: Query::new(
                FromClause::new(EntityType::Assignment, "a".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::Comparison {
                        left: Expression::PropertyAccess {
                            object: Box::new(Expression::Variable("a".to_string())),
                            property: "left".to_string(),
                        },
                        operator: ComparisonOp::Matches,
                        right: Expression::String(r"(?i)innerHTML".to_string()),
                    },
                    Predicate::FunctionCall {
                        variable: "a".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "a".to_string(),
                    message: "Unsafe innerHTML - untrusted data assigned to innerHTML".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("js/unsafe-innerhtml", "Unsafe innerHTML")
                .description("Detects dangerous innerHTML assignments with untrusted data")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// document.write XSS
    fn document_write_xss_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/document-write-xss",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        value: r"(?i)(document\.write|document\.writeln)".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "document.write XSS - untrusted data in document.write".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("js/document-write-xss", "document.write XSS")
                .description("Detects XSS via document.write()")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// React dangerouslySetInnerHTML
    fn react_dangerous_html_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/react-dangerous-html",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        value: r"(?i)dangerouslySetInnerHTML".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "React XSS - untrusted data in dangerouslySetInnerHTML".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("js/react-dangerous-html", "React dangerouslySetInnerHTML")
                .description("Detects XSS via React's dangerouslySetInnerHTML")
                .category(QueryCategory::Xss)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![79])
                .owasp("A03:2021 - Injection")
                .tags(vec!["react".to_string()])
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// Code Injection via eval/Function
    fn code_injection_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/code-injection",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // JavaScript code execution
                        value: r"(?i)\b(eval|Function|setTimeout|setInterval)\b".to_string(),
                    },
                    Predicate::FunctionCall {
                        variable: "mc".to_string(),
                        function: "isTainted".to_string(),
                        arguments: Vec::new(),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "mc".to_string(),
                    message: "Code injection - untrusted data in eval/Function".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("js/code-injection", "Code Injection")
                .description("Detects code injection via eval/Function in JavaScript")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![94, 95])
                .owasp("A03:2021 - Injection")
                .sans_top_25()
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// SSRF via HTTP clients
    fn ssrf_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/ssrf",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // Node.js HTTP clients - fetch, axios, http.request, etc.
                        value: r"(?i)\b(fetch|axios|request|http\.request|https\.request|got|superagent)\b".to_string(),
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
            metadata: QueryMetadata::builder("js/ssrf", "Server-Side Request Forgery")
                .description("Detects SSRF in Node.js HTTP requests")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![918])
                .owasp("A10:2021 - Server-Side Request Forgery")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// Insecure Deserialization
    fn insecure_deserialization_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/insecure-deserialization",
            query: Query::new(
                FromClause::new(EntityType::MethodCall, "mc".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::MethodName {
                        variable: "mc".to_string(),
                        operator: ComparisonOp::Matches,
                        // JS deserialization - serialize-javascript, node-serialize, etc.
                        value: r"(?i)(\bdeserialize\b|\bunserialize\b|node-serialize|serialize-javascript|js-yaml\.load)".to_string(),
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
            metadata: QueryMetadata::builder("js/insecure-deserialization", "Insecure Deserialization")
                .description("Detects insecure deserialization in JavaScript")
                .category(QueryCategory::Injection)
                .severity(QuerySeverity::Critical)
                .precision(QueryPrecision::High)
                .cwes(vec![502])
                .owasp("A08:2021 - Software and Data Integrity Failures")
                .uses_taint()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }

    /// Weak Cipher
    fn weak_cipher_query() -> QueryDefinition {
        QueryDefinition {
            id: "js/weak-cipher",
            query: Query::new(
                FromClause::new(EntityType::CallExpression, "call".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::Comparison {
                        left: Expression::PropertyAccess {
                            object: Box::new(Expression::Variable("call".to_string())),
                            property: "text".to_string(),
                        },
                        operator: ComparisonOp::Matches,
                        // Weak ciphers with word boundaries to avoid false positives
                        right: Expression::String(r"(?i)(\bdes\b|\brc4\b|\brc2\b|blowfish|createCipher\()".to_string()),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "call".to_string(),
                    message: "Weak cipher algorithm - use AES-256-GCM or stronger".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("js/weak-cipher", "Weak Cipher Algorithm")
                .description("Detects use of weak encryption algorithms (DES, RC4, RC2, Blowfish)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::High)
                .cwes(vec![327, 326])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .languages(vec!["javascript".to_string(), "typescript".to_string()])
                .build(),
        }
    }
}
