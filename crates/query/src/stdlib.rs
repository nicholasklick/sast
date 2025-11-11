//! Standard library of built-in security queries

use crate::ast::*;

pub struct StandardLibrary;

impl StandardLibrary {
    /// Get all built-in queries for OWASP Top 10
    pub fn owasp_queries() -> Vec<(&'static str, Query)> {
        vec![
            ("sql-injection", Self::sql_injection_query()),
            ("command-injection", Self::command_injection_query()),
            ("xss", Self::xss_query()),
            ("path-traversal", Self::path_traversal_query()),
            ("hardcoded-secrets", Self::hardcoded_secrets_query()),
            ("insecure-deserialization", Self::insecure_deserialization_query()),
            ("xxe", Self::xxe_query()),
            ("ssrf", Self::ssrf_query()),
            ("weak-crypto", Self::weak_crypto_query()),
            ("ldap-injection", Self::ldap_injection_query()),
            ("unsafe-redirect", Self::unsafe_redirect_query()),
            ("server-side-template-injection", Self::template_injection_query()),
        ]
    }

    pub fn sql_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![Predicate::MethodName {
                variable: "mc".to_string(),
                operator: ComparisonOp::Equal,
                value: "execute".to_string(),
            }])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Potential SQL injection vulnerability".to_string(),
            }]),
        )
    }

    pub fn command_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![Predicate::MethodName {
                variable: "mc".to_string(),
                operator: ComparisonOp::Equal,
                value: "exec".to_string(),
            }])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Potential command injection vulnerability".to_string(),
            }]),
        )
    }

    pub fn xss_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            Some(WhereClause::new(vec![Predicate::MethodName {
                variable: "mc".to_string(),
                operator: ComparisonOp::Equal,
                value: "innerHTML".to_string(),
            }])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "mc".to_string(),
                message: "Potential XSS vulnerability".to_string(),
            }]),
        )
    }

    /// Path traversal detection - looks for file operations with ".." patterns
    pub fn path_traversal_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("readFile|writeFile|open|require|import|fs\\.".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential path traversal - file operation may access arbitrary files".to_string(),
            }]),
        )
    }

    /// Hardcoded secrets detection - looks for variables with sensitive names
    pub fn hardcoded_secrets_query() -> Query {
        Query::new(
            FromClause::new(EntityType::VariableDeclaration, "vd".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("vd".to_string())),
                        property: "name".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(password|passwd|pwd|secret|api[_-]?key|apikey|token|auth|credential|private[_-]?key)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "vd".to_string(),
                message: "Potential hardcoded secret - sensitive data should not be in source code".to_string(),
            }]),
        )
    }

    /// Insecure deserialization - detects unsafe deserialization functions
    pub fn insecure_deserialization_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(pickle\\.loads|yaml\\.unsafe_load|unserialize|eval|deserialize|fromJson|readObject)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Insecure deserialization - untrusted data deserialization can lead to RCE".to_string(),
            }]),
        )
    }

    /// XXE (XML External Entity) detection
    pub fn xxe_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(parseXml|parse|xml\\.parse|XMLParser|DocumentBuilder)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential XXE vulnerability - XML parser may be vulnerable to entity expansion attacks".to_string(),
            }]),
        )
    }

    /// SSRF (Server-Side Request Forgery) detection
    pub fn ssrf_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(fetch|axios|request|http\\.get|http\\.post|urllib|requests\\.get|curl)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential SSRF - HTTP request with user-controlled URL can access internal resources".to_string(),
            }]),
        )
    }

    /// Weak cryptography detection
    pub fn weak_crypto_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(md5|sha1|des|rc4|ecb|cbc|DES|MD5|SHA1)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Weak cryptography - using deprecated or weak cryptographic algorithms".to_string(),
            }]),
        )
    }

    /// LDAP injection detection
    pub fn ldap_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(ldap\\.search|searchLdap|LdapContext)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential LDAP injection - unsanitized input in LDAP queries".to_string(),
            }]),
        )
    }

    /// Unsafe redirect detection
    pub fn unsafe_redirect_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(redirect|sendRedirect|setHeader.*Location)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Unvalidated redirect - user-controlled redirect can lead to phishing".to_string(),
            }]),
        )
    }

    /// Server-side template injection detection
    pub fn template_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::CallExpression, "call".to_string()),
            Some(WhereClause::new(vec![
                Predicate::Comparison {
                    left: Expression::PropertyAccess {
                        object: Box::new(Expression::Variable("call".to_string())),
                        property: "callee".to_string(),
                    },
                    operator: ComparisonOp::Matches,
                    right: Expression::String("(?i)(render|compile|template\\.render|ejs\\.render|pug\\.render|handlebars)".to_string()),
                },
            ])),
            SelectClause::new(vec![SelectItem::Both {
                variable: "call".to_string(),
                message: "Potential template injection - user input in templates can lead to RCE".to_string(),
            }]),
        )
    }
}
