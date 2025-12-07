//! Universal queries that work across all languages
//!
//! These queries detect patterns that are fundamentally the same across languages,
//! such as weak cryptographic algorithms (MD5, SHA1, DES, RC4).

use super::{QueryDefinition, LanguageQueries};
use crate::ast::{Query, FromClause, WhereClause, SelectClause, SelectItem, Predicate, Expression, EntityType, ComparisonOp};
use crate::metadata::{QueryMetadata, QueryCategory, QuerySeverity, QueryPrecision};

pub struct UniversalQueries;

impl LanguageQueries for UniversalQueries {
    fn language() -> &'static str {
        "universal"
    }

    fn queries() -> Vec<QueryDefinition> {
        vec![
            Self::weak_hash_query(),
        ]
    }
}

impl UniversalQueries {
    /// Detects weak hash algorithms (MD5, SHA1) across all languages
    ///
    /// Patterns detected:
    /// - Java: MessageDigest.getInstance("MD5"), Digest::MD5
    /// - Python: hashlib.md5(), hashlib.sha1(), hashlib.new('md5')
    /// - Ruby: Digest::MD5.hexdigest(), Digest::SHA1.hexdigest()
    /// - JavaScript: crypto.createHash('md5')
    fn weak_hash_query() -> QueryDefinition {
        QueryDefinition {
            id: "universal/weak-hash",
            query: Query::new(
                FromClause::new(EntityType::CallExpression, "call".to_string()),
                Some(WhereClause::new(vec![
                    Predicate::And {
                        left: Box::new(Predicate::Or {
                            // Match function/method names containing MD5 or SHA1
                            left: Box::new(Predicate::Comparison {
                                left: Expression::PropertyAccess {
                                    object: Box::new(Expression::Variable("call".to_string())),
                                    property: "callee".to_string(),
                                },
                                operator: ComparisonOp::Matches,
                                // Match: md5, sha1, sha-1, MD5, SHA1, Digest::MD5, Digest::SHA1
                                right: Expression::String(r"(?i)(\bmd5\b|\bsha-?1\b|Digest::MD5|Digest::SHA1|hashlib\.md5|hashlib\.sha1)".to_string()),
                            }),
                            // OR match calls with MD5/SHA1 as string argument
                            right: Box::new(Predicate::Comparison {
                                left: Expression::PropertyAccess {
                                    object: Box::new(Expression::Variable("call".to_string())),
                                    property: "text".to_string(),
                                },
                                operator: ComparisonOp::Matches,
                                // Match: hashlib.new('md5'), getInstance("MD5"), createHash('sha1')
                                right: Expression::String(r#"(?i)(hashlib\.new.*['"]md5['"]|hashlib\.new.*['"]sha-?1['"]|createHash.*['"]md5['"]|createHash.*['"]sha-?1['"]|getInstance\s*\(\s*['"]MD5['"]|getInstance\s*\(\s*['"]SHA-?1['"])"#.to_string()),
                            }),
                        }),
                        // Exclude SHA1PRNG (secure random number generator, not a hash)
                        right: Box::new(Predicate::Not {
                            predicate: Box::new(Predicate::Comparison {
                                left: Expression::PropertyAccess {
                                    object: Box::new(Expression::Variable("call".to_string())),
                                    property: "text".to_string(),
                                },
                                operator: ComparisonOp::Matches,
                                right: Expression::String(r"(?i)SHA1PRNG".to_string()),
                            }),
                        }),
                    },
                ])),
                SelectClause::new(vec![SelectItem::Both {
                    variable: "call".to_string(),
                    message: "Weak hash algorithm (MD5/SHA1) - use SHA-256 or stronger".to_string(),
                }]),
            ),
            metadata: QueryMetadata::builder("universal/weak-hash", "Weak Hash Algorithm")
                .description("Detects use of weak hash algorithms (MD5, SHA1)")
                .category(QueryCategory::Cryptography)
                .severity(QuerySeverity::High)
                .precision(QueryPrecision::VeryHigh)
                .cwes(vec![328, 327])
                .owasp("A02:2021 - Cryptographic Failures")
                .sans_top_25()
                .build(),
        }
    }
}
