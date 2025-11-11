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
}
