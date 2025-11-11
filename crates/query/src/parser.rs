//! Parser for KQL queries

use crate::ast::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Unexpected token: {0}")]
    UnexpectedToken(String),
    #[error("Expected {0}, found {1}")]
    Expected(String, String),
    #[error("Invalid query syntax: {0}")]
    InvalidSyntax(String),
}

pub struct QueryParser;

impl QueryParser {
    pub fn parse(_source: &str) -> Result<Query, ParseError> {
        // Simple parser implementation - in production would use nom or similar
        // For now, return a stub
        Ok(Query::new(
            FromClause::new(EntityType::MethodCall, "mc".to_string()),
            None,
            SelectClause::new(vec![SelectItem::Variable("mc".to_string())]),
        ))
    }
}
