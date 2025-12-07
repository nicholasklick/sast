//! Language-specific query modules
//!
//! Each language has its own module defining queries with patterns specific to that language.
//! Universal queries that work across all languages are in `universal.rs`.

pub mod universal;
pub mod java;
pub mod python;
pub mod javascript;
pub mod ruby;

use crate::ast::Query;
use crate::metadata::QueryMetadata;

/// A query definition with its metadata
pub struct QueryDefinition {
    pub id: &'static str,
    pub query: Query,
    pub metadata: QueryMetadata,
}

/// Trait for language-specific query providers
pub trait LanguageQueries {
    /// Returns the language name (e.g., "java", "python")
    fn language() -> &'static str;

    /// Returns all queries for this language
    fn queries() -> Vec<QueryDefinition>;
}

/// Get all queries for a specific language
pub fn get_queries_for_language(language: &str) -> Vec<QueryDefinition> {
    let mut queries = Vec::new();

    // Always include universal queries
    queries.extend(universal::UniversalQueries::queries());

    // Add language-specific queries
    match language.to_lowercase().as_str() {
        "java" => queries.extend(java::JavaQueries::queries()),
        "python" => queries.extend(python::PythonQueries::queries()),
        "javascript" | "typescript" => queries.extend(javascript::JavaScriptQueries::queries()),
        "ruby" => queries.extend(ruby::RubyQueries::queries()),
        _ => {} // Unknown language gets only universal queries
    }

    queries
}

/// Get all queries across all languages (for backwards compatibility)
pub fn get_all_queries() -> Vec<QueryDefinition> {
    let mut queries = Vec::new();

    queries.extend(universal::UniversalQueries::queries());
    queries.extend(java::JavaQueries::queries());
    queries.extend(python::PythonQueries::queries());
    queries.extend(javascript::JavaScriptQueries::queries());
    queries.extend(ruby::RubyQueries::queries());

    queries
}
