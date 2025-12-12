//! Query metadata framework for organizing and classifying security queries
//!
//! This module provides comprehensive metadata support for security queries,
//! including CWE mappings, severity levels, categories, and query suites.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// Query severity level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuerySeverity {
    /// Critical security vulnerability
    Critical,
    /// High severity issue
    High,
    /// Medium severity issue
    Medium,
    /// Low severity issue
    Low,
    /// Informational/recommendation
    Info,
}

impl QuerySeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

/// Query precision level (CodeQL-style)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QueryPrecision {
    /// Very high precision, few false positives
    VeryHigh,
    /// High precision
    High,
    /// Medium precision
    Medium,
    /// Low precision, may have false positives
    Low,
}

impl QueryPrecision {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VeryHigh => "very-high",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

/// Query category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QueryCategory {
    /// Injection vulnerabilities (SQL, command, LDAP, etc.)
    Injection,
    /// Cross-site scripting
    Xss,
    /// Authentication and authorization
    Authentication,
    /// Cryptography issues
    Cryptography,
    /// Path traversal and file access
    PathTraversal,
    /// Information disclosure
    InformationDisclosure,
    /// Code quality issues
    CodeQuality,
    /// Resource management
    ResourceManagement,
    /// Error handling
    ErrorHandling,
    /// Concurrency issues
    Concurrency,
    /// Memory safety
    MemorySafety,
    /// Configuration issues
    Configuration,
    /// API misuse
    ApiMisuse,
    /// Framework-specific issues
    FrameworkSpecific,
    /// Best practices
    BestPractices,
}

impl QueryCategory {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Injection => "injection",
            Self::Xss => "xss",
            Self::Authentication => "authentication",
            Self::Cryptography => "cryptography",
            Self::PathTraversal => "path-traversal",
            Self::InformationDisclosure => "information-disclosure",
            Self::CodeQuality => "code-quality",
            Self::ResourceManagement => "resource-management",
            Self::ErrorHandling => "error-handling",
            Self::Concurrency => "concurrency",
            Self::MemorySafety => "memory-safety",
            Self::Configuration => "configuration",
            Self::ApiMisuse => "api-misuse",
            Self::FrameworkSpecific => "framework-specific",
            Self::BestPractices => "best-practices",
        }
    }
}

/// Query suite classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum QuerySuite {
    /// Default suite - high precision, high severity
    Default,
    /// Security-extended - includes lower precision security queries
    SecurityExtended,
    /// Security-comprehensive - all security checks including experimental
    SecurityComprehensive,
    /// Security-and-quality - includes code quality queries
    SecurityAndQuality,
}

impl QuerySuite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Default => "security-default",
            Self::SecurityExtended => "security-extended",
            Self::SecurityComprehensive => "security-comprehensive",
            Self::SecurityAndQuality => "security-and-quality",
        }
    }

    /// Get the suites that include this suite
    pub fn includes(&self) -> Vec<QuerySuite> {
        match self {
            Self::Default => vec![Self::Default, Self::SecurityExtended, Self::SecurityComprehensive, Self::SecurityAndQuality],
            Self::SecurityExtended => vec![Self::SecurityExtended, Self::SecurityComprehensive, Self::SecurityAndQuality],
            Self::SecurityComprehensive => vec![Self::SecurityComprehensive, Self::SecurityAndQuality],
            Self::SecurityAndQuality => vec![Self::SecurityAndQuality],
        }
    }
}

/// Comprehensive query metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryMetadata {
    /// Unique query identifier (e.g., "js/sql-injection")
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// Detailed description
    pub description: String,

    /// Query category
    pub category: QueryCategory,

    /// Severity level
    pub severity: QuerySeverity,

    /// Precision level
    pub precision: QueryPrecision,

    /// CWE identifiers covered by this query
    pub cwes: Vec<u32>,

    /// OWASP Top 10 2021 mapping (if applicable)
    pub owasp_top_10: Option<String>,

    /// Whether this is part of SANS Top 25
    pub sans_top_25: bool,

    /// Query suites that include this query
    pub suites: Vec<QuerySuite>,

    /// Tags for additional classification
    pub tags: Vec<String>,

    /// Supported languages
    pub languages: Vec<String>,

    /// Whether this is a taint-based query
    pub uses_taint: bool,

    /// Whether this is a path-sensitive query
    pub path_sensitive: bool,

    /// Example vulnerable code snippet
    pub example_vulnerable: Option<String>,

    /// Example fixed code snippet
    pub example_fixed: Option<String>,

    /// References (CVE, articles, docs)
    pub references: Vec<String>,
}

impl QueryMetadata {
    /// Create a new query metadata builder
    pub fn builder(id: impl Into<String>, name: impl Into<String>) -> QueryMetadataBuilder {
        QueryMetadataBuilder::new(id, name)
    }

    /// Check if this query is in the given suite
    pub fn in_suite(&self, suite: QuerySuite) -> bool {
        self.suites.contains(&suite)
    }

    /// Get the primary CWE (first one listed)
    pub fn primary_cwe(&self) -> Option<u32> {
        self.cwes.first().copied()
    }

    /// Check if this query supports the given language
    /// Returns true if no languages are specified (universal query) or if language is in list
    pub fn supports_language(&self, language: &str) -> bool {
        // If no languages specified, query applies to all languages
        if self.languages.is_empty() {
            return true;
        }
        let lang_lower = language.to_lowercase();
        self.languages.iter().any(|l| l.to_lowercase() == lang_lower)
    }

    /// Check if this query supports any of the given languages
    pub fn supports_any_language(&self, languages: &[&str]) -> bool {
        languages.iter().any(|l| self.supports_language(l))
    }
}

/// Builder for query metadata
pub struct QueryMetadataBuilder {
    id: String,
    name: String,
    description: String,
    category: Option<QueryCategory>,
    severity: QuerySeverity,
    precision: QueryPrecision,
    cwes: Vec<u32>,
    owasp_top_10: Option<String>,
    sans_top_25: bool,
    suites: Vec<QuerySuite>,
    tags: Vec<String>,
    languages: Vec<String>,
    uses_taint: bool,
    path_sensitive: bool,
    example_vulnerable: Option<String>,
    example_fixed: Option<String>,
    references: Vec<String>,
}

impl QueryMetadataBuilder {
    pub fn new(id: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            description: String::new(),
            category: None,
            severity: QuerySeverity::Medium,
            precision: QueryPrecision::High,
            cwes: Vec::new(),
            owasp_top_10: None,
            sans_top_25: false,
            suites: vec![QuerySuite::Default],
            tags: Vec::new(),
            languages: Vec::new(),  // Empty = applies to all languages
            uses_taint: false,
            path_sensitive: false,
            example_vulnerable: None,
            example_fixed: None,
            references: Vec::new(),
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn category(mut self, category: QueryCategory) -> Self {
        self.category = Some(category);
        self
    }

    pub fn severity(mut self, severity: QuerySeverity) -> Self {
        self.severity = severity;
        self
    }

    pub fn precision(mut self, precision: QueryPrecision) -> Self {
        self.precision = precision;
        self
    }

    pub fn cwe(mut self, cwe: u32) -> Self {
        self.cwes.push(cwe);
        self
    }

    pub fn cwes(mut self, cwes: Vec<u32>) -> Self {
        self.cwes = cwes;
        self
    }

    pub fn owasp(mut self, owasp: impl Into<String>) -> Self {
        self.owasp_top_10 = Some(owasp.into());
        self
    }

    pub fn sans_top_25(mut self) -> Self {
        self.sans_top_25 = true;
        self
    }

    pub fn suite(mut self, suite: QuerySuite) -> Self {
        if !self.suites.contains(&suite) {
            self.suites.push(suite);
        }
        self
    }

    pub fn suites(mut self, suites: Vec<QuerySuite>) -> Self {
        self.suites = suites;
        self
    }

    pub fn tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    pub fn tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn language(mut self, lang: impl Into<String>) -> Self {
        self.languages.push(lang.into());
        self
    }

    pub fn languages(mut self, langs: Vec<String>) -> Self {
        self.languages = langs;
        self
    }

    pub fn uses_taint(mut self) -> Self {
        self.uses_taint = true;
        self
    }

    pub fn path_sensitive(mut self) -> Self {
        self.path_sensitive = true;
        self
    }

    pub fn example_vulnerable(mut self, example: impl Into<String>) -> Self {
        self.example_vulnerable = Some(example.into());
        self
    }

    pub fn example_fixed(mut self, example: impl Into<String>) -> Self {
        self.example_fixed = Some(example.into());
        self
    }

    pub fn reference(mut self, reference: impl Into<String>) -> Self {
        self.references.push(reference.into());
        self
    }

    pub fn build(self) -> QueryMetadata {
        QueryMetadata {
            id: self.id,
            name: self.name,
            description: self.description,
            category: self.category.unwrap_or(QueryCategory::BestPractices),
            severity: self.severity,
            precision: self.precision,
            cwes: self.cwes,
            owasp_top_10: self.owasp_top_10,
            sans_top_25: self.sans_top_25,
            suites: self.suites,
            tags: self.tags,
            languages: self.languages,
            uses_taint: self.uses_taint,
            path_sensitive: self.path_sensitive,
            example_vulnerable: self.example_vulnerable,
            example_fixed: self.example_fixed,
            references: self.references,
        }
    }
}

/// Query registry for managing all queries
pub struct QueryRegistry {
    queries: HashMap<String, QueryMetadata>,
    by_category: HashMap<QueryCategory, Vec<String>>,
    by_cwe: HashMap<u32, Vec<String>>,
    by_suite: HashMap<QuerySuite, Vec<String>>,
}

impl QueryRegistry {
    pub fn new() -> Self {
        Self {
            queries: HashMap::new(),
            by_category: HashMap::new(),
            by_cwe: HashMap::new(),
            by_suite: HashMap::new(),
        }
    }

    /// Register a new query
    pub fn register(&mut self, metadata: QueryMetadata) {
        let id = metadata.id.clone();

        // Index by category
        self.by_category
            .entry(metadata.category.clone())
            .or_insert_with(Vec::new)
            .push(id.clone());

        // Index by CWE
        for &cwe in &metadata.cwes {
            self.by_cwe
                .entry(cwe)
                .or_insert_with(Vec::new)
                .push(id.clone());
        }

        // Index by suite
        for &suite in &metadata.suites {
            self.by_suite
                .entry(suite)
                .or_insert_with(Vec::new)
                .push(id.clone());
        }

        // Store metadata
        self.queries.insert(id, metadata);
    }

    /// Get query metadata by ID
    pub fn get(&self, id: &str) -> Option<&QueryMetadata> {
        self.queries.get(id)
    }

    /// Get all queries
    pub fn all(&self) -> Vec<&QueryMetadata> {
        self.queries.values().collect()
    }

    /// Get queries by category
    pub fn by_category(&self, category: &QueryCategory) -> Vec<&QueryMetadata> {
        self.by_category
            .get(category)
            .map(|ids| ids.iter().filter_map(|id| self.queries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get queries by CWE
    pub fn by_cwe(&self, cwe: u32) -> Vec<&QueryMetadata> {
        self.by_cwe
            .get(&cwe)
            .map(|ids| ids.iter().filter_map(|id| self.queries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get queries in a suite
    pub fn by_suite(&self, suite: QuerySuite) -> Vec<&QueryMetadata> {
        self.by_suite
            .get(&suite)
            .map(|ids| ids.iter().filter_map(|id| self.queries.get(id)).collect())
            .unwrap_or_default()
    }

    /// Get queries by severity
    pub fn by_severity(&self, severity: QuerySeverity) -> Vec<&QueryMetadata> {
        self.queries
            .values()
            .filter(|m| m.severity == severity)
            .collect()
    }

    /// Get OWASP Top 10 coverage
    pub fn owasp_coverage(&self) -> HashMap<String, usize> {
        let mut coverage = HashMap::new();
        for query in self.queries.values() {
            if let Some(ref owasp) = query.owasp_top_10 {
                *coverage.entry(owasp.clone()).or_insert(0) += 1;
            }
        }
        coverage
    }

    /// Get SANS Top 25 queries
    pub fn sans_top_25_queries(&self) -> Vec<&QueryMetadata> {
        self.queries.values().filter(|m| m.sans_top_25).collect()
    }

    /// Get statistics
    pub fn stats(&self) -> QueryRegistryStats {
        let mut unique_cwes: HashSet<u32> = HashSet::new();
        let mut taint_queries = 0;
        let mut path_sensitive_queries = 0;

        for query in self.queries.values() {
            unique_cwes.extend(&query.cwes);
            if query.uses_taint {
                taint_queries += 1;
            }
            if query.path_sensitive {
                path_sensitive_queries += 1;
            }
        }

        QueryRegistryStats {
            total_queries: self.queries.len(),
            unique_cwes: unique_cwes.len(),
            owasp_queries: self.queries.values().filter(|m| m.owasp_top_10.is_some()).count(),
            sans_queries: self.queries.values().filter(|m| m.sans_top_25).count(),
            taint_queries,
            path_sensitive_queries,
            default_suite: self.by_suite.get(&QuerySuite::Default).map(|v| v.len()).unwrap_or(0),
            security_extended: self.by_suite.get(&QuerySuite::SecurityExtended).map(|v| v.len()).unwrap_or(0),
            security_and_quality: self.by_suite.get(&QuerySuite::SecurityAndQuality).map(|v| v.len()).unwrap_or(0),
        }
    }
}

impl Default for QueryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about the query registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryRegistryStats {
    pub total_queries: usize,
    pub unique_cwes: usize,
    pub owasp_queries: usize,
    pub sans_queries: usize,
    pub taint_queries: usize,
    pub path_sensitive_queries: usize,
    pub default_suite: usize,
    pub security_extended: usize,
    pub security_and_quality: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_query_metadata_builder() {
        let metadata = QueryMetadata::builder("js/sql-injection", "SQL Injection")
            .description("Detects SQL injection vulnerabilities")
            .category(QueryCategory::Injection)
            .severity(QuerySeverity::Critical)
            .precision(QueryPrecision::High)
            .cwe(89)
            .owasp("A03:2021 - Injection")
            .sans_top_25()
            .uses_taint()
            .build();

        assert_eq!(metadata.id, "js/sql-injection");
        assert_eq!(metadata.name, "SQL Injection");
        assert_eq!(metadata.severity, QuerySeverity::Critical);
        assert_eq!(metadata.cwes, vec![89]);
        assert!(metadata.sans_top_25);
        assert!(metadata.uses_taint);
    }

    #[test]
    fn test_query_registry() {
        let mut registry = QueryRegistry::new();

        let metadata = QueryMetadata::builder("js/sql-injection", "SQL Injection")
            .category(QueryCategory::Injection)
            .cwe(89)
            .suite(QuerySuite::Default)
            .build();

        registry.register(metadata);

        assert_eq!(registry.all().len(), 1);
        assert_eq!(registry.by_category(&QueryCategory::Injection).len(), 1);
        assert_eq!(registry.by_cwe(89).len(), 1);
        assert_eq!(registry.by_suite(QuerySuite::Default).len(), 1);
    }

    #[test]
    fn test_query_suite_includes() {
        let default_suites = QuerySuite::Default.includes();
        assert_eq!(default_suites.len(), 3);
        assert!(default_suites.contains(&QuerySuite::Default));
        assert!(default_suites.contains(&QuerySuite::SecurityExtended));
        assert!(default_suites.contains(&QuerySuite::SecurityAndQuality));
    }
}
