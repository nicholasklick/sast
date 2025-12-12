//! Gittera Query Language (GQL) - A domain-specific language for security queries
//!
//! GQL allows users to write declarative queries to find security vulnerabilities
//! in source code using SQL-like syntax.
//!
//! ## Features
//!
//! - **SQL-like Syntax**: Familiar `FROM...WHERE...SELECT` structure
//! - **Type Matching**: Match specific AST node types
//! - **Property Access**: Query node properties (name, callee, etc.)
//! - **Comparison Operators**: `==`, `!=`, `CONTAINS`, `STARTS_WITH`, `ENDS_WITH`, `MATCHES`
//! - **Logical Operators**: `AND`, `OR`, `NOT`
//! - **Taint Analysis Integration**: `.isTainted()` method
//! - **Standard Library**: 100+ built-in security queries
//! - **Query Metadata**: CWE mappings, severity levels, OWASP/SANS coverage
//! - **Query Suites**: Default, security-extended, security-and-quality
//!
//! ## Quick Start
//!
//! ### Simple Query
//!
//! ```rust
//! use gittera_query::QueryParser;
//!
//! let query_str = r#"
//!     FROM CallExpression AS call
//!     WHERE call.callee == "eval"
//!     SELECT call, "Dangerous use of eval()"
//! "#;
//!
//! let query = QueryParser::parse(query_str)?;
//! # Ok::<(), gittera_query::ParseError>(())
//! ```
//!
//! ### Execute Query
//!
//! ```rust,no_run
//! use gittera_query::{QueryParser, QueryExecutor};
//! use gittera_parser::{Parser, Language, LanguageConfig};
//! use gittera_analyzer::CfgBuilder;
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Parse code
//! let parser = Parser::new(
//!     LanguageConfig::new(Language::TypeScript),
//!     Path::new("app.ts")
//! );
//! let ast = parser.parse_file()?;
//! let cfg = CfgBuilder::new().build(&ast);
//!
//! // Parse and execute query
//! let query_str = r#"
//!     FROM CallExpression AS call
//!     WHERE call.callee MATCHES "(?i)(eval|exec)"
//!     SELECT call, "Code injection risk"
//! "#;
//!
//! let query = QueryParser::parse(query_str)?;
//! let result = QueryExecutor::execute(&query, &ast, &cfg, None);
//!
//! // Process results
//! for finding in &result.findings {
//!     println!("{}: {}", finding.line, finding.message);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### With Taint Analysis
//!
//! ```rust,no_run
//! use gittera_query::{QueryParser, QueryExecutor};
//! use gittera_analyzer::{CfgBuilder, TaintAnalysis};
//! # use gittera_parser::{Parser, Language, LanguageConfig};
//! # use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # let parser = Parser::new(
//! #     LanguageConfig::new(Language::TypeScript),
//! #     Path::new("app.ts")
//! # );
//! # let ast = parser.parse_file()?;
//! # let cfg = CfgBuilder::new().build(&ast);
//! // Run taint analysis
//! let taint = TaintAnalysis::new()
//!     .with_default_sources()
//!     .with_default_sinks();
//! let taint_result = taint.analyze(&cfg, &ast);
//!
//! // Query for tainted eval calls
//! let query_str = r#"
//!     FROM CallExpression AS call
//!     WHERE call.callee == "eval" AND call.isTainted()
//!     SELECT call, "SQL injection vulnerability"
//! "#;
//!
//! let query = QueryParser::parse(query_str)?;
//! let result = QueryExecutor::execute(&query, &ast, &cfg, Some(&taint_result));
//! # Ok(())
//! # }
//! ```
//!
//! ## Query Syntax
//!
//! ### FROM Clause
//!
//! Specify the AST node type to match:
//!
//! ```sql
//! FROM CallExpression AS call
//! FROM FunctionDeclaration AS func
//! FROM VariableDeclaration AS var
//! ```
//!
//! ### WHERE Clause
//!
//! Filter nodes based on conditions:
//!
//! ```sql
//! -- Exact match
//! WHERE call.callee == "eval"
//!
//! -- Pattern matching
//! WHERE call.callee MATCHES "(?i)(eval|exec)"
//!
//! -- String operations
//! WHERE call.callee CONTAINS "exec"
//! WHERE call.callee STARTS_WITH "eval"
//! WHERE call.callee ENDS_WITH "Sync"
//!
//! -- Logical operators
//! WHERE call.callee == "eval" AND call.isTainted()
//! WHERE call.callee == "eval" OR call.callee == "exec"
//! WHERE NOT call.callee == "safe"
//! ```
//!
//! ### SELECT Clause
//!
//! Specify what to return:
//!
//! ```sql
//! -- Return the node
//! SELECT call
//!
//! -- Return with message
//! SELECT call, "Security issue found"
//!
//! -- Multiple items
//! SELECT call, "Code injection risk"
//! ```
//!
//! ## Standard Library
//!
//! Pre-built queries for common vulnerabilities:
//!
//! ```rust
//! use gittera_query::StandardLibrary;
//!
//! // Get all OWASP queries
//! let queries = StandardLibrary::owasp_queries();
//! println!("Found {} OWASP queries", queries.len());
//!
//! // Get specific query
//! let sql_injection = StandardLibrary::sql_injection_query();
//! println!("SQL Injection query loaded");
//! ```
//!
//! ### Available Queries
//!
//! - `sql-injection` - SQL injection detection
//! - `command-injection` - OS command injection
//! - `xss` - Cross-site scripting
//! - `path-traversal` - Path traversal attacks
//! - `code-injection` - Code injection via eval
//! - `ldap-injection` - LDAP injection
//! - `xpath-injection` - XPath injection
//! - `xxe` - XML External Entity
//! - `hardcoded-secrets` - Hardcoded credentials
//! - `insecure-deserialization` - Unsafe deserialization
//! - `ssrf` - Server-side request forgery
//! - `weak-crypto` - Weak cryptographic algorithms
//!
//! ## Operators
//!
//! ### Comparison Operators
//!
//! | Operator | Description | Example |
//! |----------|-------------|---------|
//! | `==` | Exact match | `call.callee == "eval"` |
//! | `!=` | Not equal | `call.callee != "safe"` |
//! | `CONTAINS` | Substring | `call.callee CONTAINS "exec"` |
//! | `STARTS_WITH` | Prefix | `call.callee STARTS_WITH "eval"` |
//! | `ENDS_WITH` | Suffix | `call.callee ENDS_WITH "Sync"` |
//! | `MATCHES` | Regex | `call.callee MATCHES "(?i)eval"` |
//!
//! ### Logical Operators
//!
//! | Operator | Description | Example |
//! |----------|-------------|---------|
//! | `AND` | Conjunction | `a == 1 AND b == 2` |
//! | `OR` | Disjunction | `a == 1 OR b == 2` |
//! | `NOT` | Negation | `NOT a == 1` |
//!
//! ## Methods
//!
//! ### .isTainted()
//!
//! Check if a value is tainted (requires taint analysis):
//!
//! ```sql
//! FROM CallExpression AS call
//! WHERE call.callee == "execute" AND call.isTainted()
//! SELECT call, "Tainted data in execute()"
//! ```
//!
//! ## Performance
//!
//! - **Parse Time**: ~1ms per query
//! - **Execution**: ~1-5ms per query per file
//! - **Caching**: Query ASTs are cacheable
//! - **Scalability**: Efficiently handles large ASTs
//!
//! ## Error Handling
//!
//! ```rust
//! use gittera_query::{QueryParser, ParseError};
//!
//! match QueryParser::parse("invalid query") {
//!     Ok(query) => println!("Parsed successfully"),
//!     Err(ParseError::InvalidSyntax(msg)) => {
//!         eprintln!("Syntax error: {}", msg);
//!     }
//!     Err(e) => eprintln!("Parse error: {:?}", e),
//! }
//! ```
//!
//! ## Examples
//!
//! ### Find All eval() Calls
//!
//! ```sql
//! FROM CallExpression AS call
//! WHERE call.callee == "eval"
//! SELECT call, "Use of eval() detected"
//! ```
//!
//! ### Find Dangerous Functions with Regex
//!
//! ```sql
//! FROM CallExpression AS call
//! WHERE call.callee MATCHES "(?i)(eval|exec|system)"
//! SELECT call, "Dangerous function call"
//! ```
//!
//! ### Find Tainted Database Queries
//!
//! ```sql
//! FROM CallExpression AS call
//! WHERE call.callee MATCHES "(?i)(execute|query)"
//!       AND call.isTainted()
//! SELECT call, "SQL injection vulnerability"
//! ```
//!
//! ### Complex Logic
//!
//! ```sql
//! FROM CallExpression AS call
//! WHERE (call.callee == "eval" OR call.callee == "Function")
//!       AND call.isTainted()
//!       AND NOT call.callee CONTAINS "safe"
//! SELECT call, "Code injection risk"
//! ```
//!
//! ## Testing
//!
//! Run the query test suite:
//!
//! ```bash
//! cargo test -p gittera-query
//! ```
//!
//! ## See Also
//!
//! - `GQL_GUIDE.md` - Complete GQL language guide
//! - `GQL_QUICK_REFERENCE.md` - One-page reference
//! - `TAINT_ANALYSIS_GUIDE.md` - Taint analysis integration

pub mod ast;
pub mod executor;
pub mod lexer;
pub mod parser;
pub mod stdlib;
pub mod metadata;
pub mod extended_stdlib;
pub mod owasp_rules;
pub mod languages;

pub use ast::{Query, QueryAst, Predicate};
pub use executor::{QueryExecutor, QueryResult, Finding, DataFlowPath, FlowLocation};
pub use lexer::{Token, Lexer};
pub use parser::{QueryParser, ParseError};
pub use stdlib::StandardLibrary;
pub use owasp_rules::{OwaspRuleLibrary, RuleMetadata, Severity};
pub use metadata::{
    QueryMetadata, QueryMetadataBuilder, QueryCategory, QuerySeverity,
    QueryPrecision, QuerySuite, QueryRegistry, QueryRegistryStats
};
pub use extended_stdlib::ExtendedStandardLibrary;
