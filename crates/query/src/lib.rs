//! KodeCD Query Language (KQL) - A domain-specific language for security queries
//!
//! KQL allows users to write declarative queries to find security vulnerabilities
//! in source code.

pub mod ast;
pub mod executor;
pub mod lexer;
pub mod parser;
pub mod stdlib;

pub use ast::{Query, QueryAst, Predicate};
pub use executor::{QueryExecutor, QueryResult, Finding};
pub use lexer::{Token, Lexer};
pub use parser::{QueryParser, ParseError};
pub use stdlib::StandardLibrary;
