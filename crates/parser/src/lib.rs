//! KodeCD Parser - Multi-language AST parsing using Tree-sitter
//!
//! This crate provides a unified interface for parsing source code in multiple
//! languages and converting Tree-sitter concrete syntax trees into a language-agnostic
//! Abstract Syntax Tree (AST) representation.
//!
//! ## Features
//!
//! - **Multi-language Support**: Parse 11+ languages including TypeScript, JavaScript,
//!   Python, Rust, Java, Go, C/C++, C#, Ruby, and PHP
//! - **Arena-based AST**: Optional arena allocation for 50-60% memory savings
//! - **Zero-copy Parsing**: Efficient parsing with minimal allocations
//! - **Symbol Table**: Automatic symbol table construction during parsing
//! - **Visitor Pattern**: Clean traversal interface for AST processing
//!
//! ## Architecture
//!
//! The parser provides two AST representations:
//!
//! 1. **Standard AST** (`ast.rs`): Clone-based, easy to use, suitable for small-medium files
//! 2. **Arena AST** (`ast_arena.rs`): Arena-allocated, memory-efficient, for large files
//!
//! ## Quick Start
//!
//! ### Standard Parser
//!
//! ```rust
//! use kodecd_parser::{Parser, Language, LanguageConfig};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create parser for TypeScript
//! let mut parser = Parser::new(
//!     LanguageConfig::new(Language::TypeScript),
//!     Path::new("app.ts")
//! );
//!
//! // Parse source code
//! let source = "const x = 10;";
//! let ast = parser.parse_source(source)?;
//!
//! // Traverse AST
//! for node in &ast.children {
//!     println!("Node: {:?}", node.kind);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ### Arena Parser (Memory-Efficient)
//!
//! ```rust
//! use kodecd_parser::{ParserArena, Language, LanguageConfig, AstArena};
//! use std::path::Path;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create arena and parser
//! let arena = AstArena::new();
//! let mut parser = ParserArena::new(
//!     LanguageConfig::new(Language::TypeScript),
//!     Path::new("app.ts")
//! );
//!
//! // Parse with arena allocation (50-60% less memory)
//! let source = "const x = 10;";
//! let ast = parser.parse_source(&arena, source)?;
//!
//! // Use AST with lifetime tied to arena
//! println!("Parsed {} nodes", ast.children.len());
//! # Ok(())
//! # }
//! ```
//!
//! ## Visitor Pattern
//!
//! ```rust
//! use kodecd_parser::{AstVisitor, AstNode, VisitorResult};
//!
//! struct FunctionCounter {
//!     count: usize,
//! }
//!
//! impl AstVisitor for FunctionCounter {
//!     fn visit_enter(&mut self, node: &AstNode) -> VisitorResult {
//!         use kodecd_parser::AstNodeKind;
//!         if matches!(node.kind, AstNodeKind::FunctionDeclaration { .. }) {
//!             self.count += 1;
//!         }
//!         Ok(())
//!     }
//! }
//!
//! # fn example(ast: &kodecd_parser::AstNode) {
//! let mut counter = FunctionCounter { count: 0 };
//! counter.walk(ast).unwrap();
//! println!("Found {} functions", counter.count);
//! # }
//! ```
//!
//! ## Supported Languages
//!
//! | Language | Status | Tree-sitter Grammar |
//! |----------|--------|---------------------|
//! | TypeScript | ✅ Full | tree-sitter-typescript |
//! | JavaScript | ✅ Full | tree-sitter-javascript |
//! | Python | ✅ Full | tree-sitter-python |
//! | Rust | ✅ Full | tree-sitter-rust |
//! | Java | ✅ Full | tree-sitter-java |
//! | Go | ✅ Full | tree-sitter-go |
//! | C | ✅ Full | tree-sitter-c |
//! | C++ | ✅ Full | tree-sitter-cpp |
//! | C# | ✅ Full | tree-sitter-c-sharp |
//! | Ruby | ✅ Full | tree-sitter-ruby |
//! | PHP | ✅ Full | tree-sitter-php |
//!
//! ## Performance
//!
//! - **Parse Speed**: ~1-5ms per 1000 lines
//! - **Memory Usage**: 50-60% reduction with arena AST
//! - **Traversal**: 2-3x speedup with arena AST
//! - **Scalability**: Handles 10,000+ line files efficiently
//!
//! ## Examples
//!
//! See the `examples/` directory for complete examples:
//! - `parse_file.rs` - Basic file parsing
//! - `arena_parsing.rs` - Memory-efficient arena parsing
//! - `visitor_pattern.rs` - AST traversal with visitor
//!
//! ## Error Handling
//!
//! The parser returns [`ParseError`] for parsing failures:
//!
//! ```rust
//! use kodecd_parser::{Parser, ParseError};
//!
//! # fn example() -> Result<(), ParseError> {
//! # let parser = kodecd_parser::Parser::new(
//! #   kodecd_parser::LanguageConfig::new(kodecd_parser::Language::TypeScript),
//! #   std::path::Path::new("test.ts")
//! # );
//! match parser.parse_file() {
//!     Ok(ast) => println!("Parsed successfully"),
//!     Err(ParseError::IoError(e)) => {
//!         eprintln!("IO error: {}", e);
//!     }
//!     Err(ParseError::TreeSitterError(msg)) => {
//!         eprintln!("Parse error: {}", msg);
//!     }
//!     Err(e) => eprintln!("Error: {}", e),
//! }
//! # Ok(())
//! # }
//! ```

pub mod ast;
pub mod ast_arena;
pub mod language;
pub mod parser;
pub mod parser_arena;
pub mod visitor;

pub use ast::{AstNode, AstNodeKind, Location, Span, Parameter, ImportSpecifier, LiteralValue, Visibility};
pub use ast_arena::{
    AstNode as ArenaAstNode, AstNodeKind as ArenaAstNodeKind,
    AstArena, Location as ArenaLocation, Span as ArenaSpan, Visibility as ArenaVisibility
};
pub use language::{Language, LanguageConfig};
pub use parser::{ParseError, Parser, ParseResult};
pub use parser_arena::ParserArena;
pub use visitor::{AstVisitor, VisitorResult};

/// Re-export tree-sitter for convenience
pub use tree_sitter;
