//! KodeCD Parser - Multi-language AST parsing using Tree-sitter
//!
//! This crate provides a unified interface for parsing source code in multiple
//! languages and converting Tree-sitter concrete syntax trees into a language-agnostic
//! Abstract Syntax Tree (AST) representation.

pub mod ast;
pub mod ast_arena;
pub mod language;
pub mod parser;
pub mod visitor;

pub use ast::{AstNode, AstNodeKind, Location, Span};
pub use ast_arena::{
    AstNode as ArenaAstNode, AstNodeKind as ArenaAstNodeKind,
    AstArena, Location as ArenaLocation, Span as ArenaSpan, Visibility as ArenaVisibility
};
pub use language::{Language, LanguageConfig};
pub use parser::{ParseError, Parser, ParseResult};
pub use visitor::{AstVisitor, VisitorResult};

/// Re-export tree-sitter for convenience
pub use tree_sitter;
