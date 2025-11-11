//! Core parser implementation using Tree-sitter

use crate::ast::{AstNode, AstNodeKind, LiteralValue, Location, Span, Visibility};
use crate::language::{Language, LanguageConfig};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use thiserror::Error;
use tree_sitter::{Node, Parser as TreeSitterParser};

static NODE_ID_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Failed to read file: {0}")]
    IoError(#[from] std::io::Error),
    #[error("File too large: {0} bytes (max: {1})")]
    FileTooLarge(usize, usize),
    #[error("Failed to parse file: {0}")]
    TreeSitterError(String),
    #[error("Language error: {0}")]
    LanguageError(#[from] crate::language::LanguageError),
}

pub type ParseResult<T> = Result<T, ParseError>;

/// The main parser for converting source code to AST
pub struct Parser {
    config: LanguageConfig,
    file_path: PathBuf,
}

impl Parser {
    pub fn new(config: LanguageConfig, file_path: impl Into<PathBuf>) -> Self {
        Self {
            config,
            file_path: file_path.into(),
        }
    }

    /// Parse a source file into an AST
    pub fn parse_file(&self) -> ParseResult<AstNode> {
        let source_code = std::fs::read_to_string(&self.file_path)?;
        self.parse_source(&source_code)
    }

    /// Parse source code string into an AST
    pub fn parse_source(&self, source: &str) -> ParseResult<AstNode> {
        // Check file size
        if source.len() > self.config.max_file_size {
            return Err(ParseError::FileTooLarge(
                source.len(),
                self.config.max_file_size,
            ));
        }

        // Create Tree-sitter parser
        let mut ts_parser = TreeSitterParser::new();
        let language = self.config.language.tree_sitter_language();
        ts_parser
            .set_language(&language)
            .map_err(|e| ParseError::TreeSitterError(e.to_string()))?;

        // Parse the source code
        let tree = ts_parser
            .parse(source, None)
            .ok_or_else(|| ParseError::TreeSitterError("Failed to parse".to_string()))?;

        // Convert Tree-sitter tree to our AST
        let root = tree.root_node();
        let ast = self.convert_node(&root, source);

        Ok(ast)
    }

    /// Convert a Tree-sitter node to our AST representation
    fn convert_node(&self, node: &Node, source: &str) -> AstNode {
        let node_id = NODE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);
        let location = self.node_location(node);
        let text = node
            .utf8_text(source.as_bytes())
            .unwrap_or("")
            .to_string();

        let kind = self.classify_node(node, source);

        let mut ast_node = AstNode::new(node_id, kind, location, text);

        // Process children
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if !self.config.include_comments && child.kind().contains("comment") {
                continue;
            }
            let child_ast = self.convert_node(&child, source);
            ast_node.add_child(child_ast);
        }

        ast_node
    }

    /// Classify a Tree-sitter node into our AST node kind
    fn classify_node(&self, node: &Node, source: &str) -> AstNodeKind {
        let kind = node.kind();

        match kind {
            // Program structure
            "source_file" | "program" | "module" => AstNodeKind::Program,

            // Function declarations (language-specific handling)
            "function_declaration" | "function_definition" | "function_item" => {
                self.parse_function_declaration(node, source)
            }

            // Class/struct declarations
            "class_declaration" | "struct_item" | "class_definition" => {
                self.parse_class_declaration(node, source)
            }

            // Method declarations
            "method_declaration" | "method_definition" => {
                self.parse_method_declaration(node, source)
            }

            // Variable declarations
            "variable_declaration" | "let_declaration" | "const_item" => {
                self.parse_variable_declaration(node, source)
            }

            // Statements
            "expression_statement" => AstNodeKind::ExpressionStatement,
            "return_statement" => AstNodeKind::ReturnStatement,
            "if_statement" | "if_expression" => AstNodeKind::IfStatement,
            "while_statement" | "while_expression" => AstNodeKind::WhileStatement,
            "for_statement" | "for_expression" => AstNodeKind::ForStatement,
            "try_statement" => AstNodeKind::TryStatement,
            "catch_clause" => AstNodeKind::CatchClause,
            "throw_statement" => AstNodeKind::ThrowStatement,
            "block" | "statement_block" => AstNodeKind::Block,

            // Expressions
            "binary_expression" | "binary_op" => self.parse_binary_expression(node, source),
            "unary_expression" => self.parse_unary_expression(node, source),
            "call_expression" => self.parse_call_expression(node, source),
            "member_expression" | "field_expression" => {
                self.parse_member_expression(node, source)
            }
            "identifier" => self.parse_identifier(node, source),
            "string_literal" | "string" => AstNodeKind::Literal {
                value: LiteralValue::String(node.utf8_text(source.as_bytes()).unwrap_or("").to_string()),
            },
            "number_literal" | "integer_literal" | "float_literal" => AstNodeKind::Literal {
                value: LiteralValue::Number(node.utf8_text(source.as_bytes()).unwrap_or("").to_string()),
            },
            "true" => AstNodeKind::Literal {
                value: LiteralValue::Boolean(true),
            },
            "false" => AstNodeKind::Literal {
                value: LiteralValue::Boolean(false),
            },
            "null" | "nil" => AstNodeKind::Literal {
                value: LiteralValue::Null,
            },
            "assignment_expression" => self.parse_assignment_expression(node, source),

            // Comments
            _ if kind.contains("comment") => AstNodeKind::Comment {
                is_multiline: kind.contains("block") || kind.contains("multi"),
            },

            // Fallback
            _ => AstNodeKind::Other {
                node_type: kind.to_string(),
            },
        }
    }

    fn parse_function_declaration(&self, node: &Node, source: &str) -> AstNodeKind {
        let name = self.extract_name(node, source).unwrap_or_else(|| "anonymous".to_string());
        let parameters = self.extract_parameters(node, source);
        let return_type = self.extract_return_type(node, source);

        AstNodeKind::FunctionDeclaration {
            name,
            parameters,
            return_type,
        }
    }

    fn parse_class_declaration(&self, node: &Node, source: &str) -> AstNodeKind {
        let name = self.extract_name(node, source).unwrap_or_else(|| "Anonymous".to_string());

        AstNodeKind::ClassDeclaration {
            name,
            extends: None,
            implements: Vec::new(),
        }
    }

    fn parse_method_declaration(&self, node: &Node, source: &str) -> AstNodeKind {
        let name = self.extract_name(node, source).unwrap_or_else(|| "anonymous".to_string());
        let parameters = self.extract_parameters(node, source);
        let return_type = self.extract_return_type(node, source);

        AstNodeKind::MethodDeclaration {
            name,
            parameters,
            return_type,
            visibility: Visibility::Public, // TODO: Parse actual visibility
        }
    }

    fn parse_variable_declaration(&self, node: &Node, source: &str) -> AstNodeKind {
        let name = self.extract_name(node, source).unwrap_or_else(|| "unknown".to_string());
        let is_const = node.kind().contains("const");

        AstNodeKind::VariableDeclaration {
            name,
            var_type: None,
            is_const,
        }
    }

    fn parse_binary_expression(&self, node: &Node, source: &str) -> AstNodeKind {
        let operator = self.extract_operator(node, source).unwrap_or_else(|| "unknown".to_string());
        AstNodeKind::BinaryExpression { operator }
    }

    fn parse_unary_expression(&self, node: &Node, source: &str) -> AstNodeKind {
        let operator = self.extract_operator(node, source).unwrap_or_else(|| "unknown".to_string());
        AstNodeKind::UnaryExpression { operator }
    }

    fn parse_call_expression(&self, node: &Node, source: &str) -> AstNodeKind {
        let callee = self.extract_callee(node, source).unwrap_or_else(|| "unknown".to_string());
        let arguments_count = self.count_arguments(node);

        AstNodeKind::CallExpression {
            callee,
            arguments_count,
        }
    }

    fn parse_member_expression(&self, _node: &Node, _source: &str) -> AstNodeKind {
        AstNodeKind::MemberExpression {
            object: "object".to_string(), // TODO: Extract actual object
            property: "property".to_string(), // TODO: Extract actual property
        }
    }

    fn parse_identifier(&self, node: &Node, source: &str) -> AstNodeKind {
        let name = node
            .utf8_text(source.as_bytes())
            .unwrap_or("unknown")
            .to_string();
        AstNodeKind::Identifier { name }
    }

    fn parse_assignment_expression(&self, node: &Node, source: &str) -> AstNodeKind {
        let operator = self.extract_operator(node, source).unwrap_or_else(|| "=".to_string());
        AstNodeKind::AssignmentExpression { operator }
    }

    // Helper methods for extracting information from nodes
    fn extract_name(&self, node: &Node, source: &str) -> Option<String> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" || child.kind() == "name" {
                return Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
            }
        }
        None
    }

    fn extract_parameters(&self, node: &Node, source: &str) -> Vec<String> {
        let mut parameters = Vec::new();
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            if child.kind().contains("parameter") {
                if let Some(name) = self.extract_name(&child, source) {
                    parameters.push(name);
                }
            }
        }

        parameters
    }

    fn extract_return_type(&self, _node: &Node, _source: &str) -> Option<String> {
        // TODO: Language-specific return type extraction
        None
    }

    fn extract_operator(&self, node: &Node, _source: &str) -> Option<String> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let kind = child.kind();
            if kind == "+" || kind == "-" || kind == "*" || kind == "/"
                || kind == "==" || kind == "!=" || kind == "<" || kind == ">"
                || kind == "&&" || kind == "||" || kind == "=" {
                return Some(kind.to_string());
            }
        }
        None
    }

    fn extract_callee(&self, node: &Node, source: &str) -> Option<String> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" || child.kind() == "function" {
                return Some(child.utf8_text(source.as_bytes()).unwrap_or("").to_string());
            }
        }
        None
    }

    fn count_arguments(&self, node: &Node) -> usize {
        let mut cursor = node.walk();
        let args_nodes: Vec<_> = node.children(&mut cursor)
            .filter(|n| n.kind() == "arguments" || n.kind() == "argument_list")
            .collect();

        let mut count = 0;
        for args_node in args_nodes {
            let mut args_cursor = args_node.walk();
            count += args_node.children(&mut args_cursor)
                .filter(|n| !n.kind().contains("(") && !n.kind().contains(")") && !n.kind().contains(","))
                .count();
        }
        count
    }

    fn node_location(&self, node: &Node) -> Location {
        let start = node.start_position();
        let end = node.end_position();

        Location {
            file_path: self.file_path.display().to_string(),
            span: Span {
                start_line: start.row + 1,
                start_column: start.column + 1,
                end_line: end.row + 1,
                end_column: end.column + 1,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            },
        }
    }
}

/// Parse a file with automatic language detection
pub fn parse_file(path: impl AsRef<Path>) -> ParseResult<AstNode> {
    let path = path.as_ref();
    let language = Language::from_path(path)?;
    let config = LanguageConfig::new(language);
    let parser = Parser::new(config, path);
    parser.parse_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rust() {
        let source = r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#;
        let config = LanguageConfig::new(Language::Rust);
        let parser = Parser::new(config, "test.rs");
        let ast = parser.parse_source(source).unwrap();
        assert_eq!(ast.kind, AstNodeKind::Program);
    }
}
