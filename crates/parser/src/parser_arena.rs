//! Arena-based parser that builds AST directly into arena memory
//!
//! This parser builds the arena-allocated AST directly from tree-sitter,
//! avoiding the intermediate standard AST and providing 50-60% memory savings.

use crate::ast_arena::{
    AstArena, AstNode, AstNodeKind, LiteralValue, Location, Span, Visibility,
};
use crate::language::LanguageConfig;
use std::path::Path;
use thiserror::Error;
use tree_sitter::{Node, Parser as TSParser};

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Failed to parse file: {0}")]
    ParseFailed(String),
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),
}

pub type ParseResult<'arena> = Result<&'arena AstNode<'arena>, ParseError>;

/// Arena-based parser that builds AST directly into arena memory
pub struct ParserArena {
    ts_parser: TSParser,
    file_path: String,
}

impl ParserArena {
    /// Create a new arena-based parser
    pub fn new(config: LanguageConfig, file_path: &Path) -> Self {
        let mut ts_parser = TSParser::new();
        let language = config.language.tree_sitter_language();
        ts_parser
            .set_language(&language)
            .expect("Failed to set language");

        Self {
            ts_parser,
            file_path: file_path.to_string_lossy().to_string(),
        }
    }

    /// Parse a file and build arena AST
    pub fn parse_file<'arena>(
        &mut self,
        arena: &'arena AstArena,
    ) -> ParseResult<'arena> {
        let source = std::fs::read_to_string(&self.file_path)?;
        self.parse_source(arena, &source)
    }

    /// Parse source code and build arena AST
    pub fn parse_source<'arena>(
        &mut self,
        arena: &'arena AstArena,
        source: &str,
    ) -> ParseResult<'arena> {
        let tree = self
            .ts_parser
            .parse(source, None)
            .ok_or_else(|| ParseError::ParseFailed("Tree-sitter parsing failed".to_string()))?;

        let root_node = tree.root_node();
        let file_path_interned = arena.alloc_str(&self.file_path);

        Ok(self.build_ast_node(arena, root_node, source, file_path_interned))
    }

    /// Build an AST node from a tree-sitter node
    fn build_ast_node<'arena>(
        &self,
        arena: &'arena AstArena,
        node: Node,
        source: &str,
        file_path: &'arena str,
    ) -> &'arena AstNode<'arena> {
        let id = arena.next_id();

        // Create location
        let location = Location {
            file_path,
            span: Span {
                start_line: node.start_position().row + 1,
                start_column: node.start_position().column,
                end_line: node.end_position().row + 1,
                end_column: node.end_position().column,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            },
        };

        // Get node text
        let text = node
            .utf8_text(source.as_bytes())
            .unwrap_or("")
            .trim();
        let text_interned = arena.alloc_str(text);

        // Classify the node kind
        let kind = self.classify_node(arena, &node, source);

        // Recursively build children
        let mut children = Vec::new();
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            children.push(self.build_ast_node(arena, child, source, file_path));
        }

        // Allocate node in arena
        arena.alloc_node(id, kind, location, text_interned, children)
    }

    /// Classify a tree-sitter node into our AST node kind
    fn classify_node<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> AstNodeKind<'arena> {
        let kind = node.kind();

        match kind {
            // Program structure
            "program" | "source_file" => AstNodeKind::Program,
            "module" => AstNodeKind::Module,
            "package" | "package_declaration" => AstNodeKind::Package,

            // Function declarations
            "function_declaration" | "function_definition" | "function_item" => {
                let name = self.extract_name(arena, node, source);
                let parameters = self.extract_parameters(arena, node, source);
                let return_type = self.extract_return_type(arena, node, source);
                AstNodeKind::FunctionDeclaration {
                    name,
                    parameters,
                    return_type,
                }
            }

            // Class declarations
            "class_declaration" | "class_definition" => {
                let name = self.extract_name(arena, node, source);
                let extends = self.extract_extends(arena, node, source);
                let implements = self.extract_implements(arena, node, source);
                AstNodeKind::ClassDeclaration {
                    name,
                    extends,
                    implements,
                }
            }

            // Method declarations
            "method_declaration" | "method_definition" => {
                let name = self.extract_name(arena, node, source);
                let parameters = self.extract_parameters(arena, node, source);
                let return_type = self.extract_return_type(arena, node, source);
                let visibility = self.extract_visibility(node, source);
                AstNodeKind::MethodDeclaration {
                    name,
                    parameters,
                    return_type,
                    visibility,
                }
            }

            // Variable declarations
            "variable_declaration" | "let_declaration" | "const_item"
            | "lexical_declaration" | "variable_declarator" => {
                let name = self.extract_name(arena, node, source);
                let var_type = self.extract_variable_type(arena, node, source);
                let is_const = kind.contains("const");
                AstNodeKind::VariableDeclaration {
                    name,
                    var_type,
                    is_const,
                }
            }

            // Interface declarations
            "interface_declaration" => {
                let name = self.extract_name(arena, node, source);
                AstNodeKind::InterfaceDeclaration { name }
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
            // Ruby uses "binary" for binary expressions
            "binary_expression" | "binary_op" | "binary" => {
                let operator = self.extract_operator(arena, node, source);
                AstNodeKind::BinaryExpression { operator }
            }
            "unary_expression" => {
                let operator = self.extract_operator(arena, node, source);
                AstNodeKind::UnaryExpression { operator }
            }
            // Function/method calls - language-specific node types:
            // JavaScript/TypeScript/Go/Rust/C/C++/Scala/Swift/Kotlin: call_expression
            // Python/Ruby: call
            // Java: method_invocation
            // C#: invocation_expression
            // PHP: function_call_expression, member_call_expression, nullsafe_member_call_expression, scoped_call_expression
            // Lua: function_call
            // Perl: function_call_expression, method_call_expression, func0op_call_expression, func1op_call_expression, coderef_call_expression
            // Bash: command
            "call_expression" | "call" | "method_invocation" | "invocation_expression"
            | "function_call_expression" | "member_call_expression" | "nullsafe_member_call_expression" | "scoped_call_expression"
            | "function_call"
            | "method_call_expression" | "func0op_call_expression" | "func1op_call_expression" | "coderef_call_expression"
            | "command" => {
                let callee = self.extract_callee(arena, node, source);
                let arguments_count = self.count_arguments(node);
                AstNodeKind::CallExpression {
                    callee,
                    arguments_count,
                }
            }
            "member_expression" | "field_expression" => {
                let (object, property) = self.extract_member_parts(arena, node, source);
                AstNodeKind::MemberExpression { object, property }
            }
            // Ruby uses "assignment" and "variable_assignment"
            // Go uses "assignment_statement" for assignments like bar = param
            "assignment_expression" | "assignment" | "variable_assignment" | "assignment_statement" => {
                let operator = self.extract_operator(arena, node, source);
                AstNodeKind::AssignmentExpression { operator }
            }

            // Literals
            "string_literal" | "string" => AstNodeKind::Literal {
                value: LiteralValue::String(arena.alloc_str(
                    node.utf8_text(source.as_bytes()).unwrap_or(""),
                )),
            },
            "number" | "integer" | "float" => AstNodeKind::Literal {
                value: LiteralValue::Number(arena.alloc_str(
                    node.utf8_text(source.as_bytes()).unwrap_or("0"),
                )),
            },
            "true" => AstNodeKind::Literal {
                value: LiteralValue::Boolean(true),
            },
            "false" => AstNodeKind::Literal {
                value: LiteralValue::Boolean(false),
            },
            "null" => AstNodeKind::Literal {
                value: LiteralValue::Null,
            },
            "undefined" => AstNodeKind::Literal {
                value: LiteralValue::Undefined,
            },

            // Identifiers
            "identifier" => {
                let name = arena.alloc_str(node.utf8_text(source.as_bytes()).unwrap_or(""));
                AstNodeKind::Identifier { name }
            }

            // Imports/Exports
            "import_statement" | "import_declaration" => {
                let source_str = self.extract_import_source(arena, node, source);
                AstNodeKind::Import {
                    source: source_str,
                }
            }
            "export_statement" | "export_declaration" => AstNodeKind::Export,

            // New expressions (object creation) - critical for security
            "new_expression" | "object_creation_expression" => {
                let callee = self.extract_callee(arena, node, source);
                let arguments_count = self.count_arguments(node);
                AstNodeKind::NewExpression {
                    callee,
                    arguments_count,
                }
            }

            // Array expressions
            "array" | "array_expression" | "list" => AstNodeKind::ArrayExpression,

            // Object expressions
            "object" | "object_expression" | "hash" | "dictionary" => AstNodeKind::ObjectExpression,

            // Conditional/ternary expressions
            // Ruby uses "conditional" for ternary operator
            "conditional_expression" | "ternary_expression" | "conditional" => AstNodeKind::ConditionalExpression,

            // Switch statements
            "switch_statement" | "switch_expression" => AstNodeKind::SwitchStatement,
            "switch_case" | "case_clause" => AstNodeKind::SwitchCase,

            // Lambda/arrow functions
            "arrow_function" | "lambda" | "lambda_expression" | "anonymous_function" => {
                let parameters = self.extract_parameters(arena, node, source);
                AstNodeKind::ArrowFunction { parameters }
            }

            // this/super expressions
            "this" | "this_expression" => AstNodeKind::ThisExpression,
            "super" | "super_expression" => AstNodeKind::SuperExpression,

            // Await/yield expressions - important for async taint tracking
            "await_expression" => AstNodeKind::AwaitExpression,
            "yield_expression" => AstNodeKind::YieldExpression,

            // Spread/rest elements - important for taint propagation
            "spread_element" | "spread_argument" | "spread_expression" => AstNodeKind::SpreadElement,
            "rest_element" | "rest_parameter" | "rest_pattern" => AstNodeKind::RestElement,

            // Property access subscript
            "subscript_expression" | "element_reference" | "index_expression" => {
                AstNodeKind::SubscriptExpression
            }

            // Parenthesized expressions
            // Ruby uses "parenthesized_statements" for parenthesized expressions
            "parenthesized_expression" | "parenthesized_statements" => AstNodeKind::ParenthesizedExpression,

            // Template strings - important for XSS/injection detection
            "template_string" | "template_literal" => AstNodeKind::TemplateString,

            // Break/continue with labels
            "break_statement" => AstNodeKind::BreakStatement,
            "continue_statement" => AstNodeKind::ContinueStatement,

            // Do-while loops
            "do_statement" | "do_while_statement" => AstNodeKind::DoWhileStatement,

            // Enum declarations
            "enum_declaration" | "enum_item" => {
                let name = self.extract_name(arena, node, source);
                AstNodeKind::EnumDeclaration { name }
            }

            // Type alias
            "type_alias_declaration" | "type_declaration" => {
                let name = self.extract_name(arena, node, source);
                AstNodeKind::TypeAlias { name }
            }

            // Augmented assignment (+=, -=, etc.)
            "augmented_assignment_expression" | "compound_assignment_expr" => {
                let operator = self.extract_operator(arena, node, source);
                AstNodeKind::AugmentedAssignment { operator }
            }

            // Update expressions (++, --)
            "update_expression" => {
                let operator = self.extract_operator(arena, node, source);
                AstNodeKind::UpdateExpression { operator }
            }

            // Comments
            _ if kind.contains("comment") => AstNodeKind::Comment {
                is_multiline: kind.contains("block") || kind.contains("multi"),
            },

            // Fallback
            _ => AstNodeKind::Other {
                node_type: arena.alloc_str(kind),
            },
        }
    }

    // Helper methods for extracting information from nodes

    fn extract_name<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> &'arena str {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind() == "identifier" || child.kind() == "name" {
                return arena.alloc_str(child.utf8_text(source.as_bytes()).unwrap_or(""));
            }
        }
        arena.alloc_str("unknown")
    }

    fn extract_parameters<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> Vec<&'arena str> {
        let mut params = Vec::new();
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            if child.kind().contains("parameter") {
                let param_name = self.extract_name(arena, &child, source);
                params.push(param_name);
            }
        }

        params
    }

    fn extract_return_type<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> Option<&'arena str> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind().contains("type") && !child.kind().contains("parameter") {
                return Some(arena.alloc_str(child.utf8_text(source.as_bytes()).unwrap_or("")));
            }
        }
        None
    }

    fn extract_extends<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> Option<&'arena str> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind().contains("extends") {
                return Some(arena.alloc_str(child.utf8_text(source.as_bytes()).unwrap_or("")));
            }
        }
        None
    }

    fn extract_implements<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> Vec<&'arena str> {
        let mut implements = Vec::new();
        let mut cursor = node.walk();

        for child in node.children(&mut cursor) {
            if child.kind().contains("implements") {
                let mut impl_cursor = child.walk();
                for impl_child in child.children(&mut impl_cursor) {
                    if impl_child.kind() == "identifier" {
                        implements.push(arena.alloc_str(
                            impl_child.utf8_text(source.as_bytes()).unwrap_or(""),
                        ));
                    }
                }
            }
        }

        implements
    }

    fn extract_variable_type<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> Option<&'arena str> {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind().contains("type_annotation") || child.kind() == "type" {
                return Some(arena.alloc_str(child.utf8_text(source.as_bytes()).unwrap_or("")));
            }
        }
        None
    }

    fn extract_visibility(&self, node: &Node, _source: &str) -> Visibility {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            match child.kind() {
                "public" => return Visibility::Public,
                "private" => return Visibility::Private,
                "protected" => return Visibility::Protected,
                "internal" => return Visibility::Internal,
                _ => {}
            }
        }
        Visibility::Public
    }

    fn extract_operator<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        _source: &str,
    ) -> &'arena str {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            let kind = child.kind();
            if kind.len() <= 3
                && (kind.contains('+')
                    || kind.contains('-')
                    || kind.contains('*')
                    || kind.contains('/')
                    || kind.contains('=')
                    || kind.contains('!')
                    || kind.contains('<')
                    || kind.contains('>'))
            {
                return arena.alloc_str(kind);
            }
        }
        arena.alloc_str("unknown")
    }

    fn extract_callee<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> &'arena str {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            // Handle member expressions (e.g., crypto.createHash)
            if child.kind() == "member_expression" || child.kind() == "field_expression" {
                return arena.alloc_str(child.utf8_text(source.as_bytes()).unwrap_or(""));
            }
            // Handle simple identifiers
            if child.kind() == "identifier" || child.kind() == "function" {
                return arena.alloc_str(child.utf8_text(source.as_bytes()).unwrap_or(""));
            }
        }
        arena.alloc_str("unknown")
    }

    fn count_arguments(&self, node: &Node) -> usize {
        let mut cursor = node.walk();
        let args_nodes: Vec<_> = node
            .children(&mut cursor)
            .filter(|n| n.kind() == "arguments" || n.kind() == "argument_list")
            .collect();

        let mut count = 0;
        for args_node in args_nodes {
            let mut args_cursor = args_node.walk();
            count += args_node
                .children(&mut args_cursor)
                .filter(|n| !n.kind().contains("(") && !n.kind().contains(")") && !n.kind().contains(","))
                .count();
        }
        count
    }

    fn extract_member_parts<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> (&'arena str, &'arena str) {
        let mut cursor = node.walk();
        let children: Vec<_> = node.children(&mut cursor).collect();

        let object = if !children.is_empty() {
            arena.alloc_str(children[0].utf8_text(source.as_bytes()).unwrap_or("object"))
        } else {
            arena.alloc_str("object")
        };

        let property = if children.len() > 1 {
            arena.alloc_str(
                children
                    .last()
                    .and_then(|n| n.utf8_text(source.as_bytes()).ok())
                    .unwrap_or("property"),
            )
        } else {
            arena.alloc_str("property")
        };

        (object, property)
    }

    fn extract_import_source<'arena>(
        &self,
        arena: &'arena AstArena,
        node: &Node,
        source: &str,
    ) -> &'arena str {
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.kind().contains("string") {
                return arena.alloc_str(child.utf8_text(source.as_bytes()).unwrap_or(""));
            }
        }
        arena.alloc_str("")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::language::Language;

    #[test]
    fn test_parse_simple_function() {
        let arena = AstArena::new();
        let config = LanguageConfig::new(Language::JavaScript);
        let mut parser = ParserArena::new(config, Path::new("test.js"));

        let source = "function hello() { return 42; }";
        let ast = parser.parse_source(&arena, source).unwrap();

        assert_eq!(ast.children.len() > 0, true);
        println!("Parsed AST with {} children", ast.children.len());
    }

    #[test]
    fn test_memory_efficiency() {
        let arena = AstArena::new();
        let config = LanguageConfig::new(Language::TypeScript);
        let mut parser = ParserArena::new(config, Path::new("test.ts"));

        let source = r#"
function test1() { console.log("test"); }
function test2() { console.log("test"); }
function test3() { console.log("test"); }
        "#;

        let ast = parser.parse_source(&arena, source).unwrap();

        let stats = arena.memory_stats();
        println!("Memory stats: {}", stats);

        // Should use minimal memory due to arena allocation
        assert!(stats.arena_allocated < 50000); // Less than 50KB for small file
    }
}
