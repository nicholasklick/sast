//! Unit tests for TypeScript-specific AST node variants
//!
//! Tests all TypeScript constructs added in Phase 6 of AST expansion:
//! - Type annotations
//! - Type arguments (generics in calls)
//! - Type parameters (generic declarations)
//! - As expressions (type assertions)
//! - Satisfies expressions
//! - Non-null assertions

use kodecd_parser::{Language, LanguageConfig, Parser, ast::AstNodeKind};
use std::path::Path;

/// Helper to check if a node kind exists in the tree
fn has_node_kind<F>(ast: &kodecd_parser::ast::AstNode, kind_matcher: F) -> bool
where
    F: Fn(&AstNodeKind) -> bool
{
    fn find_node_kind<F>(ast: &kodecd_parser::ast::AstNode, kind_matcher: &F) -> bool
    where
        F: Fn(&AstNodeKind) -> bool
    {
        if kind_matcher(&ast.kind) {
            return true;
        }

        for child in &ast.children {
            if find_node_kind(child, kind_matcher) {
                return true;
            }
        }

        false
    }

    find_node_kind(ast, &kind_matcher)
}

// ============================================================================
// Type Annotation Tests
// ============================================================================

#[test]
fn test_type_annotation_function_params() {
    let code = r#"
        function greet(name: string, age: number): string {
            return "Hello";
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_annotation = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeAnnotation { .. }));
    assert!(has_type_annotation, "Should find TypeAnnotation");
}

#[test]
fn test_type_annotation_variables() {
    let code = r#"
        const name: string = "John";
        let age: number = 30;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_annotation = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeAnnotation { .. }));
    assert!(has_type_annotation, "Should find TypeAnnotation in variable declarations");
}

// ============================================================================
// Type Arguments Tests (Generics in calls)
// ============================================================================

#[test]
fn test_type_arguments_function_call() {
    let code = r#"
        const result = identity<string>("hello");
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_arguments = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeArguments { .. }));
    assert!(has_type_arguments, "Should find TypeArguments in function call");
}

#[test]
fn test_type_arguments_multiple() {
    let code = r#"
        const map = new Map<string, number>();
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_arguments = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeArguments { .. }));
    assert!(has_type_arguments, "Should find TypeArguments with multiple types");
}

// ============================================================================
// Type Parameters Tests (Generic declarations)
// ============================================================================

#[test]
fn test_type_parameters_function() {
    let code = r#"
        function identity<T>(arg: T): T {
            return arg;
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_parameters = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeParameters { .. }));
    assert!(has_type_parameters, "Should find TypeParameters in function declaration");
}

#[test]
fn test_type_parameters_class() {
    let code = r#"
        class Container<T> {
            value: T;
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_parameters = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeParameters { .. }));
    assert!(has_type_parameters, "Should find TypeParameters in class declaration");
}

#[test]
fn test_type_parameters_multiple() {
    let code = r#"
        function pair<K, V>(key: K, value: V): [K, V] {
            return [key, value];
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_parameters = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeParameters { .. }));
    assert!(has_type_parameters, "Should find TypeParameters with multiple type params");
}

// ============================================================================
// As Expression Tests (Type assertions)
// ============================================================================

#[test]
fn test_as_expression_simple() {
    let code = r#"
        const value = obj as MyType;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_as_expression = has_node_kind(&ast, |k| matches!(k, AstNodeKind::AsExpression { .. }));
    assert!(has_as_expression, "Should find AsExpression");
}

#[test]
fn test_as_expression_unknown_to_specific() {
    let code = r#"
        const num = (value as unknown) as number;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_as_expression = has_node_kind(&ast, |k| matches!(k, AstNodeKind::AsExpression { .. }));
    assert!(has_as_expression, "Should find AsExpression with chained assertions");
}

// ============================================================================
// Satisfies Expression Tests
// ============================================================================

#[test]
fn test_satisfies_expression() {
    let code = r#"
        const value = obj satisfies MyType;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_satisfies = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SatisfiesExpression { .. }));
    assert!(has_satisfies, "Should find SatisfiesExpression");
}

#[test]
fn test_satisfies_with_object_literal() {
    let code = r#"
        const config = {
            name: "app",
            version: 1
        } satisfies Config;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_satisfies = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SatisfiesExpression { .. }));
    assert!(has_satisfies, "Should find SatisfiesExpression with object literal");
}

// ============================================================================
// Non-Null Assertion Tests
// ============================================================================

#[test]
fn test_non_null_assertion() {
    let code = r#"
        const value = maybeNull!;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_non_null = has_node_kind(&ast, |k| matches!(k, AstNodeKind::NonNullAssertion));
    assert!(has_non_null, "Should find NonNullAssertion");
}

#[test]
fn test_non_null_assertion_chained() {
    let code = r#"
        const value = obj.prop!.method();
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_non_null = has_node_kind(&ast, |k| matches!(k, AstNodeKind::NonNullAssertion));
    assert!(has_non_null, "Should find NonNullAssertion in chained expression");
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_complex_typescript_function() {
    let code = r#"
        function processData<T extends object>(
            data: T,
            transformer: (item: T) => string
        ): string[] {
            return [transformer(data)];
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_type_params = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeParameters { .. }));
    let has_type_annotation = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeAnnotation { .. }));

    assert!(has_type_params || has_type_annotation, "Should find TypeScript constructs in complex function");
}

#[test]
fn test_real_world_typescript_pattern() {
    let code = r#"
        interface User {
            name: string;
            age: number;
        }

        function getUser(id: string): User {
            const data = fetchData(id) as User;
            return data!;
        }

        const user = getUser("123") satisfies User;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should have type annotations, as expressions, satisfies, and non-null
    let has_typescript = has_node_kind(&ast, |k| matches!(k, AstNodeKind::TypeAnnotation { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::AsExpression { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::SatisfiesExpression { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::NonNullAssertion));

    assert!(has_typescript, "Should find TypeScript-specific constructs in real-world pattern");
}
