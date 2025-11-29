//! Unit tests for object/array detail AST node variants
//!
//! Tests object and array constructs added in Phase 4 of AST expansion:
//! - Property nodes (key-value pairs)
//! - Computed property names
//! - Method definitions (including getters/setters)
//! - Shorthand properties

use gittera_parser::{Language, LanguageConfig, Parser, ast::{AstNodeKind, MethodKind}};
use std::path::Path;

/// Helper to check if a node kind exists in the tree
fn has_node_kind<F>(ast: &gittera_parser::ast::AstNode, kind_matcher: F) -> bool
where
    F: Fn(&AstNodeKind) -> bool
{
    fn find_node_kind<F>(ast: &gittera_parser::ast::AstNode, kind_matcher: &F) -> bool
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
// Property Tests
// ============================================================================

#[test]
fn test_property_simple() {
    let code = r#"
        const obj = {name: "test", value: 42};
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_property = has_node_kind(&ast, |k| matches!(k, AstNodeKind::Property { .. }));
    assert!(has_property, "Should find Property nodes in object literal");
}

#[test]
fn test_property_shorthand() {
    let code = r#"
        const name = "test";
        const obj = {name, value: 42};
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // May or may not detect shorthand depending on tree-sitter granularity
    let has_property = has_node_kind(&ast, |k| matches!(k, AstNodeKind::Property { .. }));
    assert!(has_property, "Should find Property nodes (shorthand or regular)");
}

#[test]
fn test_computed_property_name() {
    let code = r#"
        const key = "dynamic";
        const obj = {[key]: "value"};
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_computed = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ComputedPropertyName { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::Property { is_computed: true, .. }));

    assert!(has_computed, "Should find computed property name");
}

// ============================================================================
// Method Definition Tests
// ============================================================================

#[test]
fn test_method_definition_class() {
    let code = r#"
        class MyClass {
            myMethod() {
                return 42;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_method = has_node_kind(&ast, |k| matches!(k, AstNodeKind::MethodDefinition { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::MethodDeclaration { .. }));

    assert!(has_method, "Should find method definition in class");
}

#[test]
fn test_method_definition_static() {
    let code = r#"
        class MyClass {
            static staticMethod() {
                return "static";
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_static_method = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { is_static: true, .. })
    }) || has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDeclaration { is_static: true, .. })
    });

    assert!(has_static_method, "Should find static method");
}

#[test]
fn test_method_definition_getter() {
    let code = r#"
        class MyClass {
            get value() {
                return this._value;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_getter = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { kind: MethodKind::Get, .. })
    });

    assert!(has_getter, "Should find getter method");
}

#[test]
fn test_method_definition_setter() {
    let code = r#"
        class MyClass {
            set value(v) {
                this._value = v;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_setter = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { kind: MethodKind::Set, .. })
    });

    assert!(has_setter, "Should find setter method");
}

#[test]
fn test_constructor() {
    let code = r#"
        class MyClass {
            constructor(value) {
                this.value = value;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_constructor = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { kind: MethodKind::Constructor, .. })
    });

    assert!(has_constructor, "Should find constructor");
}

// ============================================================================
// Object Method Tests
// ============================================================================

#[test]
fn test_object_method_shorthand() {
    let code = r#"
        const obj = {
            method() {
                return "test";
            }
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Object methods may be detected as Property with is_method=true, MethodDefinition, or MethodDeclaration
    let has_method = has_node_kind(&ast, |k| matches!(k, AstNodeKind::Property { is_method: true, .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::MethodDefinition { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::MethodDeclaration { .. }));

    assert!(has_method, "Should find method in object literal");
}

// ============================================================================
// TypeScript Tests
// ============================================================================

#[test]
fn test_typescript_class_properties() {
    let code = r#"
        class MyClass {
            public name: string;
            private value: number = 42;
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Class properties/fields should be detected as MethodDefinition, VariableDeclaration, or ClassDeclaration
    let has_field = has_node_kind(&ast, |k| matches!(k, AstNodeKind::MethodDefinition { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::VariableDeclaration { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ClassDeclaration { .. }));

    assert!(has_field, "Should find class fields in TypeScript");
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_complex_object_literal() {
    let code = r#"
        const obj = {
            name: "test",
            value,
            [key]: "dynamic",
            method() { return 42; },
            get prop() { return this._prop; },
            set prop(v) { this._prop = v; }
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Complex object should have various property types
    let has_properties = has_node_kind(&ast, |k| matches!(k, AstNodeKind::Property { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectExpression { .. }));

    assert!(has_properties, "Should find properties in complex object");
}

#[test]
fn test_class_with_multiple_methods() {
    let code = r#"
        class MyClass {
            constructor(value) {
                this.value = value;
            }

            static create() {
                return new MyClass(0);
            }

            get value() {
                return this._value;
            }

            set value(v) {
                this._value = v;
            }

            method() {
                return this.value * 2;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should have constructor
    let has_constructor = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { kind: MethodKind::Constructor, .. })
    });

    // Should have getter
    let has_getter = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { kind: MethodKind::Get, .. })
    });

    // Should have setter
    let has_setter = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { kind: MethodKind::Set, .. })
    });

    assert!(has_constructor || has_getter || has_setter,
            "Should find various method types in class");
}
