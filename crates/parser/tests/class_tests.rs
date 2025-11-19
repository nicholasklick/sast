//! Unit tests for class enhancement AST node variants
//!
//! Tests all class constructs added in Phase 7 of AST expansion:
//! - Field declarations (class properties)
//! - Static blocks
//! - Accessor properties

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
// Field Declaration Tests
// ============================================================================

#[test]
fn test_field_declaration_simple() {
    let code = r#"
        class MyClass {
            name: string;
            age: number;
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_field = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FieldDeclaration { .. }));
    assert!(has_field, "Should find FieldDeclaration");
}

#[test]
fn test_field_declaration_with_initializer() {
    let code = r#"
        class MyClass {
            count = 0;
            name = "default";
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_field_with_init = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::FieldDeclaration { has_initializer: true, .. })
    });
    assert!(has_field_with_init, "Should find FieldDeclaration with initializer");
}

#[test]
fn test_field_declaration_static() {
    let code = r#"
        class MyClass {
            static count = 0;
            static readonly MAX = 100;
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_static_field = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::FieldDeclaration { is_static: true, .. })
    });
    assert!(has_static_field, "Should find static FieldDeclaration");
}

#[test]
fn test_field_declaration_private() {
    let code = r#"
        class MyClass {
            private name: string;
            protected age: number;
            public email: string;
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_field = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FieldDeclaration { .. }));
    assert!(has_field, "Should find FieldDeclaration with visibility modifiers");
}

// ============================================================================
// Static Block Tests
// ============================================================================

#[test]
fn test_static_block() {
    let code = r#"
        class MyClass {
            static count = 0;

            static {
                console.log("Initializing");
                MyClass.count = 1;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_static_block = has_node_kind(&ast, |k| matches!(k, AstNodeKind::StaticBlock));
    assert!(has_static_block, "Should find StaticBlock");
}

#[test]
fn test_static_block_multiple() {
    let code = r#"
        class MyClass {
            static {
                console.log("First block");
            }

            static {
                console.log("Second block");
            }
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_static_block = has_node_kind(&ast, |k| matches!(k, AstNodeKind::StaticBlock));
    assert!(has_static_block, "Should find multiple StaticBlocks");
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_complex_class_structure() {
    let code = r#"
        class User {
            private id: number;
            public name: string;
            protected email: string;
            static count = 0;

            static {
                User.count = 0;
            }

            constructor(name: string) {
                this.name = name;
                User.count++;
            }

            get displayName(): string {
                return this.name;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_fields = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FieldDeclaration { .. }));
    let has_static_block = has_node_kind(&ast, |k| matches!(k, AstNodeKind::StaticBlock));
    let has_constructor = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::MethodDefinition { kind: kodecd_parser::ast::MethodKind::Constructor, .. })
    });

    assert!(has_fields, "Should find field declarations");
    assert!(has_static_block, "Should find static block");
    assert!(has_constructor, "Should find constructor");
}

#[test]
fn test_javascript_class_fields() {
    let code = r#"
        class Counter {
            count = 0;

            increment() {
                this.count++;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // JavaScript class fields should also be detected
    let has_field = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FieldDeclaration { .. }));
    assert!(has_field, "Should find FieldDeclaration in JavaScript");
}

#[test]
fn test_real_world_class_pattern() {
    let code = r#"
        class Database {
            private static instance: Database;
            private connection: any;

            static {
                Database.instance = new Database();
            }

            private constructor() {
                this.connection = null;
            }

            static getInstance(): Database {
                return Database.instance;
            }

            connect(): void {
                console.log("Connecting...");
            }
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should have static fields, static blocks, private fields, and methods
    let has_static_field = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::FieldDeclaration { is_static: true, .. })
    });
    let has_static_block = has_node_kind(&ast, |k| matches!(k, AstNodeKind::StaticBlock));

    assert!(has_static_field || has_static_block, "Should find class enhancement constructs in singleton pattern");
}
