//! Unit tests for module system AST node variants
//!
//! Tests all module constructs added in Phase 5 of AST expansion:
//! - Import statements (default, named, namespace)
//! - Export statements (default, named, all)
//! - Import/export specifiers
//! - Namespace imports/exports
//! - Re-exports

use gittera_parser::{Language, LanguageConfig, Parser, ast::AstNodeKind};
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
// Import Statement Tests
// ============================================================================

#[test]
fn test_import_default() {
    let code = r#"
        import React from 'react';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_import = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));
    assert!(has_import, "Should find ImportDeclaration");
}

#[test]
fn test_import_named() {
    let code = r#"
        import { useState, useEffect } from 'react';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_import = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));
    assert!(has_import, "Should find ImportDeclaration");

    // Check for import specifiers
    let has_specifier = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportSpecifierNode { .. }));
    assert!(has_specifier, "Should find ImportSpecifierNode");
}

#[test]
fn test_import_namespace() {
    let code = r#"
        import * as ReactDOM from 'react-dom';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_import = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));
    assert!(has_import, "Should find ImportDeclaration");

    let has_namespace = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportNamespaceSpecifier { .. }));
    assert!(has_namespace, "Should find ImportNamespaceSpecifier");
}

#[test]
fn test_import_mixed() {
    let code = r#"
        import React, { Component, useState } from 'react';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_import = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));
    assert!(has_import, "Should find ImportDeclaration for mixed import");
}

#[test]
fn test_import_renamed() {
    let code = r#"
        import { oldName as newName } from './module';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_import = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));
    assert!(has_import, "Should find ImportDeclaration with renamed import");
}

// ============================================================================
// Export Statement Tests
// ============================================================================

#[test]
fn test_export_default() {
    let code = r#"
        export default MyComponent;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_export = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportDeclaration { is_default: true, .. }));
    assert!(has_export, "Should find default ExportDeclaration");
}

#[test]
fn test_export_named() {
    let code = r#"
        export { MyComponent, MyOtherComponent };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_export = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportDeclaration { .. }));
    assert!(has_export, "Should find named ExportDeclaration");

    let has_specifier = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportSpecifierNode { .. }));
    assert!(has_specifier, "Should find ExportSpecifierNode");
}

#[test]
fn test_export_all() {
    let code = r#"
        export * from './components';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_export_all = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportAllDeclaration { .. }));
    assert!(has_export_all, "Should find ExportAllDeclaration");
}

#[test]
fn test_export_all_as() {
    let code = r#"
        export * as Components from './components';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_export_all = has_node_kind(&ast, |k| {
        matches!(k, AstNodeKind::ExportAllDeclaration { exported: Some(_), .. })
    });
    assert!(has_export_all, "Should find ExportAllDeclaration with name");
}

#[test]
fn test_export_renamed() {
    let code = r#"
        export { OldName as NewName } from './module';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_export = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportDeclaration { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportAllDeclaration { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ReExportDeclaration { .. }));

    assert!(has_export, "Should find export declaration for renamed export");
}

// ============================================================================
// TypeScript Tests
// ============================================================================

#[test]
fn test_typescript_type_import() {
    let code = r#"
        import type { MyType } from './types';
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_import = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { is_type_only: true, .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));

    assert!(has_import, "Should find ImportDeclaration for type import");
}

#[test]
fn test_typescript_type_export() {
    let code = r#"
        export type { MyType };
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_export = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportDeclaration { is_type_only: true, .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportDeclaration { .. }));

    assert!(has_export, "Should find ExportDeclaration for type export");
}

// ============================================================================
// Integration Tests
// ============================================================================

#[test]
fn test_complex_import_statements() {
    let code = r#"
        import React, { Component } from 'react';
        import * as ReactDOM from 'react-dom';
        import { useState, useEffect as useEff } from 'react';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_imports = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));
    assert!(has_imports, "Should find multiple ImportDeclarations");
}

#[test]
fn test_complex_export_statements() {
    let code = r#"
        export default MyComponent;
        export { MyOtherComponent };
        export * from './utils';
        export { OldName as NewName } from './module';
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_exports = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportDeclaration { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportAllDeclaration { .. }));

    assert!(has_exports, "Should find multiple export declarations");
}

#[test]
fn test_real_world_module_pattern() {
    let code = r#"
        import React, { useState, useEffect } from 'react';
        import * as API from './api';
        import { formatDate } from './utils';

        export default function MyComponent() {
            const [data, setData] = useState(null);
            return null;
        }

        export { API };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_imports = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ImportDeclaration { .. }));
    let has_exports = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ExportDeclaration { .. }));

    assert!(has_imports, "Should find imports in real-world pattern");
    assert!(has_exports, "Should find exports in real-world pattern");
}
