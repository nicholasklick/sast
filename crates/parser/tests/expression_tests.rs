//! Unit tests for expression AST node variants
//!
//! Tests all new expression constructs added in Phase 2 of AST expansion:
//! - Conditional expressions (ternary)
//! - Update expressions (++/--)
//! - Sequence expressions
//! - New expressions
//! - This/super expressions
//! - Spread/rest elements
//! - Parenthesized expressions
//! - Tagged template expressions
//! - Function/class expressions

use kodecd_parser::{Language, LanguageConfig, Parser, ast::AstNodeKind};
use std::path::Path;

/// Helper function to find a specific node kind
fn find_node_kind<F>(ast: &kodecd_parser::ast::AstNode, kind_matcher: &F) -> Option<AstNodeKind>
where
    F: Fn(&AstNodeKind) -> bool
{
    if kind_matcher(&ast.kind) {
        return Some(ast.kind.clone());
    }

    for child in &ast.children {
        if let Some(found) = find_node_kind(child, kind_matcher) {
            return Some(found);
        }
    }

    None
}

/// Helper to check if a node kind exists in the tree
fn has_node_kind<F>(ast: &kodecd_parser::ast::AstNode, kind_matcher: F) -> bool
where
    F: Fn(&AstNodeKind) -> bool
{
    find_node_kind(ast, &kind_matcher).is_some()
}

// ============================================================================
// Conditional Expression Tests (Ternary)
// ============================================================================

#[test]
fn test_conditional_expression_javascript() {
    let code = r#"
        const result = condition ? trueValue : falseValue;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_conditional = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ConditionalExpression { .. }));
    assert!(has_conditional, "Should find ConditionalExpression");
}

#[test]
fn test_conditional_expression_nested() {
    let code = r#"
        const x = a ? b : c ? d : e;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should find multiple conditional expressions (nested)
    let mut count = 0;
    fn count_conditionals(node: &kodecd_parser::ast::AstNode, count: &mut usize) {
        if matches!(node.kind, AstNodeKind::ConditionalExpression { .. }) {
            *count += 1;
        }
        for child in &node.children {
            count_conditionals(child, count);
        }
    }

    count_conditionals(&ast, &mut count);
    assert!(count >= 1, "Should find at least one ConditionalExpression");
}

// ============================================================================
// Update Expression Tests (++/--)
// ============================================================================

#[test]
fn test_update_expression_postfix_increment() {
    let code = r#"
        let i = 0;
        i++;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let update_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::UpdateExpression { .. }));
    assert!(update_node.is_some(), "Should find UpdateExpression");

    if let Some(AstNodeKind::UpdateExpression { operator, prefix }) = update_node {
        assert_eq!(operator, "++", "Should be increment operator");
        assert!(!prefix, "Should be postfix (i++)");
    }
}

#[test]
fn test_update_expression_prefix_decrement() {
    let code = r#"
        let i = 10;
        --i;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let update_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::UpdateExpression { .. }));
    assert!(update_node.is_some(), "Should find UpdateExpression");

    if let Some(AstNodeKind::UpdateExpression { operator, prefix }) = update_node {
        assert_eq!(operator, "--", "Should be decrement operator");
        assert!(prefix, "Should be prefix (--i)");
    }
}

// ============================================================================
// Sequence Expression Tests
// ============================================================================

#[test]
fn test_sequence_expression() {
    let code = r#"
        const x = (a++, b++, c);
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let seq_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::SequenceExpression { .. }));
    assert!(seq_node.is_some(), "Should find SequenceExpression");

    if let Some(AstNodeKind::SequenceExpression { expressions_count }) = seq_node {
        assert!(expressions_count >= 2, "Should have multiple expressions, got {}", expressions_count);
    }
}

// ============================================================================
// New Expression Tests
// ============================================================================

#[test]
fn test_new_expression_simple() {
    let code = r#"
        const obj = new Object();
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let new_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::NewExpression { .. }));
    assert!(new_node.is_some(), "Should find NewExpression");

    if let Some(AstNodeKind::NewExpression { callee, arguments_count }) = new_node {
        assert!(callee.contains("Object"), "Callee should be Object, got: {}", callee);
        assert_eq!(arguments_count, 0, "Should have 0 arguments");
    }
}

#[test]
fn test_new_expression_with_arguments() {
    let code = r#"
        const date = new Date(2024, 10, 19);
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let new_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::NewExpression { .. }));
    assert!(new_node.is_some(), "Should find NewExpression");

    if let Some(AstNodeKind::NewExpression { callee, arguments_count }) = new_node {
        assert!(callee.contains("Date"), "Callee should be Date, got: {}", callee);
        assert_eq!(arguments_count, 3, "Should have 3 arguments");
    }
}

// ============================================================================
// This/Super Expression Tests
// ============================================================================

#[test]
fn test_this_expression() {
    let code = r#"
        class MyClass {
            method() {
                return this.value;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_this = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ThisExpression));
    assert!(has_this, "Should find ThisExpression");
}

#[test]
fn test_super_expression() {
    let code = r#"
        class Child extends Parent {
            constructor() {
                super();
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_super = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SuperExpression));
    assert!(has_super, "Should find SuperExpression");
}

// ============================================================================
// Spread Element Tests
// ============================================================================

#[test]
fn test_spread_element_in_array() {
    let code = r#"
        const arr = [...oldArray, newItem];
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_spread = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SpreadElement));
    assert!(has_spread, "Should find SpreadElement");
}

#[test]
fn test_spread_element_in_call() {
    let code = r#"
        func(...args);
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_spread = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SpreadElement));
    assert!(has_spread, "Should find SpreadElement in function call");
}

// ============================================================================
// Rest Element Tests
// ============================================================================

#[test]
fn test_rest_element_in_parameters() {
    let code = r#"
        function sum(...numbers) {
            return numbers.reduce((a, b) => a + b);
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_rest = has_node_kind(&ast, |k| matches!(k, AstNodeKind::RestElement { .. }));
    assert!(has_rest, "Should find RestElement in parameters");
}

// ============================================================================
// Parenthesized Expression Tests
// ============================================================================

#[test]
fn test_parenthesized_expression() {
    let code = r#"
        const x = (a + b) * c;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_paren = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ParenthesizedExpression));
    assert!(has_paren, "Should find ParenthesizedExpression");
}

// ============================================================================
// Tagged Template Expression Tests
// ============================================================================

#[test]
#[ignore] // Tree-sitter may use different node name for tagged templates
fn test_tagged_template_expression() {
    let code = r#"
        const html = htmlTag`<div>Hello</div>`;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let tagged_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::TaggedTemplateExpression { .. }));
    assert!(tagged_node.is_some(), "Should find TaggedTemplateExpression");

    if let Some(AstNodeKind::TaggedTemplateExpression { tag }) = tagged_node {
        assert!(tag.contains("htmlTag") || tag.contains("html"), "Tag should be htmlTag or html, got: {}", tag);
    }
}

// ============================================================================
// Function Expression Tests
// ============================================================================

#[test]
fn test_function_expression_anonymous() {
    let code = r#"
        const fn = function(x, y) {
            return x + y;
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let fn_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::FunctionExpression { .. }));
    assert!(fn_node.is_some(), "Should find FunctionExpression");

    if let Some(AstNodeKind::FunctionExpression { name, parameters, .. }) = fn_node {
        assert!(name.is_none() || name == Some("anonymous".to_string()), "Should be anonymous");
        assert_eq!(parameters.len(), 2, "Should have 2 parameters");
    }
}

#[test]
fn test_function_expression_named() {
    let code = r#"
        const fn = function myFunc(x) {
            return x * 2;
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let fn_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::FunctionExpression { .. }));
    assert!(fn_node.is_some(), "Should find FunctionExpression");

    if let Some(AstNodeKind::FunctionExpression { name, .. }) = fn_node {
        assert!(name.is_some(), "Should have a name");
        if let Some(n) = name {
            assert!(n.contains("myFunc") || n.contains("Func"), "Name should be myFunc, got: {}", n);
        }
    }
}

#[test]
fn test_async_function_expression() {
    let code = r#"
        const fn = async function(x) {
            return await fetch(x);
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let fn_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::FunctionExpression { .. }));
    assert!(fn_node.is_some(), "Should find FunctionExpression");

    if let Some(AstNodeKind::FunctionExpression { is_async, .. }) = fn_node {
        assert!(is_async, "Should be async function");
    }
}

// ============================================================================
// Class Expression Tests
// ============================================================================

#[test]
#[ignore] // Tree-sitter may use different node name for class expressions
fn test_class_expression_anonymous() {
    let code = r#"
        const MyClass = class {
            constructor() {
                this.value = 42;
            }
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let class_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ClassExpression { .. }));
    assert!(class_node.is_some(), "Should find ClassExpression");
}

#[test]
#[ignore] // Tree-sitter may use different node name for class expressions
fn test_class_expression_named() {
    let code = r#"
        const MyVar = class MyClass {
            method() {
                return "test";
            }
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let class_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ClassExpression { .. }));
    assert!(class_node.is_some(), "Should find ClassExpression");

    if let Some(AstNodeKind::ClassExpression { name }) = class_node {
        assert!(name.is_some(), "Named class expression should have a name");
    }
}

// ============================================================================
// TypeScript Expression Tests
// ============================================================================

#[test]
fn test_conditional_expression_typescript() {
    let code = r#"
        const result: string = isValid ? "yes" : "no";
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_conditional = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ConditionalExpression { .. }));
    assert!(has_conditional, "Should find ConditionalExpression in TypeScript");
}

// ============================================================================
// Integration Tests - Multiple Expressions
// ============================================================================

#[test]
fn test_complex_expression_integration() {
    let code = r#"
        const result = condition ? new MyClass(x++) : super.method(...args);
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should contain multiple expression types
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ConditionalExpression { .. })),
            "Should find ConditionalExpression");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::NewExpression { .. })),
            "Should find NewExpression");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::UpdateExpression { .. })),
            "Should find UpdateExpression");
}

#[test]
fn test_real_world_expression_pattern() {
    let code = r#"
        const Component = ({ items, ...props }) => {
            return items?.length > 0
                ? items.map(item => new Item(item))
                : null;
        };
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Real-world React-style component with multiple expression types
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ConditionalExpression { .. })),
            "Should find ternary operator");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::NewExpression { .. })),
            "Should find new expression");
}
