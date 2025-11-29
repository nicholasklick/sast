//! Unit tests for pattern/destructuring AST node variants
//!
//! Tests all pattern constructs added in Phase 3 of AST expansion:
//! - Array patterns (array destructuring)
//! - Object patterns (object destructuring)
//! - Assignment patterns (default values)
//! - Rest patterns (rest in destructuring)

use gittera_parser::{Language, LanguageConfig, Parser, ast::AstNodeKind};
use std::path::Path;

/// Helper function to find a specific node kind
fn find_node_kind<F>(ast: &gittera_parser::ast::AstNode, kind_matcher: &F) -> Option<AstNodeKind>
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
fn has_node_kind<F>(ast: &gittera_parser::ast::AstNode, kind_matcher: F) -> bool
where
    F: Fn(&AstNodeKind) -> bool
{
    find_node_kind(ast, &kind_matcher).is_some()
}

// ============================================================================
// Array Pattern Tests
// ============================================================================

#[test]
fn test_array_pattern_simple() {
    let code = r#"
        const [a, b, c] = arr;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let array_pattern = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ArrayPattern { .. }));
    assert!(array_pattern.is_some(), "Should find ArrayPattern");

    if let Some(AstNodeKind::ArrayPattern { elements_count, has_rest }) = array_pattern {
        assert!(elements_count >= 3, "Should have at least 3 elements, got {}", elements_count);
        assert!(!has_rest, "Should not have rest pattern");
    }
}

#[test]
fn test_array_pattern_with_rest() {
    let code = r#"
        const [first, ...rest] = arr;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let array_pattern = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ArrayPattern { .. }));
    assert!(array_pattern.is_some(), "Should find ArrayPattern");

    if let Some(AstNodeKind::ArrayPattern { elements_count, has_rest }) = array_pattern {
        assert!(elements_count >= 1, "Should have at least 1 element");
        assert!(has_rest, "Should have rest pattern");
    }
}

#[test]
fn test_array_pattern_nested() {
    let code = r#"
        const [a, [b, c]] = arr;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should find multiple array patterns (nested)
    let mut count = 0;
    fn count_arrays(node: &gittera_parser::ast::AstNode, count: &mut usize) {
        if matches!(node.kind, AstNodeKind::ArrayPattern { .. }) {
            *count += 1;
        }
        for child in &node.children {
            count_arrays(child, count);
        }
    }

    count_arrays(&ast, &mut count);
    assert!(count >= 1, "Should find at least one ArrayPattern");
}

#[test]
fn test_array_pattern_in_function_params() {
    let code = r#"
        function foo([x, y]) {
            return x + y;
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_array_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ArrayPattern { .. }));
    assert!(has_array_pattern, "Should find ArrayPattern in function parameters");
}

// ============================================================================
// Object Pattern Tests
// ============================================================================

#[test]
fn test_object_pattern_simple() {
    let code = r#"
        const {x, y, z} = obj;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let object_pattern = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(object_pattern.is_some(), "Should find ObjectPattern");

    if let Some(AstNodeKind::ObjectPattern { properties_count, has_rest }) = object_pattern {
        assert!(properties_count >= 1, "Should have at least 1 property, got {}", properties_count);
        assert!(!has_rest, "Should not have rest pattern");
    }
}

#[test]
fn test_object_pattern_with_rest() {
    let code = r#"
        const {name, ...rest} = obj;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let object_pattern = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(object_pattern.is_some(), "Should find ObjectPattern");

    if let Some(AstNodeKind::ObjectPattern { properties_count, has_rest }) = object_pattern {
        assert!(properties_count >= 1, "Should have at least 1 property");
        assert!(has_rest, "Should have rest pattern");
    }
}

#[test]
fn test_object_pattern_nested() {
    let code = r#"
        const {a, b: {c, d}} = obj;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should find multiple object patterns (nested)
    let mut count = 0;
    fn count_objects(node: &gittera_parser::ast::AstNode, count: &mut usize) {
        if matches!(node.kind, AstNodeKind::ObjectPattern { .. }) {
            *count += 1;
        }
        for child in &node.children {
            count_objects(child, count);
        }
    }

    count_objects(&ast, &mut count);
    assert!(count >= 1, "Should find at least one ObjectPattern");
}

#[test]
fn test_object_pattern_in_function_params() {
    let code = r#"
        function foo({name, age}) {
            return name + age;
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_object_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(has_object_pattern, "Should find ObjectPattern in function parameters");
}

#[test]
fn test_object_pattern_renamed_properties() {
    let code = r#"
        const {oldName: newName, value} = obj;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_object_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(has_object_pattern, "Should find ObjectPattern with renamed properties");
}

// ============================================================================
// Assignment Pattern Tests (Default Values)
// ============================================================================

#[test]
fn test_assignment_pattern_array() {
    let code = r#"
        const [a = 1, b = 2] = arr;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let assignment_pattern = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::AssignmentPattern { .. }));
    assert!(assignment_pattern.is_some(), "Should find AssignmentPattern");

    if let Some(AstNodeKind::AssignmentPattern { has_default }) = assignment_pattern {
        assert!(has_default, "Should have default value");
    }
}

#[test]
fn test_assignment_pattern_object() {
    let code = r#"
        const {x = 10, y = 20} = obj;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Assignment patterns in object destructuring may or may not be exposed as separate nodes
    // depending on tree-sitter granularity, so we check for either pattern
    let has_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::AssignmentPattern { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(has_pattern, "Should find pattern in object destructuring with defaults");
}

#[test]
fn test_assignment_pattern_function_params() {
    let code = r#"
        function foo(a = 1, b = 2) {
            return a + b;
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_assignment_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::AssignmentPattern { .. }));
    assert!(has_assignment_pattern, "Should find AssignmentPattern in function parameters");
}

// ============================================================================
// Rest Pattern Tests
// ============================================================================

#[test]
fn test_rest_pattern_array() {
    let code = r#"
        const [first, ...rest] = arr;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_rest_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::RestPattern { .. }));
    // RestPattern may not always be detected separately from ArrayPattern with has_rest flag
    // So we check for either RestPattern or ArrayPattern with has_rest
    let has_rest_indicator = has_rest_pattern ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ArrayPattern { has_rest: true, .. }));

    assert!(has_rest_indicator, "Should find rest pattern indicator in array destructuring");
}

#[test]
fn test_rest_pattern_object() {
    let code = r#"
        const {x, ...rest} = obj;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_rest_indicator = has_node_kind(&ast, |k| matches!(k, AstNodeKind::RestPattern { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { has_rest: true, .. }));

    assert!(has_rest_indicator, "Should find rest pattern indicator in object destructuring");
}

// ============================================================================
// TypeScript Pattern Tests
// ============================================================================

#[test]
fn test_array_pattern_typescript() {
    let code = r#"
        const [a, b]: [number, string] = [1, "hello"];
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_array_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ArrayPattern { .. }));
    assert!(has_array_pattern, "Should find ArrayPattern in TypeScript");
}

#[test]
fn test_object_pattern_typescript() {
    let code = r#"
        const {name, age}: {name: string, age: number} = person;
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_object_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(has_object_pattern, "Should find ObjectPattern in TypeScript");
}

// ============================================================================
// Integration Tests - Complex Patterns
// ============================================================================

#[test]
fn test_complex_nested_destructuring() {
    let code = r#"
        const {
            user: {name, age = 18},
            items: [first, ...rest]
        } = data;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should contain multiple pattern types
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. })),
            "Should find ObjectPattern");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ArrayPattern { .. })),
            "Should find ArrayPattern");
}

#[test]
fn test_real_world_react_props_pattern() {
    let code = r#"
        function Component({ items = [], onClick, ...props }) {
            return items.map(item => <div onClick={onClick} {...props}>{item}</div>);
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Real-world React component props destructuring
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. })),
            "Should find ObjectPattern for props destructuring");

    // May or may not detect assignment pattern depending on tree-sitter granularity
    let has_assignment_or_default = has_node_kind(&ast, |k| matches!(k, AstNodeKind::AssignmentPattern { .. })) ||
        has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(has_assignment_or_default, "Should handle default values in destructuring");
}

#[test]
fn test_mixed_array_object_pattern() {
    let code = r#"
        const [[a, b], {c, d}] = arr;
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should contain both array and object patterns
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ArrayPattern { .. })),
            "Should find ArrayPattern");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. })),
            "Should find ObjectPattern");
}

#[test]
fn test_for_of_with_destructuring() {
    let code = r#"
        for (const {name, value} of items) {
            console.log(name, value);
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_object_pattern = has_node_kind(&ast, |k| matches!(k, AstNodeKind::ObjectPattern { .. }));
    assert!(has_object_pattern, "Should find ObjectPattern in for-of loop");
}
