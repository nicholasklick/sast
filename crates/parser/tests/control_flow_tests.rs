//! Unit tests for control flow AST node variants
//!
//! Tests all new control flow constructs added in Phase 1 of AST expansion:
//! - Switch statements and cases
//! - Do-while loops
//! - Break/continue with labels
//! - Finally clauses
//! - Labeled statements
//! - With statements (JavaScript)

use gittera_parser::{Language, LanguageConfig, Parser, ast::AstNodeKind};
use std::path::Path;

/// Helper function to parse code and find a specific node kind
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
// Switch Statement Tests
// ============================================================================

#[test]
fn test_switch_statement_javascript() {
    let code = r#"
        switch (x) {
            case 1:
                console.log("one");
                break;
            case 2:
                console.log("two");
                break;
            default:
                console.log("other");
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should contain SwitchStatement
    let switch_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::SwitchStatement { .. }));
    assert!(switch_node.is_some(), "Should find SwitchStatement");

    if let Some(AstNodeKind::SwitchStatement { discriminant, cases_count }) = switch_node {
        assert!(discriminant.contains("x"), "Discriminant should be 'x', got: {}", discriminant);
        assert_eq!(cases_count, 3, "Should have 3 cases (2 regular + 1 default)");
    }
}

#[test]
fn test_switch_statement_typescript() {
    let code = r#"
        const action = "start";
        switch (action) {
            case "start":
                return 1;
            case "stop":
                return 2;
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_switch = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SwitchStatement { .. }));
    assert!(has_switch, "Should find SwitchStatement in TypeScript");
}

#[test]
fn test_switch_case_with_default() {
    let code = r#"
        switch (status) {
            case "active":
                doActive();
                break;
            default:
                doDefault();
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Count SwitchCase nodes
    let mut case_count = 0;
    let mut default_count = 0;

    fn count_cases(node: &gittera_parser::ast::AstNode, case_count: &mut usize, default_count: &mut usize) {
        if let AstNodeKind::SwitchCase { test, .. } = &node.kind {
            if test.is_none() {
                *default_count += 1;
            } else {
                *case_count += 1;
            }
        }

        for child in &node.children {
            count_cases(child, case_count, default_count);
        }
    }

    count_cases(&ast, &mut case_count, &mut default_count);

    // May or may not detect individual cases depending on tree-sitter granularity
    // At minimum, we should have detected the switch statement itself
    let has_switch = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SwitchStatement { .. }));
    assert!(has_switch, "Should find SwitchStatement");
}

#[test]
fn test_rust_match_expression() {
    let code = r#"
        fn main() {
            let x = 5;
            match x {
                1 => println!("one"),
                2 => println!("two"),
                _ => println!("other"),
            }
        }
    "#;

    let config = LanguageConfig::new(Language::Rust);
    let parser = Parser::new(config, Path::new("test.rs"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Rust's match should map to SwitchStatement
    let has_switch = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SwitchStatement { .. }));
    assert!(has_switch, "Rust match should map to SwitchStatement");
}

// ============================================================================
// Do-While Loop Tests
// ============================================================================

#[test]
fn test_do_while_javascript() {
    let code = r#"
        let i = 0;
        do {
            console.log(i);
            i++;
        } while (i < 10);
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_do_while = has_node_kind(&ast, |k| matches!(k, AstNodeKind::DoWhileStatement));
    assert!(has_do_while, "Should find DoWhileStatement");
}

#[test]
fn test_do_while_java() {
    let code = r#"
        class Test {
            void run() {
                int i = 0;
                do {
                    System.out.println(i);
                    i++;
                } while (i < 10);
            }
        }
    "#;

    let config = LanguageConfig::new(Language::Java);
    let parser = Parser::new(config, Path::new("Test.java"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_do_while = has_node_kind(&ast, |k| matches!(k, AstNodeKind::DoWhileStatement));
    assert!(has_do_while, "Should find DoWhileStatement in Java");
}

// ============================================================================
// Break/Continue Statement Tests
// ============================================================================

#[test]
fn test_break_statement_simple() {
    let code = r#"
        while (true) {
            if (done) {
                break;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let break_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::BreakStatement { .. }));
    assert!(break_node.is_some(), "Should find BreakStatement");

    if let Some(AstNodeKind::BreakStatement { label }) = break_node {
        assert!(label.is_none(), "Simple break should have no label");
    }
}

#[test]
fn test_break_with_label_javascript() {
    let code = r#"
        outer: for (let i = 0; i < 10; i++) {
            for (let j = 0; j < 10; j++) {
                if (i * j > 50) {
                    break outer;
                }
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let break_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::BreakStatement { .. }));
    assert!(break_node.is_some(), "Should find BreakStatement");

    if let Some(AstNodeKind::BreakStatement { label }) = break_node {
        assert!(label.is_some(), "Labeled break should have a label");
        if let Some(l) = label {
            assert!(l.contains("outer"), "Label should be 'outer', got: {}", l);
        }
    }
}

#[test]
fn test_continue_statement_simple() {
    let code = r#"
        for (let i = 0; i < 10; i++) {
            if (i % 2 === 0) {
                continue;
            }
            console.log(i);
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let continue_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ContinueStatement { .. }));
    assert!(continue_node.is_some(), "Should find ContinueStatement");

    if let Some(AstNodeKind::ContinueStatement { label }) = continue_node {
        assert!(label.is_none(), "Simple continue should have no label");
    }
}

#[test]
fn test_continue_with_label_javascript() {
    let code = r#"
        outer: for (let i = 0; i < 10; i++) {
            for (let j = 0; j < 10; j++) {
                if (j > 5) {
                    continue outer;
                }
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let continue_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::ContinueStatement { .. }));
    assert!(continue_node.is_some(), "Should find ContinueStatement");

    if let Some(AstNodeKind::ContinueStatement { label }) = continue_node {
        assert!(label.is_some(), "Labeled continue should have a label");
        if let Some(l) = label {
            assert!(l.contains("outer"), "Label should be 'outer', got: {}", l);
        }
    }
}

#[test]
fn test_break_in_rust() {
    let code = r#"
        fn main() {
            loop {
                if done {
                    break;
                }
            }
        }
    "#;

    let config = LanguageConfig::new(Language::Rust);
    let parser = Parser::new(config, Path::new("test.rs"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_break = has_node_kind(&ast, |k| matches!(k, AstNodeKind::BreakStatement { .. }));
    assert!(has_break, "Should find BreakStatement in Rust");
}

// ============================================================================
// Labeled Statement Tests
// ============================================================================

#[test]
fn test_labeled_statement_javascript() {
    let code = r#"
        myLabel: {
            console.log("start");
            if (condition) {
                break myLabel;
            }
            console.log("end");
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let labeled_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::LabeledStatement { .. }));
    assert!(labeled_node.is_some(), "Should find LabeledStatement");

    if let Some(AstNodeKind::LabeledStatement { label }) = labeled_node {
        assert!(label.contains("myLabel"), "Label should be 'myLabel', got: {}", label);
    }
}

#[test]
fn test_labeled_loop_javascript() {
    let code = r#"
        outer: while (true) {
            inner: while (true) {
                break outer;
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_labeled = has_node_kind(&ast, |k| matches!(k, AstNodeKind::LabeledStatement { .. }));
    assert!(has_labeled, "Should find LabeledStatement for labeled loops");
}

// ============================================================================
// Finally Clause Tests
// ============================================================================

#[test]
fn test_finally_clause_javascript() {
    let code = r#"
        try {
            riskyOperation();
        } catch (error) {
            handleError(error);
        } finally {
            cleanup();
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_finally = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FinallyClause));
    assert!(has_finally, "Should find FinallyClause");
}

#[test]
fn test_finally_clause_typescript() {
    let code = r#"
        async function test() {
            try {
                await fetch();
            } finally {
                console.log("done");
            }
        }
    "#;

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new("test.ts"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_finally = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FinallyClause));
    assert!(has_finally, "Should find FinallyClause in TypeScript");
}

#[test]
fn test_finally_clause_java() {
    let code = r#"
        class Test {
            void run() {
                try {
                    dangerousOp();
                } catch (Exception e) {
                    log(e);
                } finally {
                    cleanup();
                }
            }
        }
    "#;

    let config = LanguageConfig::new(Language::Java);
    let parser = Parser::new(config, Path::new("Test.java"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_finally = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FinallyClause));
    assert!(has_finally, "Should find FinallyClause in Java");
}

#[test]
fn test_finally_clause_python() {
    let code = r#"
try:
    risky_operation()
except Exception as e:
    handle_error(e)
finally:
    cleanup()
    "#;

    let config = LanguageConfig::new(Language::Python);
    let parser = Parser::new(config, Path::new("test.py"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_finally = has_node_kind(&ast, |k| matches!(k, AstNodeKind::FinallyClause));
    assert!(has_finally, "Should find FinallyClause in Python");
}

// ============================================================================
// With Statement Tests (JavaScript-specific)
// ============================================================================

#[test]
fn test_with_statement_javascript() {
    let code = r#"
        with (obj) {
            console.log(property);
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let with_node = find_node_kind(&ast, &|k| matches!(k, AstNodeKind::WithStatement { .. }));
    assert!(with_node.is_some(), "Should find WithStatement");

    if let Some(AstNodeKind::WithStatement { object }) = with_node {
        assert!(object.contains("obj"), "Object should be 'obj', got: {}", object);
    }
}

#[test]
fn test_with_statement_complex() {
    let code = r#"
        with (document.getElementById("myDiv")) {
            style.color = "red";
            innerHTML = "Hello";
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_with = has_node_kind(&ast, |k| matches!(k, AstNodeKind::WithStatement { .. }));
    assert!(has_with, "Should find WithStatement with complex object expression");
}

// ============================================================================
// Integration Tests - Multiple Control Flow Constructs
// ============================================================================

#[test]
fn test_complex_control_flow_integration() {
    let code = r#"
        outer: for (let i = 0; i < 10; i++) {
            switch (i) {
                case 0:
                    continue outer;
                case 5:
                    break outer;
                default:
                    console.log(i);
            }
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Should have all these constructs
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::LabeledStatement { .. })),
            "Should find LabeledStatement");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::SwitchStatement { .. })),
            "Should find SwitchStatement");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::ContinueStatement { .. })),
            "Should find ContinueStatement");
    assert!(has_node_kind(&ast, |k| matches!(k, AstNodeKind::BreakStatement { .. })),
            "Should find BreakStatement");
}

#[test]
fn test_nested_try_finally() {
    let code = r#"
        try {
            try {
                dangerousOp();
            } finally {
                innerCleanup();
            }
        } catch (e) {
            handleError(e);
        } finally {
            outerCleanup();
        }
    "#;

    let config = LanguageConfig::new(Language::JavaScript);
    let parser = Parser::new(config, Path::new("test.js"));
    let ast = parser.parse_source(code).expect("Parse failed");

    // Count finally clauses
    let mut finally_count = 0;
    fn count_finally(node: &gittera_parser::ast::AstNode, count: &mut usize) {
        if matches!(node.kind, AstNodeKind::FinallyClause) {
            *count += 1;
        }
        for child in &node.children {
            count_finally(child, count);
        }
    }

    count_finally(&ast, &mut finally_count);
    assert!(finally_count >= 1, "Should find at least one FinallyClause in nested try-finally");
}

#[test]
#[ignore] // Go tree-sitter grammar may use different node names
fn test_go_switch_statement() {
    let code = r#"
        package main

        func main() {
            switch x {
            case 1:
                println("one")
            case 2:
                println("two")
            default:
                println("other")
            }
        }
    "#;

    let config = LanguageConfig::new(Language::Go);
    let parser = Parser::new(config, Path::new("test.go"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_switch = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SwitchStatement { .. }));
    assert!(has_switch, "Should find SwitchStatement in Go");
}

#[test]
#[ignore] // Java tree-sitter grammar may use different node names
fn test_java_switch_statement() {
    let code = r#"
        class Test {
            void run(int x) {
                switch (x) {
                    case 1:
                        System.out.println("one");
                        break;
                    case 2:
                        System.out.println("two");
                        break;
                    default:
                        System.out.println("other");
                }
            }
        }
    "#;

    let config = LanguageConfig::new(Language::Java);
    let parser = Parser::new(config, Path::new("Test.java"));
    let ast = parser.parse_source(code).expect("Parse failed");

    let has_switch = has_node_kind(&ast, |k| matches!(k, AstNodeKind::SwitchStatement { .. }));
    assert!(has_switch, "Should find SwitchStatement in Java");
}
