//! Integration tests for KQL parser and executor

use gittera_analyzer::cfg::CfgBuilder;
use gittera_parser::ast::{AstNode, AstNodeKind, Location, Parameter, Span};
use gittera_parser::{Language, LanguageConfig, Parser};
use gittera_query::{QueryExecutor, QueryParser};
use std::path::Path;

/// Helper to create a test AST node
fn create_test_node(kind: AstNodeKind, text: &str, children: Vec<AstNode>) -> AstNode {
    AstNode {
        id: 1,
        kind,
        location: Location {
            file_path: "test.js".to_string(),
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: text.len(),
                start_byte: 0,
                end_byte: text.len(),
            },
        },
        children,
        text: text.to_string(),
    }
}

#[test]
fn test_query_finds_eval_calls() {
    // Create test AST with eval() call
    let eval_call = create_test_node(
        AstNodeKind::CallExpression {
            callee: "eval".to_string(),
            arguments_count: 1,
            is_optional_chain: false,
        },
        "eval(userInput)",
        vec![],
    );

    let root = create_test_node(AstNodeKind::Program, "eval(userInput)", vec![eval_call]);

    // Parse query
    let query_str = r#"
        FROM CallExpression AS call
        WHERE call.callee == "eval"
        SELECT call, "Dangerous eval() detected"
    "#;

    let query = QueryParser::parse(query_str).expect("Failed to parse query");

    // Build CFG
    let cfg = CfgBuilder::new().build(&root);

    // Execute query
    let result = QueryExecutor::execute(&query, &root, &cfg, None);

    // Verify findings
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0].message.contains("eval"));
}

#[test]
fn test_query_with_regex_pattern() {
    // Create test AST with innerHTML assignment
    let member_expr = create_test_node(
        AstNodeKind::MemberExpression {
            object: "element".to_string(),
            property: "innerHTML".to_string(),
            is_computed: false,
            is_optional: false,
        },
        "element.innerHTML",
        vec![],
    );

    let root = create_test_node(
        AstNodeKind::Program,
        "element.innerHTML = data",
        vec![member_expr],
    );

    // Parse query with regex
    let query_str = r#"
        FROM MemberExpression AS member
        WHERE member.property MATCHES "(?i)(innerHTML|outerHTML)"
        SELECT member, "Potential XSS vulnerability"
    "#;

    let query = QueryParser::parse(query_str).expect("Failed to parse query");

    // Build CFG
    let cfg = CfgBuilder::new().build(&root);

    // Execute query
    let result = QueryExecutor::execute(&query, &root, &cfg, None);

    // Verify findings
    assert_eq!(result.findings.len(), 1);
    assert!(result.findings[0].message.contains("XSS"));
}

#[test]
fn test_query_with_contains_operator() {
    // Create test AST with variable declaration
    let var_decl = create_test_node(
        AstNodeKind::VariableDeclaration {
            name: "apiKey".to_string(),
            var_type: None,
            is_const: true,
            initializer: None,
        },
        "const apiKey = 'secret'",
        vec![],
    );

    let root = create_test_node(
        AstNodeKind::Program,
        "const apiKey = 'secret'",
        vec![var_decl],
    );

    // Parse query with CONTAINS
    let query_str = r#"
        FROM VariableDeclaration AS vd
        WHERE vd.name CONTAINS "Key"
        SELECT vd, "Potential secret variable"
    "#;

    let query = QueryParser::parse(query_str).expect("Failed to parse query");

    // Build CFG
    let cfg = CfgBuilder::new().build(&root);

    // Execute query
    let result = QueryExecutor::execute(&query, &root, &cfg, None);

    // Verify findings
    assert_eq!(result.findings.len(), 1);
}

#[test]
fn test_query_with_and_or_logic() {
    // Create test AST with function
    let func = create_test_node(
        AstNodeKind::FunctionDeclaration {
            name: "executeQuery".to_string(),
            parameters: vec![Parameter {
                name: "sql".to_string(),
                param_type: None,
                default_value: None,
                is_optional: false,
                is_rest: false,
            }],
            return_type: None,
            is_async: false,
            is_generator: false,
        },
        "function executeQuery(sql) {}",
        vec![],
    );

    let root = create_test_node(
        AstNodeKind::Program,
        "function executeQuery(sql) {}",
        vec![func],
    );

    // Parse query with complex logic
    let query_str = r#"
        FROM FunctionDeclaration AS fn
        WHERE (fn.name CONTAINS "execute" OR fn.name CONTAINS "query")
              AND fn.parameterCount == 1
        SELECT fn, "Potential SQL injection sink"
    "#;

    let query = QueryParser::parse(query_str).expect("Failed to parse query");

    // Build CFG
    let cfg = CfgBuilder::new().build(&root);

    // Execute query
    let result = QueryExecutor::execute(&query, &root, &cfg, None);

    // Verify findings
    assert_eq!(result.findings.len(), 1);
}

#[test]
fn test_query_with_not_operator() {
    // Create test AST with safe function
    let func = create_test_node(
        AstNodeKind::FunctionDeclaration {
            name: "safeFunction".to_string(),
            parameters: vec![],
            return_type: None,
            is_async: false,
            is_generator: false,
        },
        "function safeFunction() {}",
        vec![],
    );

    let root = create_test_node(
        AstNodeKind::Program,
        "function safeFunction() {}",
        vec![func],
    );

    // Parse query with NOT
    let query_str = r#"
        FROM FunctionDeclaration AS fn
        WHERE NOT fn.name STARTS_WITH "safe"
        SELECT fn, "Non-safe function"
    "#;

    let query = QueryParser::parse(query_str).expect("Failed to parse query");

    // Build CFG
    let cfg = CfgBuilder::new().build(&root);

    // Execute query
    let result = QueryExecutor::execute(&query, &root, &cfg, None);

    // Should not find anything because function name starts with "safe"
    assert_eq!(result.findings.len(), 0);
}

#[test]
fn test_multiple_queries_on_same_ast() {
    // Create test AST with multiple nodes
    let eval_call = create_test_node(
        AstNodeKind::CallExpression {
            callee: "eval".to_string(),
            arguments_count: 1,
            is_optional_chain: false,
        },
        "eval(x)",
        vec![],
    );

    let exec_call = create_test_node(
        AstNodeKind::CallExpression {
            callee: "exec".to_string(),
            arguments_count: 1,
            is_optional_chain: false,
        },
        "exec(cmd)",
        vec![],
    );

    let root = create_test_node(
        AstNodeKind::Program,
        "eval(x); exec(cmd)",
        vec![eval_call, exec_call],
    );

    let cfg = CfgBuilder::new().build(&root);

    // Query 1: Find eval
    let query1 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee == "eval" SELECT c"#,
    )
    .unwrap();
    let result1 = QueryExecutor::execute(&query1, &root, &cfg, None);
    assert_eq!(result1.findings.len(), 1);

    // Query 2: Find exec
    let query2 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee == "exec" SELECT c"#,
    )
    .unwrap();
    let result2 = QueryExecutor::execute(&query2, &root, &cfg, None);
    assert_eq!(result2.findings.len(), 1);

    // Query 3: Find both
    let query3 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee MATCHES "(eval|exec)" SELECT c"#,
    )
    .unwrap();
    let result3 = QueryExecutor::execute(&query3, &root, &cfg, None);
    assert_eq!(result3.findings.len(), 2);
}

#[test]
fn test_real_file_parsing_and_querying() {
    // Test with actual test_vulnerabilities.ts file if it exists
    let test_file = "../../../test_vulnerabilities.ts";

    if !Path::new(test_file).exists() {
        println!("Skipping real file test - test_vulnerabilities.ts not found");
        return;
    }

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new(test_file));
    let ast = parser.parse_file().expect("Failed to parse test file");

    let cfg = CfgBuilder::new().build(&ast);

    // Run a simple query
    let query_str = r#"
        FROM CallExpression AS call
        WHERE call.callee MATCHES "eval"
        SELECT call, "Found eval call"
    "#;

    let query = QueryParser::parse(query_str).expect("Failed to parse query");
    let result = QueryExecutor::execute(&query, &ast, &cfg, None);

    // Just verify it doesn't crash - findings depend on file content
    println!("Found {} eval calls in test file", result.findings.len());
}

#[test]
fn test_all_comparison_operators() {
    let node = create_test_node(
        AstNodeKind::CallExpression {
            callee: "getUserInput".to_string(),
            arguments_count: 0,
            is_optional_chain: false,
        },
        "getUserInput()",
        vec![],
    );

    let root = create_test_node(AstNodeKind::Program, "getUserInput()", vec![node]);
    let cfg = CfgBuilder::new().build(&root);

    // Test ==
    let q1 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee == "getUserInput" SELECT c"#,
    )
    .unwrap();
    assert_eq!(QueryExecutor::execute(&q1, &root, &cfg, None).findings.len(), 1);

    // Test !=
    let q2 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee != "safe" SELECT c"#,
    )
    .unwrap();
    assert_eq!(QueryExecutor::execute(&q2, &root, &cfg, None).findings.len(), 1);

    // Test CONTAINS
    let q3 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee CONTAINS "Input" SELECT c"#,
    )
    .unwrap();
    assert_eq!(QueryExecutor::execute(&q3, &root, &cfg, None).findings.len(), 1);

    // Test STARTS_WITH
    let q4 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee STARTS_WITH "get" SELECT c"#,
    )
    .unwrap();
    assert_eq!(QueryExecutor::execute(&q4, &root, &cfg, None).findings.len(), 1);

    // Test ENDS_WITH
    let q5 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee ENDS_WITH "Input" SELECT c"#,
    )
    .unwrap();
    assert_eq!(QueryExecutor::execute(&q5, &root, &cfg, None).findings.len(), 1);

    // Test MATCHES (regex)
    let q6 = QueryParser::parse(
        r#"FROM CallExpression AS c WHERE c.callee MATCHES "get.*Input" SELECT c"#,
    )
    .unwrap();
    assert_eq!(QueryExecutor::execute(&q6, &root, &cfg, None).findings.len(), 1);
}
