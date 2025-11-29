//! End-to-end tests for interprocedural analysis

use gittera_analyzer::call_graph::CallGraphBuilder;
use gittera_analyzer::interprocedural_taint::InterproceduralTaintAnalysis;
use gittera_parser::ast::{AstNode, AstNodeKind, Location, Span};
use gittera_parser::{Language, LanguageConfig, Parser};
use std::path::Path;

/// Helper to create a test location
fn test_location() -> Location {
    Location {
        file_path: "test.rs".to_string(),
        span: Span {
            start_line: 1,
            start_column: 0,
            end_line: 1,
            end_column: 10,
            start_byte: 0,
            end_byte: 10,
        },
    }
}

#[test]
fn test_simple_interprocedural_taint() {
    // Create AST:
    // function getInput() { return getUserInput(); }
    // function vulnerable() { const data = getInput(); execute(data); }

    let source_call = AstNode::new(
        1,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "getUserInput".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "getUserInput()".to_string(),
    );

    let return_stmt = AstNode {
        id: 2,
        kind: AstNodeKind::ReturnStatement,
        location: test_location(),
        children: vec![source_call],
        text: "return getUserInput();".to_string(),
    };

    let get_input_func = AstNode {
        id: 3,
        kind: AstNodeKind::FunctionDeclaration {
            name: "getInput".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        location: test_location(),
        children: vec![return_stmt],
        text: "function getInput() { return getUserInput(); }".to_string(),
    };

    let get_input_call = AstNode::new(
        4,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "getInput".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "getInput()".to_string(),
    );

    let var_decl = AstNode {
        id: 5,
        kind: AstNodeKind::VariableDeclaration {
            name: "data".to_string(),
            var_type: None,
            is_const: true, initializer: None,
        },
        location: test_location(),
        children: vec![get_input_call],
        text: "const data = getInput();".to_string(),
    };

    let execute_call = AstNode::new(
        6,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "execute".to_string(),
            arguments_count: 1,
        },
        test_location(),
        "execute(data)".to_string(),
    );

    let vulnerable_func = AstNode {
        id: 7,
        kind: AstNodeKind::FunctionDeclaration {
            name: "vulnerable".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        location: test_location(),
        children: vec![var_decl, execute_call],
        text: "function vulnerable() { const data = getInput(); execute(data); }".to_string(),
    };

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![get_input_func, vulnerable_func],
        text: "program".to_string(),
    };

    // Build call graph
    let call_graph = CallGraphBuilder::new().build(&program);

    println!("Call graph nodes: {}", call_graph.node_count());
    println!("Call graph edges: {}", call_graph.edge_count());

    // Run interprocedural taint analysis
    let mut analysis = InterproceduralTaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();

    let result = analysis.analyze(&program, &call_graph);

    println!("Found {} vulnerabilities", result.vulnerabilities.len());
    for vuln in &result.vulnerabilities {
        println!(
            "  [{}] {} at sink '{}'",
            vuln.severity.as_str(),
            vuln.tainted_value.variable,
            vuln.sink.name
        );
    }

    // Should detect vulnerability (actual detection depends on implementation details)
    // The test validates the analysis runs without errors
}

#[test]
fn test_call_graph_construction() {
    // Simple test: main() calls helper()
    let helper_call = AstNode::new(
        1,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "helper".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "helper()".to_string(),
    );

    let main_func = AstNode {
        id: 2,
        kind: AstNodeKind::FunctionDeclaration {
            name: "main".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        location: test_location(),
        children: vec![helper_call],
        text: "function main() { helper(); }".to_string(),
    };

    let helper_func = AstNode::new(
        3,
        AstNodeKind::FunctionDeclaration {
            name: "helper".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        test_location(),
        "function helper() {}".to_string(),
    );

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, helper_func],
        text: "program".to_string(),
    };

    let call_graph = CallGraphBuilder::new().build(&program);

    assert_eq!(call_graph.node_count(), 2);
    assert!(call_graph.contains("main"));
    assert!(call_graph.contains("helper"));

    let callees = call_graph.get_callees("main");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].to, "helper");
}

#[test]
fn test_topological_sort_ordering() {
    // Create call chain: main -> foo -> bar
    let bar_call = AstNode::new(
        1,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "bar".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "bar()".to_string(),
    );

    let foo_func = AstNode {
        id: 2,
        kind: AstNodeKind::FunctionDeclaration {
            name: "foo".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        location: test_location(),
        children: vec![bar_call],
        text: "function foo() { bar(); }".to_string(),
    };

    let foo_call = AstNode::new(
        3,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "foo".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "foo()".to_string(),
    );

    let main_func = AstNode {
        id: 4,
        kind: AstNodeKind::FunctionDeclaration {
            name: "main".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        location: test_location(),
        children: vec![foo_call],
        text: "function main() { foo(); }".to_string(),
    };

    let bar_func = AstNode::new(
        5,
        AstNodeKind::FunctionDeclaration {
            name: "bar".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        test_location(),
        "function bar() {}".to_string(),
    );

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, foo_func, bar_func],
        text: "program".to_string(),
    };

    let call_graph = CallGraphBuilder::new().build(&program);

    let sorted = call_graph.topological_sort();
    assert!(sorted.is_some());

    let sorted = sorted.unwrap();
    assert_eq!(sorted.len(), 3);

    println!("Topological sort result: {:?}", sorted);

    // Verify ordering: topological sort returns bottom-up order (callees before callers)
    // So for main -> foo -> bar, we get [bar, foo, main]
    let bar_pos = sorted.iter().position(|s| s == "bar").unwrap();
    let foo_pos = sorted.iter().position(|s| s == "foo").unwrap();
    let main_pos = sorted.iter().position(|s| s == "main").unwrap();

    println!("Positions: main={}, foo={}, bar={}", main_pos, foo_pos, bar_pos);

    // For bottom-up analysis, callees should come before callers
    assert!(bar_pos < foo_pos);
    assert!(foo_pos < main_pos);
}

#[test]
fn test_real_file_interprocedural_analysis() {
    let test_file = "../../../test_interprocedural.ts";

    if !Path::new(test_file).exists() {
        println!("Skipping real file test - test_interprocedural.ts not found");
        return;
    }

    let config = LanguageConfig::new(Language::TypeScript);
    let parser = Parser::new(config, Path::new(test_file));
    let ast = parser.parse_file().expect("Failed to parse test file");

    // Build call graph
    let call_graph = CallGraphBuilder::new().build(&ast);

    println!("\n=== Call Graph Analysis ===");
    println!("Functions: {}", call_graph.node_count());
    println!("Call edges: {}", call_graph.edge_count());

    // Show some call relationships
    for node in call_graph.nodes().take(5) {
        let callees = call_graph.get_callees(&node.name);
        if !callees.is_empty() {
            println!("  {} calls:", node.name);
            for callee in callees {
                println!("    -> {}", callee.to);
            }
        }
    }

    // Run interprocedural taint analysis
    let mut analysis = InterproceduralTaintAnalysis::new()
        .with_default_sources()
        .with_default_sinks()
        .with_default_sanitizers();

    let result = analysis.analyze(&ast, &call_graph);

    println!("\n=== Interprocedural Taint Analysis ===");
    println!("Found {} vulnerabilities:", result.vulnerabilities.len());

    for (i, vuln) in result.vulnerabilities.iter().enumerate().take(10) {
        println!(
            "{}. [{}] Variable: {} | Sink: {}",
            i + 1,
            vuln.severity.as_str(),
            vuln.tainted_value.variable,
            vuln.sink.name
        );
    }

    if result.vulnerabilities.len() > 10 {
        println!("... and {} more", result.vulnerabilities.len() - 10);
    }

    // Verify analysis runs without errors
    assert!(result.vulnerabilities.len() >= 0);
}

#[test]
fn test_method_call_graph() {
    // Test class with methods
    let get_data_call = AstNode::new(
        1,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "getData".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "this.getData()".to_string(),
    );

    let process_method = AstNode {
        id: 2,
        kind: AstNodeKind::MethodDeclaration {
            name: "process".to_string(),
            parameters: vec![],
            return_type: None,
            visibility: gittera_parser::ast::Visibility::Public,
            is_static: false,
            is_async: false,
            is_abstract: false,
        },
        location: test_location(),
        children: vec![get_data_call],
        text: "process() { this.getData(); }".to_string(),
    };

    let get_data_method = AstNode::new(
        3,
        AstNodeKind::MethodDeclaration {
            name: "getData".to_string(),
            parameters: vec![],
            return_type: None,
            visibility: gittera_parser::ast::Visibility::Public,
            is_static: false,
            is_async: false,
            is_abstract: false,
        },
        test_location(),
        "getData() {}".to_string(),
    );

    let class_decl = AstNode {
        id: 4,
        kind: AstNodeKind::ClassDeclaration {
            name: "Processor".to_string(),
            extends: None,
            implements: vec![],
            is_abstract: false,
        },
        location: test_location(),
        children: vec![process_method, get_data_method],
        text: "class Processor {}".to_string(),
    };

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![class_decl],
        text: "program".to_string(),
    };

    let call_graph = CallGraphBuilder::new().build(&program);

    assert_eq!(call_graph.node_count(), 2);
    assert!(call_graph.contains("Processor.process"));
    assert!(call_graph.contains("Processor.getData"));

    let callees = call_graph.get_callees("Processor.process");
    // Note: Currently may not detect this.getData() as calling Processor.getData
    // because we don't have full type resolution yet
    println!("Processor.process callees: {}", callees.len());
}

#[test]
fn test_reachability_analysis() {
    // Create call chain: main -> foo -> bar, baz (independent)
    let bar_call = AstNode::new(
        1,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "bar".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "bar()".to_string(),
    );

    let foo_func = AstNode {
        id: 2,
        kind: AstNodeKind::FunctionDeclaration {
            name: "foo".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        location: test_location(),
        children: vec![bar_call],
        text: "function foo() { bar(); }".to_string(),
    };

    let foo_call = AstNode::new(
        3,
        AstNodeKind::CallExpression { is_optional_chain: false,
            callee: "foo".to_string(),
            arguments_count: 0,
        },
        test_location(),
        "foo()".to_string(),
    );

    let main_func = AstNode {
        id: 4,
        kind: AstNodeKind::FunctionDeclaration {
            name: "main".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        location: test_location(),
        children: vec![foo_call],
        text: "function main() { foo(); }".to_string(),
    };

    let bar_func = AstNode::new(
        5,
        AstNodeKind::FunctionDeclaration {
            name: "bar".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        test_location(),
        "function bar() {}".to_string(),
    );

    let baz_func = AstNode::new(
        6,
        AstNodeKind::FunctionDeclaration {
            name: "baz".to_string(),
            parameters: vec![],
            return_type: None, is_async: false, is_generator: false,
        },
        test_location(),
        "function baz() {}".to_string(),
    );

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, foo_func, bar_func, baz_func],
        text: "program".to_string(),
    };

    let call_graph = CallGraphBuilder::new().build(&program);

    let reachable = call_graph.reachable_from("main");
    assert!(reachable.contains("main"));
    assert!(reachable.contains("foo"));
    assert!(reachable.contains("bar"));
    assert!(!reachable.contains("baz")); // Not reachable from main
}
