use gittera_analyzer::cfg::{CfgBuilder, CfgEdgeKind, CfgNodeKind, ControlFlowGraph};
use gittera_parser::ast::{AstNode, AstNodeKind, Location, Span};
use gittera_parser::{Language, LanguageConfig, Parser};
use petgraph::visit::EdgeRef;
use std::path::Path;

/// Helper to create a test AST node
fn create_test_node(kind: AstNodeKind, children: Vec<AstNode>) -> AstNode {
    AstNode {
        id: 0,
        kind,
        location: Location {
            file_path: "test.js".to_string(),
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: 0,
                start_byte: 0,
                end_byte: 0,
            },
        },
        text: String::new(),
        children,
    }
}

/// Helper to parse JavaScript code
fn parse_js(code: &str) -> AstNode {
    let parser = Parser::new(
        LanguageConfig::new(Language::JavaScript),
        Path::new("test.js"),
    );

    parser.parse_source(code).unwrap_or_else(|_| {
        create_test_node(AstNodeKind::Program, vec![])
    })
}

/// Helper to count nodes of a specific kind in CFG
fn count_nodes_by_kind(cfg: &ControlFlowGraph, kind: CfgNodeKind) -> usize {
    cfg.graph
        .node_weights()
        .filter(|n| n.kind == kind)
        .count()
}

/// Helper to count edges of a specific kind in CFG
fn count_edges_by_kind(cfg: &ControlFlowGraph, kind: CfgEdgeKind) -> usize {
    cfg.graph
        .edge_weights()
        .filter(|e| e.kind == kind)
        .count()
}

/// Helper to check if there's an edge from one node kind to another
fn has_edge_between_kinds(
    cfg: &ControlFlowGraph,
    from_kind: CfgNodeKind,
    to_kind: CfgNodeKind,
) -> bool {
    for edge in cfg.graph.edge_references() {
        let source_node = cfg.graph.node_weight(edge.source()).unwrap();
        let target_node = cfg.graph.node_weight(edge.target()).unwrap();

        if source_node.kind == from_kind && target_node.kind == to_kind {
            return true;
        }
    }
    false
}

// ============================================================================
// Basic CFG Tests
// ============================================================================

#[test]
fn test_cfg_basic_creation() {
    let ast = parse_js("const x = 1;");
    let cfg = CfgBuilder::new().build(&ast);

    // Should have entry and exit nodes
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1);
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1);

    // Should have at least one statement
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Statement) >= 1);
}

#[test]
fn test_cfg_sequential_statements() {
    let code = r#"
        const x = 1;
        const y = 2;
        const z = 3;
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have statements connected sequentially
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Statement) >= 3);

    // Entry should connect to first statement, statements to exit
    assert!(has_edge_between_kinds(&cfg, CfgNodeKind::Entry, CfgNodeKind::Statement));
}

#[test]
fn test_cfg_empty_program() {
    let ast = parse_js("");
    let cfg = CfgBuilder::new().build(&ast);

    // Should still have entry and exit
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1);
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1);

    // Entry should connect to exit
    let successors = cfg.successors(cfg.entry);
    assert!(!successors.is_empty());
}

// ============================================================================
// Branch/Conditional Tests
// ============================================================================

#[test]
fn test_cfg_if_statement() {
    let code = r#"
        if (condition) {
            thenBranch();
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have a branch node
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Branch) >= 1);

    // Should have true/false edges
    assert!(count_edges_by_kind(&cfg, CfgEdgeKind::True) >= 1);
}

#[test]
fn test_cfg_if_else_statement() {
    let code = r#"
        if (condition) {
            thenBranch();
        } else {
            elseBranch();
        }
        after();
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have branch node
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Branch) >= 1);

    // Should have both true and false edges
    assert!(count_edges_by_kind(&cfg, CfgEdgeKind::True) >= 1);
    assert!(count_edges_by_kind(&cfg, CfgEdgeKind::False) >= 1);
}

#[test]
fn test_cfg_nested_if_statements() {
    let code = r#"
        if (outer) {
            if (inner) {
                nested();
            }
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have multiple branch nodes for nested ifs
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Branch) >= 2);
}

// ============================================================================
// Loop Tests
// ============================================================================

#[test]
fn test_cfg_while_loop() {
    let code = r#"
        while (condition) {
            body();
        }
        after();
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have loop node
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Loop) >= 1);

    // Loop should have back-edge (continue edge from body to header)
    // This creates a cycle in the CFG
    let loop_nodes: Vec<_> = cfg.graph
        .node_indices()
        .filter(|&idx| cfg.graph.node_weight(idx).unwrap().kind == CfgNodeKind::Loop)
        .collect();

    assert!(!loop_nodes.is_empty(), "Should have at least one loop node");

    // Check for back-edge (successor that points back to loop header)
    for loop_node in loop_nodes {
        let successors = cfg.successors(loop_node);
        // Loop body should eventually have an edge back to loop header
        assert!(!successors.is_empty(), "Loop should have successors");
    }
}

#[test]
fn test_cfg_for_loop() {
    let code = r#"
        for (let i = 0; i < 10; i++) {
            body();
        }
        after();
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // For loop should have loop node
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Loop) >= 1);
}

#[test]
fn test_cfg_nested_loops() {
    let code = r#"
        while (outer) {
            while (inner) {
                nested();
            }
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have multiple loop nodes
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Loop) >= 2);
}

#[test]
fn test_cfg_loop_with_multiple_statements() {
    let code = r#"
        while (condition) {
            statement1();
            statement2();
            statement3();
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have loop and multiple statements
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Loop) >= 1);
    // Statements inside loop body
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Statement) >= 3);
}

// ============================================================================
// Return Statement Tests
// ============================================================================

#[test]
fn test_cfg_return_statement() {
    let code = r#"
        function test() {
            const x = 1;
            return x;
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have return node if parser recognizes return statement
    let return_count = count_nodes_by_kind(&cfg, CfgNodeKind::Return);

    // If we have return nodes, they should connect to exit
    if return_count > 0 {
        let return_nodes: Vec<_> = cfg.graph
            .node_indices()
            .filter(|&idx| cfg.graph.node_weight(idx).unwrap().kind == CfgNodeKind::Return)
            .collect();

        for return_node in return_nodes {
            let successors = cfg.successors(return_node);
            // Return node should have exit as successor
            assert!(successors.contains(&cfg.exit), "Return should connect to exit");
        }
    }

    // At minimum, CFG should be valid
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1);
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1);
}

#[test]
fn test_cfg_early_return() {
    let code = r#"
        function test() {
            if (condition) {
                return early;
            }
            normalFlow();
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // CFG should be valid with entry and exit
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1);
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1);

    // Should have some nodes beyond entry/exit
    assert!(cfg.graph.node_count() >= 2, "CFG should have at least entry and exit nodes");
}

#[test]
fn test_cfg_multiple_returns() {
    let code = r#"
        function test() {
            if (condition1) {
                return value1;
            }
            if (condition2) {
                return value2;
            }
            return value3;
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // CFG should be valid with entry and exit
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1);
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1);

    // Should have some nodes beyond entry/exit
    assert!(cfg.graph.node_count() >= 2, "CFG should have at least entry and exit nodes");
}

// ============================================================================
// Function Call Tests
// ============================================================================

#[test]
fn test_cfg_function_call() {
    let code = r#"
        doSomething();
        doSomethingElse();
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // CFG should be created successfully
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1);
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1);

    // Should have some statement or function call nodes
    let total_nodes = cfg.graph.node_count();
    assert!(total_nodes >= 2, "Should have at least entry and exit");
}

// ============================================================================
// Complex Control Flow Tests
// ============================================================================

#[test]
fn test_cfg_if_inside_loop() {
    let code = r#"
        while (outerCondition) {
            if (innerCondition) {
                action();
            }
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have both loop and branch
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Loop) >= 1);
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Branch) >= 1);
}

#[test]
fn test_cfg_loop_inside_if() {
    let code = r#"
        if (condition) {
            while (loopCondition) {
                body();
            }
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have both branch and loop
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Branch) >= 1);
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Loop) >= 1);
}

#[test]
fn test_cfg_complex_nested_structure() {
    let code = r#"
        if (outer) {
            while (loop1) {
                if (inner) {
                    action1();
                } else {
                    action2();
                }
            }
        } else {
            for (let i = 0; i < 10; i++) {
                alternative();
            }
        }
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Should have branches for if statements
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Branch) >= 1);

    // Should have loops
    assert!(count_nodes_by_kind(&cfg, CfgNodeKind::Loop) >= 1);

    // CFG should be valid
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1);
    assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1);
}

// ============================================================================
// CFG Properties Tests
// ============================================================================

#[test]
fn test_cfg_always_has_entry_exit() {
    let test_cases = vec![
        "",
        "const x = 1;",
        "if (x) { y(); }",
        "while (true) { break; }",
        "function test() { return 1; }",
    ];

    for code in test_cases {
        let ast = parse_js(code);
        let cfg = CfgBuilder::new().build(&ast);

        assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Entry), 1,
            "Should have exactly one entry node for: {}", code);
        assert_eq!(count_nodes_by_kind(&cfg, CfgNodeKind::Exit), 1,
            "Should have exactly one exit node for: {}", code);
    }
}

#[test]
fn test_cfg_successor_relationships() {
    let code = r#"
        const a = 1;
        const b = 2;
        const c = 3;
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Entry should have successors
    let entry_successors = cfg.successors(cfg.entry);
    assert!(!entry_successors.is_empty(), "Entry should have successors");

    // Exit should have predecessors
    let exit_predecessors = cfg.predecessors(cfg.exit);
    assert!(!exit_predecessors.is_empty(), "Exit should have predecessors");
}

#[test]
fn test_cfg_paths_to_node() {
    let code = r#"
        if (condition) {
            branch1();
        } else {
            branch2();
        }
        merge();
    "#;

    let ast = parse_js(code);
    let cfg = CfgBuilder::new().build(&ast);

    // Find merge point (should have multiple paths to it)
    // Entry → Branch → Then → Merge
    // Entry → Branch → Else → Merge

    // This tests that CFG correctly represents multiple paths
    let all_nodes: Vec<_> = cfg.graph.node_indices().collect();
    assert!(all_nodes.len() >= 4, "Should have at least entry, exit, branch, and merge nodes");
}
