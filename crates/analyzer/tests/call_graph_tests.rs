//! Comprehensive Call Graph Tests
//!
//! Tests for call graph construction and querying covering:
//! - Function discovery (various function types)
//! - Call site detection (different call patterns)
//! - Graph construction (nodes, edges, structure)
//! - Interprocedural analysis (call chains, recursion)
//! - Graph queries (callers, callees, reachability)

use gittera_analyzer::call_graph::{CallGraph, CallGraphBuilder, CallGraphNode, CallableKind, CallEdge};
use gittera_parser::ast::{AstNode, AstNodeKind, Location, Span, Visibility};

// Helper to create test location
fn test_location() -> Location {
    Location {
        file_path: "test.js".to_string(),
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

// Helper to create a function declaration AST node
fn create_function(id: usize, name: &str, children: Vec<AstNode>) -> AstNode {
    AstNode {
        id,
        kind: AstNodeKind::FunctionDeclaration {
            name: name.to_string(),
            parameters: vec![],
            return_type: None,
            is_async: false,
            is_generator: false,
        },
        location: test_location(),
        children,
        text: format!("function {}() {{}}", name),
    }
}

// Helper to create a method declaration AST node
fn create_method(id: usize, name: &str, children: Vec<AstNode>) -> AstNode {
    AstNode {
        id,
        kind: AstNodeKind::MethodDeclaration {
            name: name.to_string(),
            parameters: vec![],
            return_type: None,
            visibility: Visibility::Public,
            is_static: false,
            is_async: false,
            is_abstract: false,
        },
        location: test_location(),
        children,
        text: format!("{}() {{}}", name),
    }
}

// Helper to create a class declaration AST node
fn create_class(id: usize, name: &str, children: Vec<AstNode>) -> AstNode {
    AstNode {
        id,
        kind: AstNodeKind::ClassDeclaration {
            name: name.to_string(),
            extends: None,
            implements: vec![],
            is_abstract: false,
        },
        location: test_location(),
        children,
        text: format!("class {} {{}}", name),
    }
}

// Helper to create a function call AST node
fn create_call(id: usize, callee: &str) -> AstNode {
    AstNode::new(
        id,
        AstNodeKind::CallExpression {
            callee: callee.to_string(),
            arguments_count: 0,
            is_optional_chain: false,
        },
        test_location(),
        format!("{}()", callee),
    )
}

// ============================================================================
// SECTION 1: FUNCTION DISCOVERY (5 tests)
// ============================================================================

#[test]
fn test_function_declaration_discovery() {
    // Test discovery of regular function declarations
    let func1 = create_function(1, "foo", vec![]);
    let func2 = create_function(2, "bar", vec![]);
    let func3 = create_function(3, "baz", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![func1, func2, func3],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 3);
    assert!(graph.contains("foo"));
    assert!(graph.contains("bar"));
    assert!(graph.contains("baz"));

    // Check node kinds
    assert_eq!(
        graph.get_node("foo").unwrap().kind,
        CallableKind::Function
    );
}

#[test]
fn test_class_method_discovery() {
    // Test discovery of class methods
    let method1 = create_method(1, "methodA", vec![]);
    let method2 = create_method(2, "methodB", vec![]);

    let class = create_class(3, "MyClass", vec![method1, method2]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![class],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 2);
    assert!(graph.contains("MyClass.methodA"));
    assert!(graph.contains("MyClass.methodB"));

    // Check node kind
    let node = graph.get_node("MyClass.methodA").unwrap();
    match &node.kind {
        CallableKind::Method { class_name } => {
            assert_eq!(class_name, "MyClass");
        }
        _ => panic!("Expected Method kind"),
    }
}

#[test]
fn test_nested_function_discovery() {
    // Test discovery of nested functions
    let inner_func = create_function(1, "inner", vec![]);

    let outer_func = create_function(2, "outer", vec![inner_func]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![outer_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 2);
    assert!(graph.contains("outer"));
    assert!(graph.contains("inner"));
}

#[test]
fn test_multiple_classes() {
    // Test discovery across multiple classes
    let method1 = create_method(1, "foo", vec![]);
    let class1 = create_class(2, "ClassA", vec![method1]);

    let method2 = create_method(3, "bar", vec![]);
    let class2 = create_class(4, "ClassB", vec![method2]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![class1, class2],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 2);
    assert!(graph.contains("ClassA.foo"));
    assert!(graph.contains("ClassB.bar"));
}

#[test]
fn test_mixed_function_types() {
    // Test discovery of mixed function types
    let standalone_func = create_function(1, "standalone", vec![]);

    let method = create_method(2, "method", vec![]);
    let class = create_class(3, "MyClass", vec![method]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![standalone_func, class],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 2);
    assert!(graph.contains("standalone"));
    assert!(graph.contains("MyClass.method"));
}

// ============================================================================
// SECTION 2: CALL SITE DETECTION (5 tests)
// ============================================================================

#[test]
fn test_direct_function_call() {
    // Test detection of direct function calls
    let helper_call = create_call(1, "helper");

    let main_func = create_function(2, "main", vec![helper_call]);
    let helper_func = create_function(3, "helper", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, helper_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    let callees = graph.get_callees("main");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].to, "helper");
    assert_eq!(callees[0].from, "main");

    // Check reverse edges
    let callers = graph.get_callers("helper");
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0], "main");
}

#[test]
fn test_multiple_call_sites() {
    // Test detection of multiple calls from one function
    let foo_call = create_call(1, "foo");
    let bar_call = create_call(2, "bar");
    let baz_call = create_call(3, "baz");

    let main_func = create_function(4, "main", vec![foo_call, bar_call, baz_call]);
    let foo_func = create_function(5, "foo", vec![]);
    let bar_func = create_function(6, "bar", vec![]);
    let baz_func = create_function(7, "baz", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, foo_func, bar_func, baz_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    let callees = graph.get_callees("main");
    assert_eq!(callees.len(), 3);

    let callee_names: Vec<&str> = callees.iter().map(|e| e.to.as_str()).collect();
    assert!(callee_names.contains(&"foo"));
    assert!(callee_names.contains(&"bar"));
    assert!(callee_names.contains(&"baz"));
}

#[test]
fn test_method_call_from_method() {
    // Test method calling another function
    let helper_call = create_call(1, "helper");

    let method = create_method(2, "myMethod", vec![helper_call]);
    let class = create_class(3, "MyClass", vec![method]);

    let helper_func = create_function(4, "helper", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![class, helper_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    let callees = graph.get_callees("MyClass.myMethod");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].to, "helper");
}

#[test]
fn test_nested_function_calls() {
    // Test nested function calling outer scope function
    let outer_call = create_call(1, "outer");
    let inner_func = create_function(2, "inner", vec![outer_call]);

    let outer_func = create_function(3, "outer", vec![inner_func]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![outer_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    // Inner function calls outer function
    let callees = graph.get_callees("inner");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].to, "outer");
}

#[test]
fn test_call_site_tracking() {
    // Test that call sites record correct node IDs
    let call1 = create_call(100, "helper");
    let call2 = create_call(200, "helper");

    let main_func = create_function(2, "main", vec![call1, call2]);
    let helper_func = create_function(3, "helper", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, helper_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    let callees = graph.get_callees("main");
    assert_eq!(callees.len(), 2);

    // Both calls should have different call site IDs
    let call_site_ids: Vec<usize> = callees.iter().map(|e| e.call_site_node_id).collect();
    assert!(call_site_ids.contains(&100));
    assert!(call_site_ids.contains(&200));
}

// ============================================================================
// SECTION 3: GRAPH CONSTRUCTION (4 tests)
// ============================================================================

#[test]
fn test_graph_node_creation() {
    let mut graph = CallGraph::new();

    let node1 = CallGraphNode {
        name: "func1".to_string(),
        kind: CallableKind::Function,
        node_id: 1,
    };

    let node2 = CallGraphNode {
        name: "MyClass.method".to_string(),
        kind: CallableKind::Method {
            class_name: "MyClass".to_string(),
        },
        node_id: 2,
    };

    graph.add_node(node1);
    graph.add_node(node2);

    assert_eq!(graph.node_count(), 2);
    assert!(graph.contains("func1"));
    assert!(graph.contains("MyClass.method"));

    // Verify node retrieval
    let retrieved = graph.get_node("func1").unwrap();
    assert_eq!(retrieved.name, "func1");
    assert_eq!(retrieved.node_id, 1);
}

#[test]
fn test_graph_edge_creation() {
    let mut graph = CallGraph::new();

    // Add nodes
    graph.add_node(CallGraphNode {
        name: "caller".to_string(),
        kind: CallableKind::Function,
        node_id: 1,
    });

    graph.add_node(CallGraphNode {
        name: "callee".to_string(),
        kind: CallableKind::Function,
        node_id: 2,
    });

    // Add edge
    graph.add_edge(CallEdge {
        from: "caller".to_string(),
        to: "callee".to_string(),
        call_site_node_id: 10,
    });

    assert_eq!(graph.edge_count(), 1);

    // Verify forward edge
    let callees = graph.get_callees("caller");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].to, "callee");

    // Verify reverse edge
    let callers = graph.get_callers("callee");
    assert_eq!(callers.len(), 1);
    assert_eq!(callers[0], "caller");
}

#[test]
fn test_graph_iterator_methods() {
    let mut graph = CallGraph::new();

    // Add nodes
    graph.add_node(CallGraphNode {
        name: "a".to_string(),
        kind: CallableKind::Function,
        node_id: 1,
    });
    graph.add_node(CallGraphNode {
        name: "b".to_string(),
        kind: CallableKind::Function,
        node_id: 2,
    });
    graph.add_node(CallGraphNode {
        name: "c".to_string(),
        kind: CallableKind::Function,
        node_id: 3,
    });

    // Add edges
    graph.add_edge(CallEdge {
        from: "a".to_string(),
        to: "b".to_string(),
        call_site_node_id: 10,
    });
    graph.add_edge(CallEdge {
        from: "a".to_string(),
        to: "c".to_string(),
        call_site_node_id: 11,
    });

    // Test nodes iterator
    let node_names: Vec<String> = graph.nodes().map(|n| n.name.clone()).collect();
    assert_eq!(node_names.len(), 3);
    assert!(node_names.contains(&"a".to_string()));
    assert!(node_names.contains(&"b".to_string()));
    assert!(node_names.contains(&"c".to_string()));

    // Test edges iterator
    let edges: Vec<&CallEdge> = graph.edges().collect();
    assert_eq!(edges.len(), 2);
}

#[test]
fn test_recursive_call_detection() {
    // Test self-recursive function
    let recursive_call = create_call(1, "factorial");

    let factorial_func = create_function(2, "factorial", vec![recursive_call]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![factorial_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 1);
    assert!(graph.contains("factorial"));

    // Should have self-edge
    let callees = graph.get_callees("factorial");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].to, "factorial");
    assert_eq!(callees[0].from, "factorial");
}

// ============================================================================
// SECTION 4: INTERPROCEDURAL ANALYSIS (3 tests)
// ============================================================================

#[test]
fn test_call_chain_analysis() {
    // Test: main -> foo -> bar -> baz
    let baz_call = create_call(1, "baz");
    let bar_func = create_function(2, "bar", vec![baz_call]);

    let bar_call = create_call(3, "bar");
    let foo_func = create_function(4, "foo", vec![bar_call]);

    let foo_call = create_call(5, "foo");
    let main_func = create_function(6, "main", vec![foo_call]);

    let baz_func = create_function(7, "baz", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, foo_func, bar_func, baz_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 4);

    // Verify call chain
    let main_callees = graph.get_callees("main");
    assert_eq!(main_callees.len(), 1);
    assert_eq!(main_callees[0].to, "foo");

    let foo_callees = graph.get_callees("foo");
    assert_eq!(foo_callees.len(), 1);
    assert_eq!(foo_callees[0].to, "bar");

    let bar_callees = graph.get_callees("bar");
    assert_eq!(bar_callees.len(), 1);
    assert_eq!(bar_callees[0].to, "baz");

    // Check reachability
    let reachable = graph.reachable_from("main");
    assert_eq!(reachable.len(), 4);
    assert!(reachable.contains("main"));
    assert!(reachable.contains("foo"));
    assert!(reachable.contains("bar"));
    assert!(reachable.contains("baz"));
}

#[test]
fn test_mutual_recursion() {
    // Test: ping -> pong -> ping (mutual recursion)
    let pong_call = create_call(1, "pong");
    let ping_func = create_function(2, "ping", vec![pong_call]);

    let ping_call = create_call(3, "ping");
    let pong_func = create_function(4, "pong", vec![ping_call]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![ping_func, pong_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 2);

    // Verify mutual calls
    let ping_callees = graph.get_callees("ping");
    assert_eq!(ping_callees.len(), 1);
    assert_eq!(ping_callees[0].to, "pong");

    let pong_callees = graph.get_callees("pong");
    assert_eq!(pong_callees.len(), 1);
    assert_eq!(pong_callees[0].to, "ping");

    // Topological sort should fail (cycle detected)
    let sorted = graph.topological_sort();
    assert!(sorted.is_none(), "Should detect cycle in mutual recursion");
}

#[test]
fn test_cross_class_calls() {
    // Test: ClassA.methodA calls ClassB.methodB
    let method_b_call = create_call(1, "ClassB.methodB");
    let method_a = create_method(2, "methodA", vec![method_b_call]);
    let class_a = create_class(3, "ClassA", vec![method_a]);

    let method_b = create_method(4, "methodB", vec![]);
    let class_b = create_class(5, "ClassB", vec![method_b]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![class_a, class_b],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    assert_eq!(graph.node_count(), 2);

    let callees = graph.get_callees("ClassA.methodA");
    assert_eq!(callees.len(), 1);
    assert_eq!(callees[0].to, "ClassB.methodB");
}

// ============================================================================
// SECTION 5: GRAPH QUERIES (3 tests)
// ============================================================================

#[test]
fn test_find_callers_query() {
    // Build graph: a -> b, c -> b, d -> b
    let b_call_from_a = create_call(1, "b");
    let a_func = create_function(2, "a", vec![b_call_from_a]);

    let b_call_from_c = create_call(3, "b");
    let c_func = create_function(4, "c", vec![b_call_from_c]);

    let b_call_from_d = create_call(5, "b");
    let d_func = create_function(6, "d", vec![b_call_from_d]);

    let b_func = create_function(7, "b", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![a_func, c_func, d_func, b_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    // Find all callers of b
    let callers = graph.get_callers("b");
    assert_eq!(callers.len(), 3);
    assert!(callers.contains(&"a"));
    assert!(callers.contains(&"c"));
    assert!(callers.contains(&"d"));
}

#[test]
fn test_find_callees_query() {
    // Build graph: main -> foo, main -> bar, main -> baz
    let foo_call = create_call(1, "foo");
    let bar_call = create_call(2, "bar");
    let baz_call = create_call(3, "baz");

    let main_func = create_function(4, "main", vec![foo_call, bar_call, baz_call]);
    let foo_func = create_function(5, "foo", vec![]);
    let bar_func = create_function(6, "bar", vec![]);
    let baz_func = create_function(7, "baz", vec![]);

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, foo_func, bar_func, baz_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    // Find all callees of main
    let callees = graph.get_callees("main");
    assert_eq!(callees.len(), 3);

    let callee_names: Vec<&str> = callees.iter().map(|e| e.to.as_str()).collect();
    assert!(callee_names.contains(&"foo"));
    assert!(callee_names.contains(&"bar"));
    assert!(callee_names.contains(&"baz"));
}

#[test]
fn test_reachability_query() {
    // Build graph: main -> a -> b -> c, main -> d
    let b_call = create_call(1, "b");
    let a_func = create_function(2, "a", vec![b_call]);

    let c_call = create_call(3, "c");
    let b_func = create_function(4, "b", vec![c_call]);

    let c_func = create_function(5, "c", vec![]);

    let a_call = create_call(6, "a");
    let d_call = create_call(7, "d");
    let main_func = create_function(8, "main", vec![a_call, d_call]);

    let d_func = create_function(9, "d", vec![]);

    let e_func = create_function(10, "e", vec![]); // Unreachable from main

    let program = AstNode {
        id: 0,
        kind: AstNodeKind::Program,
        location: test_location(),
        children: vec![main_func, a_func, b_func, c_func, d_func, e_func],
        text: "program".to_string(),
    };

    let builder = CallGraphBuilder::new();
    let graph = builder.build(&program);

    // Find all functions reachable from main
    let reachable = graph.reachable_from("main");
    assert_eq!(reachable.len(), 5); // main, a, b, c, d

    assert!(reachable.contains("main"));
    assert!(reachable.contains("a"));
    assert!(reachable.contains("b"));
    assert!(reachable.contains("c"));
    assert!(reachable.contains("d"));
    assert!(!reachable.contains("e")); // e is not reachable
}
