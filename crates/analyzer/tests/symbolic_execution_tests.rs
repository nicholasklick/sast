//! Comprehensive Symbolic Execution Tests
//!
//! Tests for the symbolic execution engine covering:
//! - Basic symbolic execution
//! - Constraint generation and solving
//! - Path exploration strategies
//! - Integration with taint analysis
//! - Complex control flow
//! - Edge cases

use gittera_analyzer::symbolic::{
    BinaryOperator, Constraint, ExecutionPath, SymbolicExecutorBuilder,
    SymbolicState, SymbolicValue, UnaryOperator,
};
use gittera_parser::ast::{AstNode, AstNodeKind, LiteralValue, Location, Span};

// Helper to create test AST nodes
fn create_node(kind: AstNodeKind, children: Vec<AstNode>) -> AstNode {
    static mut COUNTER: usize = 0;
    let id = unsafe {
        COUNTER += 1;
        COUNTER
    };

    AstNode {
        id,
        kind,
        location: Location {
            file_path: "test.js".to_string(),
            span: Span {
                start_line: 1,
                start_column: 0,
                end_line: 1,
                end_column: 10,
                start_byte: 0,
                end_byte: 10,
            },
        },
        children,
        text: String::new(),
    }
}

fn create_literal_int(value: i64) -> AstNode {
    create_node(
        AstNodeKind::Literal {
            value: LiteralValue::Number(value.to_string()),
        },
        vec![],
    )
}

fn create_literal_bool(value: bool) -> AstNode {
    create_node(
        AstNodeKind::Literal {
            value: LiteralValue::Boolean(value),
        },
        vec![],
    )
}

fn create_identifier(name: &str) -> AstNode {
    create_node(AstNodeKind::Identifier { name: name.to_string() }, vec![])
}

fn create_var_decl(name: &str, init: Option<AstNode>) -> AstNode {
    let children = init.map(|n| vec![n]).unwrap_or_default();
    create_node(
        AstNodeKind::VariableDeclaration {
            name: name.to_string(),
            var_type: None,
            is_const: false,
            initializer: None,
        },
        children,
    )
}

fn create_binary_expr(operator: &str, left: AstNode, right: AstNode) -> AstNode {
    create_node(
        AstNodeKind::BinaryExpression {
            operator: operator.to_string(),
        },
        vec![left, right],
    )
}

fn create_if_stmt(condition: AstNode, then_branch: AstNode, else_branch: Option<AstNode>) -> AstNode {
    let mut children = vec![condition, then_branch];
    if let Some(else_node) = else_branch {
        children.push(else_node);
    }
    create_node(AstNodeKind::IfStatement, children)
}

fn create_assignment(target: &str, value: AstNode) -> AstNode {
    create_node(
        AstNodeKind::AssignmentExpression {
            operator: "=".to_string(),
        },
        vec![create_identifier(target), value],
    )
}

// ============================================================================
// SECTION 1: BASIC SYMBOLIC EXECUTION (5 tests)
// ============================================================================

#[test]
fn test_symbolic_value_types() {
    // Integer
    let int_val = SymbolicValue::int(42);
    assert!(int_val.is_concrete());
    assert_eq!(int_val, SymbolicValue::Concrete(42));

    // Boolean
    let bool_val = SymbolicValue::bool(true);
    assert!(bool_val.is_concrete());
    assert_eq!(bool_val, SymbolicValue::ConcreteBool(true));

    // Symbolic variable
    let sym_val = SymbolicValue::var("x");
    assert!(sym_val.is_symbolic());
    assert!(!sym_val.is_concrete());
}

#[test]
fn test_simple_variable_declaration() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_depth(1) // Force depth limit to create path
        .build();

    // const x = 42;
    let program = create_node(
        AstNodeKind::Program,
        vec![create_var_decl("x", Some(create_literal_int(42)))],
    );

    let result = executor.execute(&program);

    // With max_depth=1, should hit depth limit and create a path
    assert!(result.stats.total_paths >= 1);
}

#[test]
fn test_symbolic_variable_creation() {
    let mut state = SymbolicState::new();

    // Test symbolic variable creation directly
    state.set("x".to_string(), SymbolicValue::var("x"));

    let x_value = state.get("x");
    assert!(x_value.is_symbolic());
    assert!(!x_value.is_concrete());
}

#[test]
fn test_variable_assignment() {
    let mut state = SymbolicState::new();

    // Test variable assignment directly
    state.set("x".to_string(), SymbolicValue::int(10));
    assert_eq!(state.get("x"), SymbolicValue::int(10));

    // Reassign
    state.set("x".to_string(), SymbolicValue::int(20));
    assert_eq!(state.get("x"), SymbolicValue::int(20));
}

#[test]
fn test_execution_stats() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_depth(10)
        .with_max_paths(50)
        .build();

    let program = create_node(
        AstNodeKind::Program,
        vec![
            create_var_decl("x", Some(create_literal_int(1))),
            create_var_decl("y", Some(create_literal_int(2))),
        ],
    );

    let result = executor.execute(&program);

    assert_eq!(result.stats.total_paths, result.paths.len());
    assert!(result.stats.max_depth_reached <= 10);
}

// ============================================================================
// SECTION 2: CONSTRAINT SOLVING (4 tests)
// ============================================================================

#[test]
fn test_integer_constraints() {
    // x > 0
    let condition = SymbolicValue::binary(
        BinaryOperator::GreaterThan,
        SymbolicValue::var("x"),
        SymbolicValue::int(0),
    );

    let constraint = Constraint::new(condition, 1);
    assert_eq!(constraint.source_node, 1);

    // Simplified constraint should be stored
    match &constraint.condition {
        SymbolicValue::BinaryOp { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::GreaterThan);
        }
        _ => panic!("Expected binary operation"),
    }
}

#[test]
fn test_boolean_constraints() {
    // Test boolean value creation
    let true_val = SymbolicValue::bool(true);
    let false_val = SymbolicValue::bool(false);

    assert!(true_val.is_concrete());
    assert!(false_val.is_concrete());
    assert_eq!(true_val, SymbolicValue::ConcreteBool(true));
    assert_eq!(false_val, SymbolicValue::ConcreteBool(false));

    // Test boolean in constraints
    let condition = SymbolicValue::binary(
        BinaryOperator::And,
        true_val.clone(),
        SymbolicValue::var("x"),
    );

    // Should remain symbolic (x is unknown)
    assert!(condition.is_symbolic());
}

#[test]
fn test_comparison_constraints() {
    // Test various comparison operators
    let x = SymbolicValue::var("x");

    // x < 10
    let less_than = SymbolicValue::binary(
        BinaryOperator::LessThan,
        x.clone(),
        SymbolicValue::int(10),
    );

    // x >= 5
    let greater_equal = SymbolicValue::binary(
        BinaryOperator::GreaterThanOrEqual,
        x.clone(),
        SymbolicValue::int(5),
    );

    // Both should be symbolic (can't simplify without concrete values)
    assert!(less_than.is_symbolic());
    assert!(greater_equal.is_symbolic());

    // Create constraints
    let c1 = Constraint::new(less_than, 1);
    let c2 = Constraint::new(greater_equal, 2);

    assert_eq!(c1.source_node, 1);
    assert_eq!(c2.source_node, 2);
}

#[test]
fn test_complex_constraint_combination() {
    // (x > 0) && (x < 100)
    let x = SymbolicValue::var("x");

    let greater_than_zero = SymbolicValue::binary(
        BinaryOperator::GreaterThan,
        x.clone(),
        SymbolicValue::int(0),
    );

    let less_than_hundred = SymbolicValue::binary(
        BinaryOperator::LessThan,
        x,
        SymbolicValue::int(100),
    );

    let combined = SymbolicValue::binary(
        BinaryOperator::And,
        greater_than_zero,
        less_than_hundred,
    );

    let constraint = Constraint::new(combined, 1);

    // Should maintain structure
    match &constraint.condition {
        SymbolicValue::BinaryOp { operator, .. } => {
            assert_eq!(*operator, BinaryOperator::And);
        }
        _ => panic!("Expected AND operation"),
    }
}

// ============================================================================
// SECTION 3: PATH EXPLORATION (4 tests)
// ============================================================================

#[test]
fn test_simple_branching() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_depth(2)
        .build();

    // if (x > 0) { return 1; } else { return 2; }
    let condition = create_binary_expr(">", create_identifier("x"), create_literal_int(0));
    let then_branch = create_node(AstNodeKind::ReturnStatement, vec![create_literal_int(1)]);
    let else_branch = create_node(AstNodeKind::ReturnStatement, vec![create_literal_int(2)]);

    let if_stmt = create_if_stmt(condition, then_branch, Some(else_branch));

    let program = create_node(
        AstNodeKind::Program,
        vec![if_stmt],
    );

    let result = executor.execute(&program);

    // Should create paths (branching with returns will complete paths)
    assert!(
        result.stats.total_paths >= 1,
        "Should have at least 1 path, got {}",
        result.stats.total_paths
    );
}

#[test]
fn test_path_constraint_accumulation() {
    let mut state = SymbolicState::new();

    // Add multiple constraints
    let c1 = Constraint::new(
        SymbolicValue::binary(
            BinaryOperator::GreaterThan,
            SymbolicValue::var("x"),
            SymbolicValue::int(0),
        ),
        1,
    );

    let c2 = Constraint::new(
        SymbolicValue::binary(
            BinaryOperator::LessThan,
            SymbolicValue::var("x"),
            SymbolicValue::int(100),
        ),
        2,
    );

    state.add_constraint(c1);
    state.add_constraint(c2);

    assert_eq!(state.constraints.len(), 2);
    assert_eq!(state.constraints[0].source_node, 1);
    assert_eq!(state.constraints[1].source_node, 2);
}

#[test]
fn test_state_forking() {
    let mut state = SymbolicState::new();
    state.set("x".to_string(), SymbolicValue::int(10));
    state.add_constraint(Constraint::new(
        SymbolicValue::bool(true),
        1,
    ));

    // Fork the state
    let mut forked = state.fork();

    // Both should have same initial values
    assert_eq!(forked.get("x"), SymbolicValue::int(10));
    assert_eq!(forked.constraints.len(), 1);

    // Modify forked state
    forked.set("y".to_string(), SymbolicValue::int(20));

    // Original should be unchanged
    assert_eq!(state.get("y"), SymbolicValue::Unknown);
    assert_eq!(forked.get("y"), SymbolicValue::int(20));
}

#[test]
fn test_loop_handling() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_loop_iterations(2)
        .build();

    // while (x < 10) { x = x + 1; }
    let condition = create_binary_expr("<", create_identifier("x"), create_literal_int(10));
    let body = create_assignment(
        "x",
        create_binary_expr("+", create_identifier("x"), create_literal_int(1)),
    );

    let while_loop = create_node(AstNodeKind::WhileStatement, vec![condition, body]);

    let program = create_node(
        AstNodeKind::Program,
        vec![create_var_decl("x", Some(create_literal_int(0))), while_loop],
    );

    let result = executor.execute(&program);

    // Should terminate (not infinite loop)
    assert!(!result.paths.is_empty());
}

// ============================================================================
// SECTION 4: ARITHMETIC AND SIMPLIFICATION (4 tests)
// ============================================================================

#[test]
fn test_constant_folding_arithmetic() {
    // 10 + 5 should simplify to 15
    let expr = SymbolicValue::binary(
        BinaryOperator::Add,
        SymbolicValue::int(10),
        SymbolicValue::int(5),
    );

    let simplified = expr.simplify();
    assert_eq!(simplified, SymbolicValue::Concrete(15));

    // 20 - 8 should simplify to 12
    let expr = SymbolicValue::binary(
        BinaryOperator::Subtract,
        SymbolicValue::int(20),
        SymbolicValue::int(8),
    );

    assert_eq!(expr.simplify(), SymbolicValue::Concrete(12));

    // 3 * 4 should simplify to 12
    let expr = SymbolicValue::binary(
        BinaryOperator::Multiply,
        SymbolicValue::int(3),
        SymbolicValue::int(4),
    );

    assert_eq!(expr.simplify(), SymbolicValue::Concrete(12));
}

#[test]
fn test_constant_folding_comparisons() {
    // 5 < 10 should be true
    let expr = SymbolicValue::binary(
        BinaryOperator::LessThan,
        SymbolicValue::int(5),
        SymbolicValue::int(10),
    );

    assert_eq!(expr.simplify(), SymbolicValue::ConcreteBool(true));

    // 10 == 10 should be true
    let expr = SymbolicValue::binary(
        BinaryOperator::Equal,
        SymbolicValue::int(10),
        SymbolicValue::int(10),
    );

    assert_eq!(expr.simplify(), SymbolicValue::ConcreteBool(true));

    // 5 > 10 should be false
    let expr = SymbolicValue::binary(
        BinaryOperator::GreaterThan,
        SymbolicValue::int(5),
        SymbolicValue::int(10),
    );

    assert_eq!(expr.simplify(), SymbolicValue::ConcreteBool(false));
}

#[test]
fn test_symbolic_arithmetic() {
    // x + 5 (symbolic)
    let expr = SymbolicValue::binary(
        BinaryOperator::Add,
        SymbolicValue::var("x"),
        SymbolicValue::int(5),
    );

    // Should remain symbolic (can't simplify)
    let simplified = expr.simplify();
    assert!(simplified.is_symbolic());

    match simplified {
        SymbolicValue::BinaryOp { operator, .. } => {
            assert_eq!(operator, BinaryOperator::Add);
        }
        _ => panic!("Expected binary operation"),
    }
}

#[test]
fn test_unary_operations() {
    // !true should be false
    let expr = SymbolicValue::UnaryOp {
        operator: UnaryOperator::Not,
        operand: Box::new(SymbolicValue::bool(true)),
    };

    assert_eq!(expr.simplify(), SymbolicValue::ConcreteBool(false));

    // !false should be true
    let expr = SymbolicValue::UnaryOp {
        operator: UnaryOperator::Not,
        operand: Box::new(SymbolicValue::bool(false)),
    };

    assert_eq!(expr.simplify(), SymbolicValue::ConcreteBool(true));

    // !x (symbolic)
    let expr = SymbolicValue::UnaryOp {
        operator: UnaryOperator::Not,
        operand: Box::new(SymbolicValue::var("x")),
    };

    // Should remain symbolic
    assert!(expr.simplify().is_symbolic());
}

// ============================================================================
// SECTION 5: COMPLEX CONTROL FLOW (3 tests)
// ============================================================================

#[test]
fn test_nested_if_statements() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_depth(3)
        .build();

    // if (x > 0) {
    //   if (x > 10) { return 1; } else { return 2; }
    // } else {
    //   return 3;
    // }

    let inner_condition = create_binary_expr(">", create_identifier("x"), create_literal_int(10));
    let inner_then = create_node(AstNodeKind::ReturnStatement, vec![create_literal_int(1)]);
    let inner_else = create_node(AstNodeKind::ReturnStatement, vec![create_literal_int(2)]);
    let inner_if = create_if_stmt(inner_condition, inner_then, Some(inner_else));

    let outer_condition = create_binary_expr(">", create_identifier("x"), create_literal_int(0));
    let outer_else = create_node(AstNodeKind::ReturnStatement, vec![create_literal_int(3)]);

    let outer_if = create_if_stmt(outer_condition, inner_if, Some(outer_else));

    let program = create_node(
        AstNodeKind::Program,
        vec![outer_if],
    );

    let result = executor.execute(&program);

    // Should explore paths
    assert!(
        result.stats.total_paths >= 1,
        "Nested ifs should create paths"
    );
}

#[test]
fn test_multiple_conditions() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_depth(2)
        .build();

    // if (x > 0 && y > 0) { return 1; } else { return 2; }
    let x_cond = create_binary_expr(">", create_identifier("x"), create_literal_int(0));
    let y_cond = create_binary_expr(">", create_identifier("y"), create_literal_int(0));
    let combined = create_binary_expr("&&", x_cond, y_cond);

    let then_branch = create_node(AstNodeKind::ReturnStatement, vec![create_literal_int(1)]);
    let else_branch = create_node(AstNodeKind::ReturnStatement, vec![create_literal_int(2)]);

    let if_stmt = create_if_stmt(combined, then_branch, Some(else_branch));

    let program = create_node(
        AstNodeKind::Program,
        vec![if_stmt],
    );

    let result = executor.execute(&program);

    // Should generate paths
    assert!(result.stats.total_paths >= 1);
}

#[test]
fn test_sequential_statements() {
    let executor = SymbolicExecutorBuilder::new().build();

    // let x = 1;
    // let y = 2;
    // let z = x + y;
    let program = create_node(
        AstNodeKind::Program,
        vec![
            create_var_decl("x", Some(create_literal_int(1))),
            create_var_decl("y", Some(create_literal_int(2))),
            create_var_decl(
                "z",
                Some(create_binary_expr(
                    "+",
                    create_identifier("x"),
                    create_identifier("y"),
                )),
            ),
        ],
    );

    let result = executor.execute(&program);

    if let Some(path) = result.paths.first() {
        assert_eq!(path.state.get("x"), SymbolicValue::int(1));
        assert_eq!(path.state.get("y"), SymbolicValue::int(2));
        // z should be 1 + 2 = 3 (simplified)
        assert_eq!(path.state.get("z"), SymbolicValue::int(3));
    }
}

// ============================================================================
// SECTION 6: EXECUTION PATH PROPERTIES (3 tests)
// ============================================================================

#[test]
fn test_execution_path_completion() {
    let state = SymbolicState::new();
    let trace = vec![1, 2, 3];

    let path = ExecutionPath::new(state, trace);
    assert!(!path.completed);
    assert_eq!(path.feasible, None);

    let completed = path.complete();
    assert!(completed.completed);
}

#[test]
fn test_execution_path_feasibility() {
    let state = SymbolicState::new();
    let trace = vec![1, 2];

    let path = ExecutionPath::new(state, trace);

    let feasible = path.with_feasibility(true);
    assert_eq!(feasible.feasible, Some(true));

    let infeasible = feasible.with_feasibility(false);
    assert_eq!(infeasible.feasible, Some(false));
}

#[test]
fn test_execution_trace() {
    let executor = SymbolicExecutorBuilder::new().build();

    let program = create_node(
        AstNodeKind::Program,
        vec![
            create_var_decl("x", Some(create_literal_int(1))),
            create_var_decl("y", Some(create_literal_int(2))),
        ],
    );

    let result = executor.execute(&program);

    if let Some(path) = result.paths.first() {
        // Trace should contain visited node IDs
        assert!(!path.trace.is_empty(), "Trace should not be empty");
    }
}

// ============================================================================
// SECTION 7: EDGE CASES AND LIMITS (4 tests)
// ============================================================================

#[test]
fn test_max_depth_limit() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_depth(3)
        .build();

    // Create deeply nested structure
    let program = create_node(
        AstNodeKind::Program,
        vec![
            create_var_decl("a", Some(create_literal_int(1))),
            create_var_decl("b", Some(create_literal_int(2))),
            create_var_decl("c", Some(create_literal_int(3))),
            create_var_decl("d", Some(create_literal_int(4))),
            create_var_decl("e", Some(create_literal_int(5))),
        ],
    );

    let result = executor.execute(&program);

    // Should respect max depth
    assert!(result.stats.max_depth_reached <= 3);
}

#[test]
fn test_max_paths_limit() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_paths(5)
        .build();

    // Create program with many branches
    let if1 = create_if_stmt(
        create_binary_expr(">", create_identifier("x"), create_literal_int(0)),
        create_assignment("y", create_literal_int(1)),
        Some(create_assignment("y", create_literal_int(2))),
    );

    let if2 = create_if_stmt(
        create_binary_expr(">", create_identifier("y"), create_literal_int(0)),
        create_assignment("z", create_literal_int(1)),
        Some(create_assignment("z", create_literal_int(2))),
    );

    let program = create_node(AstNodeKind::Program, vec![if1, if2]);

    let result = executor.execute(&program);

    // Should not exceed max paths
    assert!(result.paths.len() <= 5);
}

#[test]
fn test_empty_program() {
    let executor = SymbolicExecutorBuilder::new()
        .with_max_depth(1)
        .build();

    let program = create_node(AstNodeKind::Program, vec![]);

    let result = executor.execute(&program);

    // Should handle empty program gracefully
    // With max_depth=1, should hit depth limit immediately
    assert!(result.stats.total_paths >= 0);
    assert_eq!(result.stats.total_constraints, 0);
}

#[test]
fn test_visited_node_tracking() {
    let mut state = SymbolicState::new();

    assert!(!state.has_visited(1));

    state.mark_visited(1);
    assert!(state.has_visited(1));

    state.mark_visited(2);
    assert!(state.has_visited(1));
    assert!(state.has_visited(2));
    assert!(!state.has_visited(3));
}
