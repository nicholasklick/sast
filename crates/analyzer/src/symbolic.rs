//! Symbolic execution engine for path-sensitive analysis
//!
//! This module implements a symbolic execution engine that explores program paths
//! by treating program inputs as symbolic values rather than concrete values.
//!
//! ## Overview
//!
//! Symbolic execution is a program analysis technique that:
//! 1. Treats inputs as symbolic variables instead of concrete values
//! 2. Executes the program symbolically, maintaining path conditions
//! 3. Explores multiple execution paths systematically
//! 4. Uses constraint solving to determine path feasibility
//!
//! ## Use Cases
//!
//! - **Test case generation**: Find inputs that trigger specific paths
//! - **Bug finding**: Discover inputs that cause crashes or violations
//! - **Security analysis**: Find exploitable inputs (buffer overflows, injections)
//! - **Path-sensitive analysis**: Analyze program behavior along specific paths
//!
//! ## Example
//!
//! ```rust
//! use kodecd_analyzer::{SymbolicExecutor, SymbolicExecutorBuilder};
//! use kodecd_parser::{AstNode, AstNodeKind, Location, Span};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a simple program AST
//! let program = AstNode {
//!     id: 0,
//!     kind: AstNodeKind::Program,
//!     location: Location {
//!         file_path: "test.js".to_string(),
//!         span: Span {
//!             start_line: 1, start_column: 0,
//!             end_line: 1, end_column: 10,
//!             start_byte: 0, end_byte: 10,
//!         },
//!     },
//!     children: Vec::new(),
//!     text: String::new(),
//! };
//!
//! // Execute symbolically
//! let executor = SymbolicExecutorBuilder::new()
//!     .with_max_depth(10)
//!     .with_max_paths(100)
//!     .build();
//!
//! let result = executor.execute(&program);
//!
//! // Examine explored paths
//! println!("Explored {} paths", result.paths.len());
//! for path in &result.paths {
//!     println!("Path conditions: {:?}", path.constraints);
//! }
//! # Ok(())
//! # }
//! ```

use kodecd_parser::ast::{AstNode, AstNodeKind, NodeId};
use std::collections::{HashMap, HashSet, VecDeque};
use serde::{Deserialize, Serialize};

/// Represents a symbolic value
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SymbolicValue {
    /// Concrete integer value
    Concrete(i64),

    /// Concrete boolean value
    ConcreteBool(bool),

    /// Concrete string value
    ConcreteString(String),

    /// Symbolic variable (name)
    Symbolic(String),

    /// Binary operation on symbolic values
    BinaryOp {
        operator: BinaryOperator,
        left: Box<SymbolicValue>,
        right: Box<SymbolicValue>,
    },

    /// Unary operation on symbolic value
    UnaryOp {
        operator: UnaryOperator,
        operand: Box<SymbolicValue>,
    },

    /// Conditional expression (ternary)
    Conditional {
        condition: Box<SymbolicValue>,
        true_value: Box<SymbolicValue>,
        false_value: Box<SymbolicValue>,
    },

    /// Unknown/uninitialized value
    Unknown,
}

impl SymbolicValue {
    /// Create a symbolic variable
    pub fn var(name: impl Into<String>) -> Self {
        SymbolicValue::Symbolic(name.into())
    }

    /// Create a concrete integer
    pub fn int(value: i64) -> Self {
        SymbolicValue::Concrete(value)
    }

    /// Create a concrete boolean
    pub fn bool(value: bool) -> Self {
        SymbolicValue::ConcreteBool(value)
    }

    /// Create a binary operation
    pub fn binary(op: BinaryOperator, left: SymbolicValue, right: SymbolicValue) -> Self {
        SymbolicValue::BinaryOp {
            operator: op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    /// Check if this is a concrete value
    pub fn is_concrete(&self) -> bool {
        matches!(self,
            SymbolicValue::Concrete(_) |
            SymbolicValue::ConcreteBool(_) |
            SymbolicValue::ConcreteString(_)
        )
    }

    /// Check if this is a symbolic value
    pub fn is_symbolic(&self) -> bool {
        !self.is_concrete()
    }

    /// Simplify the symbolic value if possible
    pub fn simplify(&self) -> SymbolicValue {
        match self {
            SymbolicValue::BinaryOp { operator, left, right } => {
                let left = left.simplify();
                let right = right.simplify();

                // Constant folding
                if let (SymbolicValue::Concrete(l), SymbolicValue::Concrete(r)) = (&left, &right) {
                    match operator {
                        BinaryOperator::Add => return SymbolicValue::Concrete(l + r),
                        BinaryOperator::Subtract => return SymbolicValue::Concrete(l - r),
                        BinaryOperator::Multiply => return SymbolicValue::Concrete(l * r),
                        BinaryOperator::Divide if *r != 0 => return SymbolicValue::Concrete(l / r),
                        BinaryOperator::Equal => return SymbolicValue::ConcreteBool(l == r),
                        BinaryOperator::NotEqual => return SymbolicValue::ConcreteBool(l != r),
                        BinaryOperator::LessThan => return SymbolicValue::ConcreteBool(l < r),
                        BinaryOperator::LessThanOrEqual => return SymbolicValue::ConcreteBool(l <= r),
                        BinaryOperator::GreaterThan => return SymbolicValue::ConcreteBool(l > r),
                        BinaryOperator::GreaterThanOrEqual => return SymbolicValue::ConcreteBool(l >= r),
                        _ => {}
                    }
                }

                SymbolicValue::BinaryOp {
                    operator: *operator,
                    left: Box::new(left),
                    right: Box::new(right),
                }
            }

            SymbolicValue::UnaryOp { operator, operand } => {
                let operand = operand.simplify();

                if let SymbolicValue::ConcreteBool(b) = operand {
                    if *operator == UnaryOperator::Not {
                        return SymbolicValue::ConcreteBool(!b);
                    }
                }

                SymbolicValue::UnaryOp {
                    operator: *operator,
                    operand: Box::new(operand),
                }
            }

            _ => self.clone(),
        }
    }
}

/// Binary operators for symbolic expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryOperator {
    // Arithmetic
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,

    // Comparison
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,

    // Logical
    And,
    Or,

    // Bitwise
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
}

/// Unary operators for symbolic expressions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnaryOperator {
    Not,
    Negate,
    BitwiseNot,
}

/// A constraint on symbolic values (path condition)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraint {
    /// The symbolic expression that must be true
    pub condition: SymbolicValue,

    /// Source location where this constraint was added
    pub source_node: NodeId,
}

impl Constraint {
    /// Create a new constraint
    pub fn new(condition: SymbolicValue, source_node: NodeId) -> Self {
        Self {
            condition: condition.simplify(),
            source_node,
        }
    }
}

/// Symbolic state at a program point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicState {
    /// Mapping from variable names to symbolic values
    variables: HashMap<String, SymbolicValue>,

    /// Path constraints accumulated so far
    pub constraints: Vec<Constraint>,

    /// Current execution depth (for loop/recursion limiting)
    pub depth: usize,

    /// Set of nodes already visited on this path
    visited_nodes: HashSet<NodeId>,
}

impl SymbolicState {
    /// Create a new empty symbolic state
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            constraints: Vec::new(),
            depth: 0,
            visited_nodes: HashSet::new(),
        }
    }

    /// Get the symbolic value of a variable
    pub fn get(&self, name: &str) -> SymbolicValue {
        self.variables.get(name).cloned().unwrap_or(SymbolicValue::Unknown)
    }

    /// Set the symbolic value of a variable
    pub fn set(&mut self, name: String, value: SymbolicValue) {
        self.variables.insert(name, value);
    }

    /// Add a path constraint
    pub fn add_constraint(&mut self, constraint: Constraint) {
        self.constraints.push(constraint);
    }

    /// Check if a node has been visited
    pub fn has_visited(&self, node_id: NodeId) -> bool {
        self.visited_nodes.contains(&node_id)
    }

    /// Mark a node as visited
    pub fn mark_visited(&mut self, node_id: NodeId) {
        self.visited_nodes.insert(node_id);
    }

    /// Clone the state for exploring a different path
    pub fn fork(&self) -> Self {
        self.clone()
    }

    /// Get all variables and their values
    pub fn variables(&self) -> &HashMap<String, SymbolicValue> {
        &self.variables
    }
}

impl Default for SymbolicState {
    fn default() -> Self {
        Self::new()
    }
}

/// An execution path through the program
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionPath {
    /// The final symbolic state at the end of this path
    pub state: SymbolicState,

    /// Path constraints that must be satisfied
    pub constraints: Vec<Constraint>,

    /// Sequence of nodes executed along this path
    pub trace: Vec<NodeId>,

    /// Whether this path completed successfully
    pub completed: bool,

    /// Whether this path is feasible (constraints satisfiable)
    pub feasible: Option<bool>,
}

impl ExecutionPath {
    /// Create a new execution path
    pub fn new(state: SymbolicState, trace: Vec<NodeId>) -> Self {
        let constraints = state.constraints.clone();
        Self {
            state,
            constraints,
            trace,
            completed: false,
            feasible: None,
        }
    }

    /// Mark this path as completed
    pub fn complete(mut self) -> Self {
        self.completed = true;
        self
    }

    /// Set feasibility
    pub fn with_feasibility(mut self, feasible: bool) -> Self {
        self.feasible = Some(feasible);
        self
    }
}

/// Result of symbolic execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolicExecutionResult {
    /// All explored paths
    pub paths: Vec<ExecutionPath>,

    /// Statistics about the execution
    pub stats: ExecutionStats,
}

/// Statistics about symbolic execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStats {
    /// Total paths explored
    pub total_paths: usize,

    /// Number of completed paths
    pub completed_paths: usize,

    /// Number of incomplete paths (hit depth/limit)
    pub incomplete_paths: usize,

    /// Maximum depth reached
    pub max_depth_reached: usize,

    /// Total constraints generated
    pub total_constraints: usize,
}

/// Symbolic executor configuration
pub struct SymbolicExecutorBuilder {
    max_depth: usize,
    max_paths: usize,
    max_loop_iterations: usize,
}

impl SymbolicExecutorBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            max_depth: 100,
            max_paths: 1000,
            max_loop_iterations: 10,
        }
    }

    /// Set maximum execution depth
    pub fn with_max_depth(mut self, depth: usize) -> Self {
        self.max_depth = depth;
        self
    }

    /// Set maximum number of paths to explore
    pub fn with_max_paths(mut self, paths: usize) -> Self {
        self.max_paths = paths;
        self
    }

    /// Set maximum loop iterations
    pub fn with_max_loop_iterations(mut self, iterations: usize) -> Self {
        self.max_loop_iterations = iterations;
        self
    }

    /// Build the symbolic executor
    pub fn build(self) -> SymbolicExecutor {
        SymbolicExecutor {
            max_depth: self.max_depth,
            max_paths: self.max_paths,
            max_loop_iterations: self.max_loop_iterations,
        }
    }
}

impl Default for SymbolicExecutorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Symbolic execution engine
pub struct SymbolicExecutor {
    max_depth: usize,
    max_paths: usize,
    max_loop_iterations: usize,
}

impl SymbolicExecutor {
    /// Execute a program symbolically
    pub fn execute(&self, ast: &AstNode) -> SymbolicExecutionResult {
        let mut paths = Vec::new();
        let mut worklist = VecDeque::new();

        // Initialize with empty state
        let initial_state = SymbolicState::new();
        worklist.push_back((ast, initial_state, Vec::new()));

        let mut max_depth_reached = 0;

        while let Some((node, mut state, mut trace)) = worklist.pop_front() {
            // Check limits
            if paths.len() >= self.max_paths {
                break;
            }

            if state.depth >= self.max_depth {
                // Path incomplete due to depth limit
                paths.push(ExecutionPath::new(state, trace));
                continue;
            }

            max_depth_reached = max_depth_reached.max(state.depth);

            // Mark node as visited
            state.mark_visited(node.id);
            trace.push(node.id);

            // Execute the node
            match self.execute_node(node, &mut state, &mut worklist, trace.clone()) {
                ExecutionAction::Continue => {
                    // Continue with children
                    state.depth += 1;
                    for child in &node.children {
                        worklist.push_back((child, state.clone(), trace.clone()));
                    }
                }
                ExecutionAction::Branch(true_state, false_state) => {
                    // Fork execution for both branches
                    if let Some(true_child) = node.children.first() {
                        worklist.push_back((true_child, true_state, trace.clone()));
                    }
                    if node.children.len() > 1 {
                        worklist.push_back((&node.children[1], false_state, trace.clone()));
                    }
                }
                ExecutionAction::Complete => {
                    // Path completed
                    paths.push(ExecutionPath::new(state, trace).complete());
                }
                ExecutionAction::Skip => {
                    // Skip this node
                }
            }
        }

        // Compute statistics
        let completed_paths = paths.iter().filter(|p| p.completed).count();
        let total_constraints = paths.iter().map(|p| p.constraints.len()).sum();

        let stats = ExecutionStats {
            total_paths: paths.len(),
            completed_paths,
            incomplete_paths: paths.len() - completed_paths,
            max_depth_reached,
            total_constraints,
        };

        SymbolicExecutionResult { paths, stats }
    }

    /// Execute a single AST node
    fn execute_node(
        &self,
        node: &AstNode,
        state: &mut SymbolicState,
        _worklist: &mut VecDeque<(&AstNode, SymbolicState, Vec<NodeId>)>,
        _trace: Vec<NodeId>,
    ) -> ExecutionAction {
        match &node.kind {
            AstNodeKind::VariableDeclaration { name, .. } => {
                // Create symbolic variable
                if node.children.is_empty() {
                    state.set(name.clone(), SymbolicValue::var(name));
                } else {
                    // Evaluate initializer
                    let value = self.evaluate_expression(&node.children[0], state);
                    state.set(name.clone(), value);
                }
                ExecutionAction::Continue
            }

            AstNodeKind::AssignmentExpression { .. } => {
                if node.children.len() >= 2 {
                    let lhs = &node.children[0];
                    let rhs = &node.children[1];

                    if let AstNodeKind::Identifier { name } = &lhs.kind {
                        let value = self.evaluate_expression(rhs, state);
                        state.set(name.clone(), value);
                    }
                }
                ExecutionAction::Continue
            }

            AstNodeKind::IfStatement => {
                // Evaluate condition
                if let Some(condition_node) = node.children.first() {
                    let condition = self.evaluate_expression(condition_node, state);

                    // Fork execution
                    let mut true_state = state.fork();
                    let mut false_state = state.fork();

                    true_state.add_constraint(Constraint::new(condition.clone(), node.id));

                    // Negate condition for false branch
                    let negated = SymbolicValue::UnaryOp {
                        operator: UnaryOperator::Not,
                        operand: Box::new(condition),
                    };
                    false_state.add_constraint(Constraint::new(negated, node.id));

                    return ExecutionAction::Branch(true_state, false_state);
                }
                ExecutionAction::Continue
            }

            AstNodeKind::WhileStatement | AstNodeKind::ForStatement => {
                // Limit loop iterations (loop unrolling)
                if state.has_visited(node.id) {
                    // Already visited - exit loop
                    ExecutionAction::Complete
                } else {
                    ExecutionAction::Continue
                }
            }

            AstNodeKind::ReturnStatement => {
                ExecutionAction::Complete
            }

            _ => ExecutionAction::Continue,
        }
    }

    /// Evaluate an expression to a symbolic value
    fn evaluate_expression(&self, node: &AstNode, state: &SymbolicState) -> SymbolicValue {
        match &node.kind {
            AstNodeKind::Identifier { name } => {
                state.get(name)
            }

            AstNodeKind::Literal { value } => {
                // Parse literal value
                match value {
                    kodecd_parser::ast::LiteralValue::Number(n) => {
                        n.parse::<i64>()
                            .map(SymbolicValue::Concrete)
                            .unwrap_or(SymbolicValue::Unknown)
                    }
                    kodecd_parser::ast::LiteralValue::Boolean(b) => {
                        SymbolicValue::ConcreteBool(*b)
                    }
                    kodecd_parser::ast::LiteralValue::String(s) => {
                        SymbolicValue::ConcreteString(s.clone())
                    }
                    _ => SymbolicValue::Unknown,
                }
            }

            AstNodeKind::BinaryExpression { operator } => {
                if node.children.len() >= 2 {
                    let left = self.evaluate_expression(&node.children[0], state);
                    let right = self.evaluate_expression(&node.children[1], state);

                    let op = match operator.as_str() {
                        "+" => BinaryOperator::Add,
                        "-" => BinaryOperator::Subtract,
                        "*" => BinaryOperator::Multiply,
                        "/" => BinaryOperator::Divide,
                        "%" => BinaryOperator::Modulo,
                        "==" | "===" => BinaryOperator::Equal,
                        "!=" | "!==" => BinaryOperator::NotEqual,
                        "<" => BinaryOperator::LessThan,
                        "<=" => BinaryOperator::LessThanOrEqual,
                        ">" => BinaryOperator::GreaterThan,
                        ">=" => BinaryOperator::GreaterThanOrEqual,
                        "&&" => BinaryOperator::And,
                        "||" => BinaryOperator::Or,
                        "&" => BinaryOperator::BitwiseAnd,
                        "|" => BinaryOperator::BitwiseOr,
                        "^" => BinaryOperator::BitwiseXor,
                        "<<" => BinaryOperator::LeftShift,
                        ">>" => BinaryOperator::RightShift,
                        _ => return SymbolicValue::Unknown,
                    };

                    SymbolicValue::binary(op, left, right).simplify()
                } else {
                    SymbolicValue::Unknown
                }
            }

            AstNodeKind::UnaryExpression { operator } => {
                if let Some(operand_node) = node.children.first() {
                    let operand = self.evaluate_expression(operand_node, state);

                    let op = match operator.as_str() {
                        "!" => UnaryOperator::Not,
                        "-" => UnaryOperator::Negate,
                        "~" => UnaryOperator::BitwiseNot,
                        _ => return SymbolicValue::Unknown,
                    };

                    SymbolicValue::UnaryOp {
                        operator: op,
                        operand: Box::new(operand),
                    }.simplify()
                } else {
                    SymbolicValue::Unknown
                }
            }

            _ => SymbolicValue::Unknown,
        }
    }
}

/// Action to take after executing a node
enum ExecutionAction {
    /// Continue with children
    Continue,

    /// Branch into two paths
    Branch(SymbolicState, SymbolicState),

    /// Complete this path
    Complete,

    /// Skip this node
    Skip,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_symbolic_value_creation() {
        let var = SymbolicValue::var("x");
        assert!(var.is_symbolic());

        let int = SymbolicValue::int(42);
        assert!(int.is_concrete());

        let bool = SymbolicValue::bool(true);
        assert!(bool.is_concrete());
    }

    #[test]
    fn test_constant_folding() {
        let left = SymbolicValue::int(10);
        let right = SymbolicValue::int(5);
        let expr = SymbolicValue::binary(BinaryOperator::Add, left, right);

        let simplified = expr.simplify();
        assert_eq!(simplified, SymbolicValue::Concrete(15));
    }

    #[test]
    fn test_symbolic_state() {
        let mut state = SymbolicState::new();

        state.set("x".to_string(), SymbolicValue::int(10));
        assert_eq!(state.get("x"), SymbolicValue::int(10));

        state.set("y".to_string(), SymbolicValue::var("input"));
        assert!(state.get("y").is_symbolic());
    }

    #[test]
    fn test_constraint_creation() {
        let condition = SymbolicValue::binary(
            BinaryOperator::GreaterThan,
            SymbolicValue::var("x"),
            SymbolicValue::int(0),
        );

        let constraint = Constraint::new(condition, 1);
        assert_eq!(constraint.source_node, 1);
    }

    #[test]
    fn test_state_forking() {
        let mut state = SymbolicState::new();
        state.set("x".to_string(), SymbolicValue::int(10));

        let forked = state.fork();
        assert_eq!(forked.get("x"), SymbolicValue::int(10));
    }
}
