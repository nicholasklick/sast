//! AST traversal for taint tracking.
//!
//! This module will contain the main AST traversal loop that drives taint analysis.
//! The `track_taint_in_ast_with_depth` function dispatches to node-specific handlers
//! based on the AST node type.
//!
//! ## Traversal Strategy
//!
//! The traversal uses a depth-first approach with two key parameters:
//! - `branch_depth`: Tracks nesting inside conditionals (prevents strong updates)
//! - `ast_depth`: Tracks recursion depth (prevents stack overflow)
//!
//! ## Node Handling
//!
//! Different node types are handled by specialized handlers in `node_handlers/`:
//! - `assignments.rs`: Variable declarations, assignments, augmented assignments
//! - `calls.rs`: Function calls, constructor invocations
//! - `control_flow.rs`: If statements, ternaries, switch/match, loops
//! - `functions.rs`: Function/method declarations, web handler detection
//!
//! ## Methods to be moved here from mod.rs
//!
//! - `track_taint_in_ast()` - Public entry point for AST traversal
//! - `track_taint_in_ast_with_depth()` - Main traversal dispatch loop
//!
//! These methods will be extracted from mod.rs in Phase 2 of the refactoring.

// NOTE: Implementation remains in mod.rs for now.
// This file will be populated in Phase 2 when we extract the traversal
// logic to use the NodeHandlerContext pattern.
