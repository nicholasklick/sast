//! Taint checking utilities.
//!
//! This module will contain functions for checking whether AST nodes contain
//! tainted data, with support for symbolic evaluation and context-specific
//! sanitization tracking.
//!
//! ## Key Methods to be moved here from mod.rs
//!
//! - `is_node_tainted()` - Check if a node contains tainted data
//! - `is_node_tainted_with_sym()` - Taint check with symbolic state for ternaries
//! - `is_node_tainted_for_html()` - HTML-specific taint checking for XSS
//! - `is_initializer_tainted()` / `is_initializer_tainted_with_sym()` - Initializer checks
//! - `has_tainted_arguments()` - Check if function call has tainted arguments
//! - `are_tainted_args_sanitized_for_state()` - Context-specific sanitization check
//! - `compute_inherited_sanitization()` - Sanitization inheritance for declarations
//! - `collect_tainted_refs()` - Collect tainted variable references
//! - `analyze_method_return_taint()` - Inter-procedural return taint analysis
//! - `find_return_taint()` - Check return statements for taint
//!
//! These methods will be extracted from mod.rs in Phase 2 of the refactoring.

// NOTE: Implementation remains in mod.rs for now.
// This file will be populated in Phase 2 when we extract the taint
// checking logic.
