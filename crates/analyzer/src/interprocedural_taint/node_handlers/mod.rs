//! Node-specific handlers for taint tracking.
//!
//! This module contains handlers for different AST node types,
//! organized by category for maintainability. Each handler receives
//! a shared context struct and delegates language-specific logic
//! to the `LanguageTaintHandler` trait.
//!
//! NOTE: The handler modules are currently stubs that will be populated
//! in Phase 2 of the refactoring when methods are extracted from mod.rs.

mod assignments;
mod calls;
mod control_flow;
mod functions;

// Re-exports from handler modules (currently stubs)
#[allow(unused_imports)]
pub use assignments::*;
#[allow(unused_imports)]
pub use calls::*;
#[allow(unused_imports)]
pub use control_flow::*;
#[allow(unused_imports)]
pub use functions::*;

use crate::symbolic::SymbolicState;
use crate::taint::{FlowState, TaintVulnerability};
use std::collections::{HashMap, HashSet};

/// Context passed to node handlers for processing.
///
/// This struct encapsulates all mutable state needed during AST traversal,
/// allowing handlers to be implemented as methods that take this context
/// rather than having many individual parameters.
pub struct NodeHandlerContext<'a> {
    /// Variables currently known to be tainted
    pub tainted_vars: &'a mut HashSet<String>,
    /// Vulnerabilities found during analysis
    pub vulnerabilities: &'a mut Vec<TaintVulnerability>,
    /// Symbolic state for constant propagation
    pub sym_state: &'a mut SymbolicState,
    /// Tracked sizes of list/array collections for index-based taint
    pub list_sizes: &'a mut HashMap<String, usize>,
    /// Variables validated for path traversal (e.g., after `if '../' in var: return`)
    pub path_sanitized_vars: &'a mut HashSet<String>,
    /// Maps variables to the flow states they've been sanitized for
    pub sanitized_for_vars: &'a mut HashMap<String, HashSet<FlowState>>,
    /// Current branch nesting depth (0 = top level, >0 = inside conditionals)
    pub branch_depth: usize,
    /// Current AST depth (for preventing stack overflow)
    pub ast_depth: usize,
}

impl<'a> NodeHandlerContext<'a> {
    /// Create a new context
    pub fn new(
        tainted_vars: &'a mut HashSet<String>,
        vulnerabilities: &'a mut Vec<TaintVulnerability>,
        sym_state: &'a mut SymbolicState,
        list_sizes: &'a mut HashMap<String, usize>,
        path_sanitized_vars: &'a mut HashSet<String>,
        sanitized_for_vars: &'a mut HashMap<String, HashSet<FlowState>>,
        branch_depth: usize,
        ast_depth: usize,
    ) -> Self {
        Self {
            tainted_vars,
            vulnerabilities,
            sym_state,
            list_sizes,
            path_sanitized_vars,
            sanitized_for_vars,
            branch_depth,
            ast_depth,
        }
    }

    /// Create a child context with incremented AST depth
    pub fn child(&mut self) -> NodeHandlerContext<'_> {
        NodeHandlerContext {
            tainted_vars: self.tainted_vars,
            vulnerabilities: self.vulnerabilities,
            sym_state: self.sym_state,
            list_sizes: self.list_sizes,
            path_sanitized_vars: self.path_sanitized_vars,
            sanitized_for_vars: self.sanitized_for_vars,
            branch_depth: self.branch_depth,
            ast_depth: self.ast_depth + 1,
        }
    }

    /// Create a child context inside a branch (incremented branch_depth)
    pub fn in_branch(&mut self) -> NodeHandlerContext<'_> {
        NodeHandlerContext {
            tainted_vars: self.tainted_vars,
            vulnerabilities: self.vulnerabilities,
            sym_state: self.sym_state,
            list_sizes: self.list_sizes,
            path_sanitized_vars: self.path_sanitized_vars,
            sanitized_for_vars: self.sanitized_for_vars,
            branch_depth: self.branch_depth + 1,
            ast_depth: self.ast_depth + 1,
        }
    }

    /// Check if we can perform strong updates (not inside a branch)
    pub fn can_strong_update(&self) -> bool {
        self.branch_depth == 0
    }
}
