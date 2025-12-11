//! Function/method declaration handlers for taint tracking.
//!
//! Handles:
//! - `FunctionDeclaration` / `MethodDeclaration` - function scope handling
//! - Web handler detection (Flask, Django, Spring)
//! - Return value taint analysis for XSS detection

use super::NodeHandlerContext;
use crate::interprocedural_taint::InterproceduralTaintAnalysis;
use gittera_parser::ast::AstNode;

impl InterproceduralTaintAnalysis {
    /// Handle function/method declaration
    ///
    /// - Creates a fresh scope for local taint tracking
    /// - Resets branch_depth to 0 for the new scope
    /// - Checks for web handler patterns and XSS in returns
    pub(crate) fn handle_function_declaration(
        &self,
        node: &AstNode,
        ctx: &mut NodeHandlerContext<'_>,
    ) {
        // TODO: Extract logic from track_taint_in_ast_with_depth
        let _ = (node, ctx);
    }
}
