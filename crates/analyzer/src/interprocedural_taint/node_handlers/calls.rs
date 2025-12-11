//! Call expression handlers for taint tracking.
//!
//! Handles:
//! - `CallExpression` - function/method calls
//! - `object_creation_expression` - Java `new` expressions (constructor sinks)

use super::NodeHandlerContext;
use crate::interprocedural_taint::InterproceduralTaintAnalysis;
use gittera_parser::ast::AstNode;

impl InterproceduralTaintAnalysis {
    /// Handle a call expression node
    ///
    /// Checks for:
    /// - Collection operations (list.add, map.put, etc.)
    /// - Sink functions with tainted arguments
    /// - Safe sink patterns (parameterized queries, etc.)
    pub(crate) fn handle_call_expression(
        &self,
        node: &AstNode,
        callee: &str,
        ctx: &mut NodeHandlerContext<'_>,
    ) {
        // TODO: Extract logic from track_taint_in_ast_with_depth
        let _ = (node, callee, ctx);
    }

    /// Handle Java object creation expressions (new ClassName(...))
    ///
    /// Checks for constructor sinks like:
    /// - ProcessBuilder (command injection)
    /// - FileInputStream/FileOutputStream (path traversal)
    pub(crate) fn handle_object_creation(
        &self,
        node: &AstNode,
        ctx: &mut NodeHandlerContext<'_>,
    ) {
        // TODO: Extract logic from track_taint_in_ast_with_depth
        let _ = (node, ctx);
    }
}
