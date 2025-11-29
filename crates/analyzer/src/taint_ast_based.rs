//! AST-based taint analysis transfer function
//!
//! This module implements the corrected taint analysis that operates on AST nodes
//! instead of string labels, providing accurate tracking through complex expressions.

use super::{TaintSource, TaintSourceKind, TaintValue};
use crate::cfg::{CfgGraphIndex, CfgNode, CfgNodeKind, ControlFlowGraph};
use crate::dataflow::TransferFunction;
use gittera_parser::ast::{AstNode, AstNodeKind, LiteralValue, NodeId};
use std::collections::{HashMap, HashSet};

/// AST-based taint transfer function
pub struct AstBasedTaintTransferFunction {
    sources: Vec<TaintSource>,
    sanitizers: HashSet<String>,
}

impl AstBasedTaintTransferFunction {
    pub fn new(sources: Vec<TaintSource>, sanitizers: HashSet<String>) -> Self {
        Self {
            sources,
            sanitizers,
        }
    }

    /// Build a mapping from AST node ID to the actual node for fast lookup
    fn build_ast_map<'a>(node: &'a AstNode, map: &mut HashMap<NodeId, &'a AstNode>) {
        map.insert(node.id, node);
        for child in &node.children {
            Self::build_ast_map(child, map);
        }
    }

    /// Find an AST node by its ID
    fn find_ast_node<'a>(ast: &'a AstNode, node_id: NodeId) -> Option<&'a AstNode> {
        if ast.id == node_id {
            return Some(ast);
        }
        for child in &ast.children {
            if let Some(found) = Self::find_ast_node(child, node_id) {
                return Some(found);
            }
        }
        None
    }

    /// Check if a function name is a taint source
    fn is_taint_source(&self, name: &str) -> Option<TaintSourceKind> {
        let name_lower = name.to_lowercase();
        for source in &self.sources {
            let source_lower = source.name.to_lowercase();
            if name_lower.contains(&source_lower) || source_lower.contains(&name_lower) {
                return Some(source.kind.clone());
            }
        }
        None
    }

    /// Check if a function name is a sanitizer
    fn is_sanitizer(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        self.sanitizers
            .iter()
            .any(|san| name_lower.contains(&san.to_lowercase()))
    }

    /// Evaluate an expression to determine if it contains tainted data
    ///
    /// This is the core function that properly analyzes AST structure
    /// instead of relying on brittle string parsing.
    fn evaluate_expression(
        &self,
        expr: &AstNode,
        taint_set: &HashSet<TaintValue>,
    ) -> Option<TaintValue> {
        match &expr.kind {
            // Identifier: look up in taint set
            AstNodeKind::Identifier { name } => {
                taint_set.iter().find(|t| t.variable == *name).cloned()
            }

            // Literal: never tainted
            AstNodeKind::Literal { .. } => None,

            // Binary expression: tainted if either operand is tainted
            AstNodeKind::BinaryExpression { .. } => {
                for child in &expr.children {
                    if let Some(taint) = self.evaluate_expression(child, taint_set) {
                        return Some(taint);
                    }
                }
                None
            }

            // Unary expression: propagate taint from operand
            AstNodeKind::UnaryExpression { .. } => {
                if let Some(operand) = expr.children.first() {
                    self.evaluate_expression(operand, taint_set)
                } else {
                    None
                }
            }

            // Call expression: check if it's a source, sanitizer, or propagates taint
            AstNodeKind::CallExpression { callee, .. } => {
                // Check if this is a taint source
                if let Some(source_kind) = self.is_taint_source(callee) {
                    return Some(TaintValue::new(expr.text.clone(), source_kind));
                }

                // Check if this is a sanitizer
                if self.is_sanitizer(callee) {
                    return None; // Sanitizer returns clean value
                }

                // Otherwise, propagate taint from arguments
                for arg in &expr.children {
                    if let Some(taint) = self.evaluate_expression(arg, taint_set) {
                        return Some(taint);
                    }
                }
                None
            }

            // Member expression: taint propagates from object
            AstNodeKind::MemberExpression { object, .. } => {
                // Check if the object itself is tainted
                if let Some(taint) = taint_set.iter().find(|t| t.variable == *object).cloned() {
                    return Some(taint);
                }

                // Also check if it's in the children (for nested member access)
                if let Some(obj_node) = expr.children.first() {
                    self.evaluate_expression(obj_node, taint_set)
                } else {
                    None
                }
            }

            // Assignment expression: evaluate the RHS
            AstNodeKind::AssignmentExpression { .. } => {
                if expr.children.len() >= 2 {
                    self.evaluate_expression(&expr.children[1], taint_set)
                } else {
                    None
                }
            }

            // Variable declaration: check initializer
            AstNodeKind::VariableDeclaration { initializer, .. } => {
                // If there's an initializer expression in the text, try to evaluate it
                if initializer.is_some() {
                    // The initializer should be in the children
                    if let Some(init_node) = expr.children.first() {
                        return self.evaluate_expression(init_node, taint_set);
                    }
                }
                None
            }

            // Block: evaluate all statements (take first tainted one)
            AstNodeKind::Block => {
                for child in &expr.children {
                    if let Some(taint) = self.evaluate_expression(child, taint_set) {
                        return Some(taint);
                    }
                }
                None
            }

            // Expression statement: evaluate the expression
            AstNodeKind::ExpressionStatement => {
                if let Some(expr_node) = expr.children.first() {
                    self.evaluate_expression(expr_node, taint_set)
                } else {
                    None
                }
            }

            // Default: no taint
            _ => None,
        }
    }

    /// Extract all variables being assigned to (left-hand side of assignment)
    ///
    /// This handles simple assignments, destructuring, member expressions, etc.
    fn extract_lvalues(&self, lhs: &AstNode) -> Vec<String> {
        let mut vars = Vec::new();

        match &lhs.kind {
            AstNodeKind::Identifier { name } => {
                vars.push(name.clone());
            }

            AstNodeKind::MemberExpression { property, .. } => {
                // For obj.field = ..., track the property
                // In a full implementation, we'd track the full path
                vars.push(property.clone());
            }

            AstNodeKind::VariableDeclaration { name, .. } => {
                vars.push(name.clone());
            }

            // For complex patterns, recursively extract
            _ => {
                for child in &lhs.children {
                    vars.extend(self.extract_lvalues(child));
                }
            }
        }

        vars
    }

    /// Handle an assignment expression
    fn handle_assignment(
        &self,
        node: &AstNode,
        output: &mut HashSet<TaintValue>,
        input: &HashSet<TaintValue>,
    ) {
        if node.children.len() < 2 {
            return;
        }

        let lhs = &node.children[0];
        let rhs = &node.children[1];

        // 1. Evaluate RHS to see if it's tainted
        let rhs_taint = self.evaluate_expression(rhs, input);

        // 2. Extract LHS variables
        let lhs_vars = self.extract_lvalues(lhs);

        // 3. Update taint for LHS
        if let Some(taint) = rhs_taint {
            // RHS is tainted - propagate to all LHS variables, preserving conditions
            for var in lhs_vars {
                output.insert(TaintValue {
                    variable: var,
                    source: taint.source.clone(),
                    sanitized: false,
                    taint_condition: taint.taint_condition.clone(),
                    sanitized_condition: taint.sanitized_condition.clone(),
                });
            }
        } else {
            // RHS is clean - kill taint for LHS variables
            for var in &lhs_vars {
                output.retain(|t| &t.variable != var);
            }
        }
    }

    /// Handle a call expression (check for sources and sanitizers)
    fn handle_call(
        &self,
        node: &AstNode,
        output: &mut HashSet<TaintValue>,
        input: &HashSet<TaintValue>,
    ) {
        if let AstNodeKind::CallExpression { callee, .. } = &node.kind {
            // Check if this is a taint source
            if let Some(source_kind) = self.is_taint_source(callee) {
                // Generate new taint
                output.insert(TaintValue::new(node.text.clone(), source_kind));
            }

            // Check if this is a sanitizer
            if self.is_sanitizer(callee) {
                // Mark all tainted arguments as sanitized
                for arg in &node.children {
                    if let Some(taint) = self.evaluate_expression(arg, input) {
                        output.insert(TaintValue {
                            variable: taint.variable,
                            source: taint.source,
                            sanitized: true,
                            taint_condition: taint.taint_condition.clone(),
                            sanitized_condition: taint.sanitized_condition.clone(),
                        });
                    }
                }
            }
        }
    }

    /// Handle a variable declaration
    fn handle_variable_declaration(
        &self,
        node: &AstNode,
        output: &mut HashSet<TaintValue>,
        input: &HashSet<TaintValue>,
    ) {
        if let AstNodeKind::VariableDeclaration { name, .. } = &node.kind {
            // Check if the initializer is tainted
            if let Some(init_node) = node.children.first() {
                if let Some(taint) = self.evaluate_expression(init_node, input) {
                    output.insert(TaintValue {
                        variable: name.clone(),
                        source: taint.source,
                        sanitized: false,
                        taint_condition: taint.taint_condition.clone(),
                        sanitized_condition: taint.sanitized_condition.clone(),
                    });
                }
            }
        }
    }
}

impl TransferFunction<TaintValue> for AstBasedTaintTransferFunction {
    fn transfer(
        &self,
        cfg: &ControlFlowGraph,
        ast: &AstNode,
        node_idx: CfgGraphIndex,
        input: &HashSet<TaintValue>,
    ) -> HashSet<TaintValue> {
        let mut output = input.clone();

        // Get the CFG node
        let cfg_node = match cfg.get_node(node_idx) {
            Some(n) => n,
            None => return output,
        };

        // Find the corresponding AST node
        let ast_node = match Self::find_ast_node(ast, cfg_node.ast_node_id) {
            Some(n) => n,
            None => return output, // No AST node found, return unchanged
        };

        // Now analyze based on the actual AST node kind
        match &ast_node.kind {
            AstNodeKind::AssignmentExpression { .. } => {
                self.handle_assignment(ast_node, &mut output, input);
            }

            AstNodeKind::CallExpression { .. } => {
                self.handle_call(ast_node, &mut output, input);
            }

            AstNodeKind::VariableDeclaration { .. } => {
                self.handle_variable_declaration(ast_node, &mut output, input);
            }

            // For other node types, taint propagates through unchanged
            _ => {}
        }

        output
    }

    fn initial_state(&self) -> HashSet<TaintValue> {
        HashSet::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gittera_parser::ast::{Location, Span};

    fn create_test_location() -> Location {
        Location {
            file_path: "test.rs".to_string(),
            span: Span {
                start_line: 1,
                start_column: 1,
                end_line: 1,
                end_column: 10,
                start_byte: 0,
                end_byte: 10,
            },
        }
    }

    #[test]
    fn test_evaluate_expression_identifier_tainted() {
        let transfer = AstBasedTaintTransferFunction::new(Vec::new(), HashSet::new());

        let mut taint_set = HashSet::new();
        taint_set.insert(TaintValue::new("x".to_string(), TaintSourceKind::UserInput));

        let node = AstNode::new(
            1,
            AstNodeKind::Identifier {
                name: "x".to_string(),
            },
            create_test_location(),
            "x".to_string(),
        );

        let result = transfer.evaluate_expression(&node, &taint_set);
        assert!(result.is_some());
        assert_eq!(result.unwrap().variable, "x");
    }

    #[test]
    fn test_evaluate_expression_identifier_clean() {
        let transfer = AstBasedTaintTransferFunction::new(Vec::new(), HashSet::new());

        let taint_set = HashSet::new();

        let node = AstNode::new(
            1,
            AstNodeKind::Identifier {
                name: "x".to_string(),
            },
            create_test_location(),
            "x".to_string(),
        );

        let result = transfer.evaluate_expression(&node, &taint_set);
        assert!(result.is_none());
    }

    #[test]
    fn test_evaluate_expression_literal() {
        let transfer = AstBasedTaintTransferFunction::new(Vec::new(), HashSet::new());

        let taint_set = HashSet::new();

        let node = AstNode::new(
            1,
            AstNodeKind::Literal {
                value: LiteralValue::String("hello".to_string()),
            },
            create_test_location(),
            "\"hello\"".to_string(),
        );

        let result = transfer.evaluate_expression(&node, &taint_set);
        assert!(result.is_none());
    }

    #[test]
    fn test_evaluate_expression_binary_propagates_taint() {
        let transfer = AstBasedTaintTransferFunction::new(Vec::new(), HashSet::new());

        let mut taint_set = HashSet::new();
        taint_set.insert(TaintValue::new("x".to_string(), TaintSourceKind::UserInput));

        // Create: x + y (where x is tainted)
        let mut binary = AstNode::new(
            1,
            AstNodeKind::BinaryExpression {
                operator: "+".to_string(),
            },
            create_test_location(),
            "x + y".to_string(),
        );

        binary.add_child(AstNode::new(
            2,
            AstNodeKind::Identifier {
                name: "x".to_string(),
            },
            create_test_location(),
            "x".to_string(),
        ));

        binary.add_child(AstNode::new(
            3,
            AstNodeKind::Identifier {
                name: "y".to_string(),
            },
            create_test_location(),
            "y".to_string(),
        ));

        let result = transfer.evaluate_expression(&binary, &taint_set);
        assert!(result.is_some());
        assert_eq!(result.unwrap().source, TaintSourceKind::UserInput);
    }

    #[test]
    fn test_extract_lvalues_simple() {
        let transfer = AstBasedTaintTransferFunction::new(Vec::new(), HashSet::new());

        let node = AstNode::new(
            1,
            AstNodeKind::Identifier {
                name: "x".to_string(),
            },
            create_test_location(),
            "x".to_string(),
        );

        let result = transfer.extract_lvalues(&node);
        assert_eq!(result, vec!["x".to_string()]);
    }

    #[test]
    fn test_is_taint_source() {
        let sources = vec![TaintSource {
            name: "input".to_string(),
            kind: TaintSourceKind::UserInput,
            node_id: 0,
        }];

        let transfer = AstBasedTaintTransferFunction::new(sources, HashSet::new());

        assert!(transfer.is_taint_source("getUserInput").is_some());
        assert!(transfer.is_taint_source("input").is_some());
        assert!(transfer.is_taint_source("safeFunction").is_none());
    }

    #[test]
    fn test_is_sanitizer() {
        let mut sanitizers = HashSet::new();
        sanitizers.insert("escape".to_string());
        sanitizers.insert("sanitize".to_string());

        let transfer = AstBasedTaintTransferFunction::new(Vec::new(), sanitizers);

        assert!(transfer.is_sanitizer("escape"));
        assert!(transfer.is_sanitizer("escapeHtml"));
        assert!(transfer.is_sanitizer("sanitize"));
        assert!(!transfer.is_sanitizer("execute"));
    }
}
