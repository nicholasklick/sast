//! Query execution engine

use crate::ast::*;
use kodecd_analyzer::cfg::ControlFlowGraph;
use kodecd_analyzer::taint::TaintAnalysisResult;
use kodecd_parser::ast::{AstNode, AstNodeKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryResult {
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file_path: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
    pub severity: String,
    pub code_snippet: String,
}

pub struct QueryExecutor;

impl QueryExecutor {
    pub fn execute(query: &Query, ast: &AstNode, _cfg: &ControlFlowGraph) -> QueryResult {
        let mut findings = Vec::new();

        // Simple execution - find nodes matching the query
        Self::execute_on_node(query, ast, &mut findings);

        QueryResult { findings }
    }

    fn execute_on_node(query: &Query, node: &AstNode, findings: &mut Vec<Finding>) {
        // Check if node matches the FROM clause
        if Self::matches_entity(&query.from.entity, &node.kind) {
            // Check WHERE clause if present
            let matches = if let Some(ref where_clause) = query.where_clause {
                Self::evaluate_where(where_clause, node)
            } else {
                true
            };

            if matches {
                findings.push(Finding {
                    file_path: node.location.file_path.clone(),
                    line: node.location.span.start_line,
                    column: node.location.span.start_column,
                    message: format!("Found: {}", node.kind),
                    severity: "Medium".to_string(),
                    code_snippet: node.text.lines().next().unwrap_or("").to_string(),
                });
            }
        }

        // Recurse into children
        for child in &node.children {
            Self::execute_on_node(query, child, findings);
        }
    }

    fn matches_entity(entity: &EntityType, kind: &AstNodeKind) -> bool {
        match (entity, kind) {
            (EntityType::MethodCall, AstNodeKind::CallExpression { .. }) => true,
            (EntityType::FunctionDeclaration, AstNodeKind::FunctionDeclaration { .. }) => true,
            (EntityType::VariableDeclaration, AstNodeKind::VariableDeclaration { .. }) => true,
            (EntityType::AnyNode, _) => true,
            _ => false,
        }
    }

    fn evaluate_where(_where_clause: &WhereClause, _node: &AstNode) -> bool {
        // Simplified - always returns true for now
        true
    }
}
