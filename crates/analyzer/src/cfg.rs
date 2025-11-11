//! Control Flow Graph (CFG) construction and analysis

use kodecd_parser::ast::{AstNode, AstNodeKind, NodeId};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type CfgGraphIndex = NodeIndex<u32>;

/// A node in the control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgNode {
    pub id: NodeId,
    pub ast_node_id: NodeId,
    pub kind: CfgNodeKind,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgNodeKind {
    Entry,
    Exit,
    Statement,
    Expression,
    Branch,
    Loop,
    FunctionCall,
    Return,
}

/// An edge in the control flow graph
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CfgEdge {
    pub label: Option<String>,
    pub kind: CfgEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CfgEdgeKind {
    Normal,
    True,
    False,
    Exception,
}

/// Control Flow Graph representation
pub struct ControlFlowGraph {
    pub graph: DiGraph<CfgNode, CfgEdge>,
    pub entry: CfgGraphIndex,
    pub exit: CfgGraphIndex,
    pub node_map: HashMap<NodeId, CfgGraphIndex>,
}

impl ControlFlowGraph {
    pub fn new() -> Self {
        let mut graph = DiGraph::new();

        // Create entry and exit nodes
        let entry = graph.add_node(CfgNode {
            id: 0,
            ast_node_id: 0,
            kind: CfgNodeKind::Entry,
            label: "ENTRY".to_string(),
        });

        let exit = graph.add_node(CfgNode {
            id: 1,
            ast_node_id: 0,
            kind: CfgNodeKind::Exit,
            label: "EXIT".to_string(),
        });

        Self {
            graph,
            entry,
            exit,
            node_map: HashMap::new(),
        }
    }

    pub fn add_node(&mut self, node: CfgNode) -> CfgGraphIndex {
        let ast_node_id = node.ast_node_id;
        let index = self.graph.add_node(node);
        self.node_map.insert(ast_node_id, index);
        index
    }

    pub fn add_edge(&mut self, from: CfgGraphIndex, to: CfgGraphIndex, edge: CfgEdge) {
        self.graph.add_edge(from, to, edge);
    }

    pub fn get_node(&self, index: CfgGraphIndex) -> Option<&CfgNode> {
        self.graph.node_weight(index)
    }

    pub fn successors(&self, index: CfgGraphIndex) -> Vec<CfgGraphIndex> {
        self.graph
            .edges(index)
            .map(|e| e.target())
            .collect()
    }

    pub fn predecessors(&self, index: CfgGraphIndex) -> Vec<CfgGraphIndex> {
        self.graph
            .edges_directed(index, petgraph::Direction::Incoming)
            .map(|e| e.source())
            .collect()
    }

    /// Get all paths from entry to a specific node
    pub fn paths_to_node(&self, target: CfgGraphIndex) -> Vec<Vec<CfgGraphIndex>> {
        let mut paths = Vec::new();
        let mut current_path = Vec::new();
        self.find_paths_recursive(self.entry, target, &mut current_path, &mut paths);
        paths
    }

    fn find_paths_recursive(
        &self,
        current: CfgGraphIndex,
        target: CfgGraphIndex,
        current_path: &mut Vec<CfgGraphIndex>,
        all_paths: &mut Vec<Vec<CfgGraphIndex>>,
    ) {
        current_path.push(current);

        if current == target {
            all_paths.push(current_path.clone());
        } else {
            for successor in self.successors(current) {
                if !current_path.contains(&successor) {
                    self.find_paths_recursive(successor, target, current_path, all_paths);
                }
            }
        }

        current_path.pop();
    }
}

impl Default for ControlFlowGraph {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing CFGs from AST
pub struct CfgBuilder {
    cfg: ControlFlowGraph,
    next_id: NodeId,
}

impl CfgBuilder {
    pub fn new() -> Self {
        Self {
            cfg: ControlFlowGraph::new(),
            next_id: 2, // 0 and 1 are reserved for entry/exit
        }
    }

    pub fn build(mut self, ast: &AstNode) -> ControlFlowGraph {
        let last_node = self.build_node(ast, self.cfg.entry);

        // Connect the last node to exit
        if let Some(last) = last_node {
            self.cfg.add_edge(
                last,
                self.cfg.exit,
                CfgEdge {
                    label: None,
                    kind: CfgEdgeKind::Normal,
                },
            );
        }

        self.cfg
    }

    fn build_node(&mut self, ast: &AstNode, predecessor: CfgGraphIndex) -> Option<CfgGraphIndex> {
        match &ast.kind {
            AstNodeKind::Program | AstNodeKind::Block => {
                self.build_sequential(&ast.children, predecessor)
            }

            AstNodeKind::IfStatement => self.build_if_statement(ast, predecessor),

            AstNodeKind::WhileStatement | AstNodeKind::ForStatement => {
                self.build_loop(ast, predecessor)
            }

            AstNodeKind::ReturnStatement => self.build_return(ast, predecessor),

            AstNodeKind::CallExpression { callee, .. } => {
                let node = self.create_cfg_node(
                    ast.id,
                    CfgNodeKind::FunctionCall,
                    format!("call: {}", callee),
                );
                let index = self.cfg.add_node(node);

                self.cfg.add_edge(
                    predecessor,
                    index,
                    CfgEdge {
                        label: None,
                        kind: CfgEdgeKind::Normal,
                    },
                );

                Some(index)
            }

            _ => {
                let node = self.create_cfg_node(
                    ast.id,
                    CfgNodeKind::Statement,
                    format!("{}", ast.kind),
                );
                let index = self.cfg.add_node(node);

                self.cfg.add_edge(
                    predecessor,
                    index,
                    CfgEdge {
                        label: None,
                        kind: CfgEdgeKind::Normal,
                    },
                );

                Some(index)
            }
        }
    }

    fn build_sequential(
        &mut self,
        children: &[AstNode],
        predecessor: CfgGraphIndex,
    ) -> Option<CfgGraphIndex> {
        let mut last = Some(predecessor);

        for child in children {
            if let Some(pred) = last {
                last = self.build_node(child, pred);
            }
        }

        last
    }

    fn build_if_statement(&mut self, ast: &AstNode, predecessor: CfgGraphIndex) -> Option<CfgGraphIndex> {
        let branch_node = self.create_cfg_node(
            ast.id,
            CfgNodeKind::Branch,
            "if".to_string(),
        );
        let branch_index = self.cfg.add_node(branch_node);

        self.cfg.add_edge(
            predecessor,
            branch_index,
            CfgEdge {
                label: None,
                kind: CfgEdgeKind::Normal,
            },
        );

        // Find then and else branches
        let then_branch = ast.children.get(1);
        let else_branch = ast.children.get(2);

        // Build then branch
        let then_end = if let Some(then_ast) = then_branch {
            self.build_node(then_ast, branch_index)
        } else {
            Some(branch_index)
        };

        // Build else branch
        let else_end = if let Some(else_ast) = else_branch {
            self.build_node(else_ast, branch_index)
        } else {
            Some(branch_index)
        };

        // Create merge node
        let merge_node = self.create_cfg_node(
            self.next_id,
            CfgNodeKind::Statement,
            "merge".to_string(),
        );
        let merge_index = self.cfg.add_node(merge_node);

        // Connect branches to merge
        if let Some(then_end) = then_end {
            self.cfg.add_edge(
                then_end,
                merge_index,
                CfgEdge {
                    label: Some("then".to_string()),
                    kind: CfgEdgeKind::True,
                },
            );
        }

        if let Some(else_end) = else_end {
            self.cfg.add_edge(
                else_end,
                merge_index,
                CfgEdge {
                    label: Some("else".to_string()),
                    kind: CfgEdgeKind::False,
                },
            );
        }

        Some(merge_index)
    }

    fn build_loop(&mut self, ast: &AstNode, predecessor: CfgGraphIndex) -> Option<CfgGraphIndex> {
        let loop_header = self.create_cfg_node(
            ast.id,
            CfgNodeKind::Loop,
            "loop".to_string(),
        );
        let loop_index = self.cfg.add_node(loop_header);

        self.cfg.add_edge(
            predecessor,
            loop_index,
            CfgEdge {
                label: None,
                kind: CfgEdgeKind::Normal,
            },
        );

        // Build loop body
        if let Some(body) = ast.children.last() {
            if let Some(body_end) = self.build_node(body, loop_index) {
                // Back edge to loop header
                self.cfg.add_edge(
                    body_end,
                    loop_index,
                    CfgEdge {
                        label: Some("continue".to_string()),
                        kind: CfgEdgeKind::True,
                    },
                );
            }
        }

        Some(loop_index)
    }

    fn build_return(&mut self, ast: &AstNode, predecessor: CfgGraphIndex) -> Option<CfgGraphIndex> {
        let return_node = self.create_cfg_node(
            ast.id,
            CfgNodeKind::Return,
            "return".to_string(),
        );
        let return_index = self.cfg.add_node(return_node);

        self.cfg.add_edge(
            predecessor,
            return_index,
            CfgEdge {
                label: None,
                kind: CfgEdgeKind::Normal,
            },
        );

        // Return connects directly to exit
        self.cfg.add_edge(
            return_index,
            self.cfg.exit,
            CfgEdge {
                label: None,
                kind: CfgEdgeKind::Normal,
            },
        );

        None // No successor after return
    }

    fn create_cfg_node(&mut self, ast_node_id: NodeId, kind: CfgNodeKind, label: String) -> CfgNode {
        let id = self.next_id;
        self.next_id += 1;

        CfgNode {
            id,
            ast_node_id,
            kind,
            label,
        }
    }
}

impl Default for CfgBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_creation() {
        let cfg = ControlFlowGraph::new();
        assert_eq!(cfg.graph.node_count(), 2); // Entry and exit
    }
}
