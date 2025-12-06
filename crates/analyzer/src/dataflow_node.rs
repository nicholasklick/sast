//! Data Flow Node Abstraction
//!
//! This module provides a CodeQL-inspired node abstraction for data flow analysis.
//! Different node types distinguish different "views" of the same AST node,
//! enabling more precise tracking of data flow.
//!
//! Key concepts:
//! - ExprNode: An expression in the program
//! - ParameterNode: A function parameter (input to function)
//! - ArgumentNode: A call argument (data flowing into a call)
//! - ReturnNode: A return value (data flowing out of function)
//! - PostUpdateNode: Value after potential mutation (for strong updates)
//! - OutNode: Data flowing out of a call

use gittera_parser::ast::NodeId;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Position of an argument in a function call
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArgumentPosition {
    /// Positional argument at index
    Positional(usize),
    /// Named/keyword argument
    Named(String),
    /// The receiver object (this/self)
    This,
}

impl fmt::Display for ArgumentPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgumentPosition::Positional(i) => write!(f, "Argument[{}]", i),
            ArgumentPosition::Named(name) => write!(f, "Argument[{}]", name),
            ArgumentPosition::This => write!(f, "Argument[this]"),
        }
    }
}

/// Kind of return from a function
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ReturnKind {
    /// Normal return value
    Normal,
    /// Yielded value (generators)
    Yield,
    /// Thrown exception
    Exception,
}

impl fmt::Display for ReturnKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReturnKind::Normal => write!(f, "ReturnValue"),
            ReturnKind::Yield => write!(f, "YieldValue"),
            ReturnKind::Exception => write!(f, "ExceptionValue"),
        }
    }
}

/// A node in the data flow graph
///
/// This abstraction distinguishes different "views" of the same AST node,
/// enabling precise tracking of data flow semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataFlowNode {
    /// Expression node - represents an expression in the program
    ExprNode {
        node_id: NodeId,
        /// Optional type information for type-aware analysis
        type_name: Option<String>,
    },

    /// Parameter node - represents a function parameter (data flowing in)
    ParameterNode {
        /// The function containing this parameter
        func_id: NodeId,
        /// Position of the parameter
        position: usize,
        /// Parameter name
        name: String,
    },

    /// Argument node - represents a call argument (data flowing into a call)
    ArgumentNode {
        /// The call site
        call_id: NodeId,
        /// Position of the argument
        position: ArgumentPosition,
    },

    /// Return node - represents a function's return value (data flowing out)
    ReturnNode {
        /// The function
        func_id: NodeId,
        /// Kind of return
        kind: ReturnKind,
    },

    /// Post-update node - value AFTER potential mutation
    ///
    /// This is key for strong updates: when we write to x, we create a
    /// PostUpdateNode(x) that represents the new value, distinct from
    /// the pre-update value.
    PostUpdateNode {
        /// The node before the update
        pre_update_id: NodeId,
    },

    /// Out node - data flowing out of a call at the call site
    OutNode {
        /// The call site
        call_id: NodeId,
        /// What kind of data flows out
        return_kind: ReturnKind,
    },

    /// Synthetic node for connecting flows
    SyntheticNode {
        /// Unique identifier
        id: String,
    },
}

impl DataFlowNode {
    /// Create an expression node
    pub fn expr(node_id: NodeId) -> Self {
        DataFlowNode::ExprNode {
            node_id,
            type_name: None,
        }
    }

    /// Create an expression node with type
    pub fn expr_with_type(node_id: NodeId, type_name: String) -> Self {
        DataFlowNode::ExprNode {
            node_id,
            type_name: Some(type_name),
        }
    }

    /// Create a parameter node
    pub fn parameter(func_id: NodeId, position: usize, name: String) -> Self {
        DataFlowNode::ParameterNode {
            func_id,
            position,
            name,
        }
    }

    /// Create an argument node for positional argument
    pub fn argument(call_id: NodeId, position: usize) -> Self {
        DataFlowNode::ArgumentNode {
            call_id,
            position: ArgumentPosition::Positional(position),
        }
    }

    /// Create an argument node for this/self
    pub fn this_argument(call_id: NodeId) -> Self {
        DataFlowNode::ArgumentNode {
            call_id,
            position: ArgumentPosition::This,
        }
    }

    /// Create a return node
    pub fn return_value(func_id: NodeId) -> Self {
        DataFlowNode::ReturnNode {
            func_id,
            kind: ReturnKind::Normal,
        }
    }

    /// Create a post-update node (value after mutation)
    pub fn post_update(pre_update_id: NodeId) -> Self {
        DataFlowNode::PostUpdateNode { pre_update_id }
    }

    /// Create an out node for call return value
    pub fn call_out(call_id: NodeId) -> Self {
        DataFlowNode::OutNode {
            call_id,
            return_kind: ReturnKind::Normal,
        }
    }

    /// Get the AST node ID associated with this data flow node
    pub fn get_node_id(&self) -> Option<NodeId> {
        match self {
            DataFlowNode::ExprNode { node_id, .. } => Some(*node_id),
            DataFlowNode::ParameterNode { func_id, .. } => Some(*func_id),
            DataFlowNode::ArgumentNode { call_id, .. } => Some(*call_id),
            DataFlowNode::ReturnNode { func_id, .. } => Some(*func_id),
            DataFlowNode::PostUpdateNode { pre_update_id } => Some(*pre_update_id),
            DataFlowNode::OutNode { call_id, .. } => Some(*call_id),
            DataFlowNode::SyntheticNode { .. } => None,
        }
    }

    /// Check if this node represents data flowing into a call
    pub fn is_argument_node(&self) -> bool {
        matches!(self, DataFlowNode::ArgumentNode { .. })
    }

    /// Check if this node represents data flowing out of a call
    pub fn is_out_node(&self) -> bool {
        matches!(self, DataFlowNode::OutNode { .. })
    }

    /// Check if this is a post-update node (for strong updates)
    pub fn is_post_update(&self) -> bool {
        matches!(self, DataFlowNode::PostUpdateNode { .. })
    }

    /// Check if this is a parameter node
    pub fn is_parameter(&self) -> bool {
        matches!(self, DataFlowNode::ParameterNode { .. })
    }

    /// Check if this is a return node
    pub fn is_return(&self) -> bool {
        matches!(self, DataFlowNode::ReturnNode { .. })
    }
}

impl fmt::Display for DataFlowNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataFlowNode::ExprNode { node_id, type_name } => {
                if let Some(ty) = type_name {
                    write!(f, "Expr[{}:{}]", node_id, ty)
                } else {
                    write!(f, "Expr[{}]", node_id)
                }
            }
            DataFlowNode::ParameterNode { position, name, .. } => {
                write!(f, "Parameter[{}:{}]", position, name)
            }
            DataFlowNode::ArgumentNode { position, .. } => {
                write!(f, "{}", position)
            }
            DataFlowNode::ReturnNode { kind, .. } => {
                write!(f, "{}", kind)
            }
            DataFlowNode::PostUpdateNode { pre_update_id } => {
                write!(f, "PostUpdate[{}]", pre_update_id)
            }
            DataFlowNode::OutNode { return_kind, .. } => {
                write!(f, "Out[{}]", return_kind)
            }
            DataFlowNode::SyntheticNode { id } => {
                write!(f, "Synthetic[{}]", id)
            }
        }
    }
}

/// Represents a local flow step (within a single function)
#[derive(Debug, Clone)]
pub struct LocalFlowStep {
    /// Source node
    pub from: DataFlowNode,
    /// Target node
    pub to: DataFlowNode,
    /// Is this a value-preserving step (vs taint-propagating)?
    pub preserves_value: bool,
}

impl LocalFlowStep {
    pub fn new(from: DataFlowNode, to: DataFlowNode) -> Self {
        Self {
            from,
            to,
            preserves_value: true,
        }
    }

    pub fn taint_step(from: DataFlowNode, to: DataFlowNode) -> Self {
        Self {
            from,
            to,
            preserves_value: false,
        }
    }
}

/// Tracks which nodes are cleared (killed) at a given point
///
/// This is essential for strong updates - when a variable is reassigned,
/// the old taint is cleared.
#[derive(Debug, Clone, Default)]
pub struct ClearedNodes {
    /// Nodes whose content is cleared
    cleared: Vec<DataFlowNode>,
}

impl ClearedNodes {
    pub fn new() -> Self {
        Self { cleared: Vec::new() }
    }

    /// Mark a node as cleared (its previous value is killed)
    pub fn clear(&mut self, node: DataFlowNode) {
        self.cleared.push(node);
    }

    /// Check if a node is cleared at this point
    pub fn is_cleared(&self, node: &DataFlowNode) -> bool {
        self.cleared.contains(node)
    }

    /// Get all cleared nodes
    pub fn iter(&self) -> impl Iterator<Item = &DataFlowNode> {
        self.cleared.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expr_node() {
        let node = DataFlowNode::expr(42);
        assert_eq!(node.get_node_id(), Some(42));
        assert!(!node.is_argument_node());
        assert!(!node.is_post_update());
    }

    #[test]
    fn test_argument_positions() {
        let pos = ArgumentPosition::Positional(0);
        assert_eq!(pos.to_string(), "Argument[0]");

        let this = ArgumentPosition::This;
        assert_eq!(this.to_string(), "Argument[this]");
    }

    #[test]
    fn test_post_update_node() {
        let node = DataFlowNode::post_update(10);
        assert!(node.is_post_update());
        assert_eq!(node.get_node_id(), Some(10));
    }

    #[test]
    fn test_cleared_nodes() {
        let mut cleared = ClearedNodes::new();
        let node = DataFlowNode::expr(5);

        assert!(!cleared.is_cleared(&node));
        cleared.clear(node.clone());
        assert!(cleared.is_cleared(&node));
    }

    #[test]
    fn test_local_flow_step() {
        let from = DataFlowNode::expr(1);
        let to = DataFlowNode::expr(2);

        let step = LocalFlowStep::new(from.clone(), to.clone());
        assert!(step.preserves_value);

        let taint_step = LocalFlowStep::taint_step(from, to);
        assert!(!taint_step.preserves_value);
    }
}
