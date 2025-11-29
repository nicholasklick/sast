//! Data flow analysis framework

use crate::cfg::{ControlFlowGraph, CfgGraphIndex};
use gittera_parser::ast::AstNode;
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Debug;
use std::hash::Hash;

pub enum DataFlowDirection {
    Forward,
    Backward,
}

/// Transfer function for data flow analysis
///
/// The lifetime parameter 'a represents the lifetime of the CFG and AST being analyzed.
/// This allows the transfer function to work with references instead of requiring ownership.
pub trait TransferFunction<T>: Send + Sync
where
    T: Clone + Eq + Hash + Debug,
{
    /// Apply the transfer function to a CFG node
    ///
    /// # Parameters
    /// - `cfg`: Reference to the control flow graph
    /// - `ast`: Reference to the full AST for deep analysis
    /// - `node`: Index of the CFG node being analyzed
    /// - `input`: The input dataflow state (taint set, reaching definitions, etc.)
    ///
    /// # Returns
    /// The output dataflow state after applying the transfer function
    fn transfer(
        &self,
        cfg: &ControlFlowGraph,
        ast: &AstNode,
        node: CfgGraphIndex,
        input: &HashSet<T>
    ) -> HashSet<T>;

    /// Get the initial state
    fn initial_state(&self) -> HashSet<T>;
}

/// Generic data flow analysis engine
pub struct DataFlowAnalysis<T>
where
    T: Clone + Eq + Hash + Debug,
{
    direction: DataFlowDirection,
    transfer_fn: Box<dyn TransferFunction<T>>,
}

impl<T> DataFlowAnalysis<T>
where
    T: Clone + Eq + Hash + Debug,
{
    pub fn new(direction: DataFlowDirection, transfer_fn: Box<dyn TransferFunction<T>>) -> Self {
        Self {
            direction,
            transfer_fn,
        }
    }

    /// Run the data flow analysis on a CFG
    pub fn analyze(&self, cfg: &ControlFlowGraph, ast: &AstNode) -> DataFlowResult<T> {
        let mut result = DataFlowResult::new();
        let mut worklist = VecDeque::new();

        // Initialize worklist
        match self.direction {
            DataFlowDirection::Forward => {
                worklist.push_back(cfg.entry);
                result.set_in(cfg.entry, self.transfer_fn.initial_state());
            }
            DataFlowDirection::Backward => {
                worklist.push_back(cfg.exit);
                result.set_out(cfg.exit, self.transfer_fn.initial_state());
            }
        }

        // Iterative fixed-point computation
        while let Some(node) = worklist.pop_front() {
            let changed = match self.direction {
                DataFlowDirection::Forward => self.analyze_forward(cfg, ast, &mut result, node),
                DataFlowDirection::Backward => self.analyze_backward(cfg, ast, &mut result, node),
            };

            if changed {
                // Add successors/predecessors to worklist
                let neighbors = match self.direction {
                    DataFlowDirection::Forward => cfg.successors(node),
                    DataFlowDirection::Backward => cfg.predecessors(node),
                };

                for neighbor in neighbors {
                    if !worklist.contains(&neighbor) {
                        worklist.push_back(neighbor);
                    }
                }
            }
        }

        result
    }

    fn analyze_forward(
        &self,
        cfg: &ControlFlowGraph,
        ast: &AstNode,
        result: &mut DataFlowResult<T>,
        node: CfgGraphIndex,
    ) -> bool {
        // Merge inputs from predecessors
        let predecessors = cfg.predecessors(node);
        let mut merged = HashSet::new();

        for pred in predecessors {
            if let Some(pred_out) = result.get_out(pred) {
                merged.extend(pred_out.iter().cloned());
            }
        }

        result.set_in(node, merged.clone());

        // Apply transfer function
        let new_out = self.transfer_fn.transfer(cfg, ast, node, &merged);

        // Check if output changed
        let changed = match result.get_out(node) {
            Some(old_out) => old_out != &new_out,
            None => true,
        };

        result.set_out(node, new_out);
        changed
    }

    fn analyze_backward(
        &self,
        cfg: &ControlFlowGraph,
        ast: &AstNode,
        result: &mut DataFlowResult<T>,
        node: CfgGraphIndex,
    ) -> bool {
        // Merge inputs from successors
        let successors = cfg.successors(node);
        let mut merged = HashSet::new();

        for succ in successors {
            if let Some(succ_in) = result.get_in(succ) {
                merged.extend(succ_in.iter().cloned());
            }
        }

        result.set_out(node, merged.clone());

        // Apply transfer function
        let new_in = self.transfer_fn.transfer(cfg, ast, node, &merged);

        // Check if input changed
        let changed = match result.get_in(node) {
            Some(old_in) => old_in != &new_in,
            None => true,
        };

        result.set_in(node, new_in);
        changed
    }
}

/// Results of data flow analysis
pub struct DataFlowResult<T>
where
    T: Clone + Eq + Hash + Debug,
{
    pub in_sets: HashMap<CfgGraphIndex, HashSet<T>>,
    pub out_sets: HashMap<CfgGraphIndex, HashSet<T>>,
}

impl<T> DataFlowResult<T>
where
    T: Clone + Eq + Hash + Debug,
{
    pub fn new() -> Self {
        Self {
            in_sets: HashMap::new(),
            out_sets: HashMap::new(),
        }
    }

    pub fn get_in(&self, node: CfgGraphIndex) -> Option<&HashSet<T>> {
        self.in_sets.get(&node)
    }

    pub fn get_out(&self, node: CfgGraphIndex) -> Option<&HashSet<T>> {
        self.out_sets.get(&node)
    }

    pub fn set_in(&mut self, node: CfgGraphIndex, set: HashSet<T>) {
        self.in_sets.insert(node, set);
    }

    pub fn set_out(&mut self, node: CfgGraphIndex, set: HashSet<T>) {
        self.out_sets.insert(node, set);
    }
}

impl<T> Default for DataFlowResult<T>
where
    T: Clone + Eq + Hash + Debug,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gittera_parser::ast::AstNode;

    struct DummyTransfer;

    impl TransferFunction<String> for DummyTransfer {
        fn transfer(
            &self,
            _cfg: &ControlFlowGraph,
            _ast: &AstNode,
            _node: CfgGraphIndex,
            input: &HashSet<String>
        ) -> HashSet<String> {
            input.clone()
        }

        fn initial_state(&self) -> HashSet<String> {
            HashSet::new()
        }
    }

    #[test]
    fn test_dataflow_result() {
        let result = DataFlowResult::<String>::new();
        assert_eq!(result.in_sets.len(), 0);
    }
}
