//! Static Single Assignment (SSA) form construction and analysis
//!
//! SSA form is an intermediate representation where each variable is assigned
//! exactly once. This enables more precise dataflow analysis because we can
//! track exactly which definition of a variable flows to which use.
//!
//! ## Key Concepts
//!
//! - **SSA Variable**: A versioned variable (e.g., x_1, x_2, x_3)
//! - **Phi Node**: Merges multiple definitions at control flow join points
//! - **Definition**: A single assignment to an SSA variable
//! - **Use**: A reference to a specific SSA variable version
//!
//! ## Example
//!
//! ```text
//! Original code:
//!   x = source();
//!   y = x;
//!   x = "safe";
//!   sink(y);
//!
//! SSA form:
//!   x_1 = source();
//!   y_1 = x_1;
//!   x_2 = "safe";
//!   sink(y_1);  // y_1 is tainted from x_1, x_2 is clean
//! ```

use crate::cfg::{CfgGraphIndex, ControlFlowGraph};
use gittera_parser::ast::{AstNode, AstNodeKind, NodeId};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

/// A versioned SSA variable
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SsaVariable {
    /// Original variable name
    pub name: String,
    /// SSA version number (0-indexed)
    pub version: u32,
}

impl SsaVariable {
    pub fn new(name: String, version: u32) -> Self {
        Self { name, version }
    }

    /// Get the display name (e.g., "x_1")
    pub fn display_name(&self) -> String {
        format!("{}_{}", self.name, self.version)
    }
}

impl std::fmt::Display for SsaVariable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}", self.name, self.version)
    }
}

/// A phi node that merges multiple definitions at a control flow join point
#[derive(Debug, Clone)]
pub struct PhiNode {
    /// The result variable (new SSA version)
    pub result: SsaVariable,
    /// The incoming values from different predecessors
    /// Maps predecessor CFG node index (as usize) to the SSA variable from that path
    pub operands: HashMap<usize, SsaVariable>,
    /// The CFG node where this phi is placed (as usize for serialization)
    pub cfg_node_idx: usize,
}

impl PhiNode {
    pub fn new(result: SsaVariable, cfg_node: CfgGraphIndex) -> Self {
        Self {
            result,
            operands: HashMap::new(),
            cfg_node_idx: cfg_node.index(),
        }
    }

    pub fn add_operand(&mut self, predecessor: CfgGraphIndex, var: SsaVariable) {
        self.operands.insert(predecessor.index(), var);
    }
}

/// Definition site for an SSA variable
#[derive(Debug, Clone)]
pub struct SsaDefinition {
    /// The defined variable
    pub variable: SsaVariable,
    /// The CFG node index where definition occurs
    pub cfg_node_idx: usize,
    /// The AST node ID of the assignment
    pub ast_node_id: NodeId,
    /// The kind of definition
    pub kind: SsaDefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SsaDefKind {
    /// Regular assignment
    Assignment,
    /// Phi node at merge point
    Phi,
    /// Function parameter
    Parameter,
    /// Source of taint (e.g., user input)
    TaintSource,
}

/// Use site for an SSA variable
#[derive(Debug, Clone)]
pub struct SsaUse {
    /// The used variable
    pub variable: SsaVariable,
    /// The CFG node index where use occurs
    pub cfg_node_idx: usize,
    /// The AST node ID of the use
    pub ast_node_id: NodeId,
}

/// SSA form representation for a function/procedure
#[derive(Debug, Clone)]
pub struct SsaForm {
    /// Map from original variable name to current version counter
    version_counters: HashMap<String, u32>,
    /// All SSA definitions
    pub definitions: Vec<SsaDefinition>,
    /// All SSA uses
    pub uses: Vec<SsaUse>,
    /// Phi nodes at each CFG node (keyed by node index)
    pub phi_nodes: HashMap<usize, Vec<PhiNode>>,
    /// Map from CFG node to definitions at that node
    pub defs_at_node: HashMap<usize, Vec<SsaVariable>>,
    /// Map from CFG node to uses at that node
    pub uses_at_node: HashMap<usize, Vec<SsaVariable>>,
    /// Reaching definitions: for each CFG node and variable, which SSA version reaches it
    pub reaching_defs: HashMap<(usize, String), SsaVariable>,
    /// Dominance frontiers (needed for phi node placement)
    dominance_frontiers: HashMap<usize, HashSet<usize>>,
    /// Immediate dominator for each node (as index)
    idom: HashMap<usize, usize>,
}

impl SsaForm {
    pub fn new() -> Self {
        Self {
            version_counters: HashMap::new(),
            definitions: Vec::new(),
            uses: Vec::new(),
            phi_nodes: HashMap::new(),
            defs_at_node: HashMap::new(),
            uses_at_node: HashMap::new(),
            reaching_defs: HashMap::new(),
            dominance_frontiers: HashMap::new(),
            idom: HashMap::new(),
        }
    }

    /// Get the next version number for a variable
    fn next_version(&mut self, name: &str) -> u32 {
        let counter = self.version_counters.entry(name.to_string()).or_insert(0);
        let version = *counter;
        *counter += 1;
        version
    }

    /// Get the current version for a variable (for uses)
    pub fn current_version(&self, name: &str) -> Option<u32> {
        self.version_counters.get(name).map(|v| v.saturating_sub(1))
    }

    /// Create a new definition
    pub fn define(
        &mut self,
        name: &str,
        cfg_node: CfgGraphIndex,
        ast_node_id: NodeId,
        kind: SsaDefKind,
    ) -> SsaVariable {
        let version = self.next_version(name);
        let var = SsaVariable::new(name.to_string(), version);

        let def = SsaDefinition {
            variable: var.clone(),
            cfg_node_idx: cfg_node.index(),
            ast_node_id,
            kind,
        };

        self.definitions.push(def);
        self.defs_at_node
            .entry(cfg_node.index())
            .or_default()
            .push(var.clone());

        var
    }

    /// Record a use of a variable
    pub fn use_var(
        &mut self,
        name: &str,
        cfg_node: CfgGraphIndex,
        ast_node_id: NodeId,
    ) -> Option<SsaVariable> {
        // Get the reaching definition for this variable at this node
        if let Some(var) = self.reaching_defs.get(&(cfg_node.index(), name.to_string())).cloned() {
            let use_site = SsaUse {
                variable: var.clone(),
                cfg_node_idx: cfg_node.index(),
                ast_node_id,
            };

            self.uses.push(use_site);
            self.uses_at_node
                .entry(cfg_node.index())
                .or_default()
                .push(var.clone());

            Some(var)
        } else {
            None
        }
    }

    /// Add a phi node at a CFG node
    pub fn add_phi_node(&mut self, cfg_node: CfgGraphIndex, var_name: &str) -> SsaVariable {
        let result_var = self.define(var_name, cfg_node, 0, SsaDefKind::Phi);
        let phi = PhiNode::new(result_var.clone(), cfg_node);

        self.phi_nodes
            .entry(cfg_node.index())
            .or_default()
            .push(phi);

        result_var
    }

    /// Get all definitions of a variable (all versions)
    pub fn get_definitions(&self, name: &str) -> Vec<&SsaDefinition> {
        self.definitions
            .iter()
            .filter(|d| d.variable.name == name)
            .collect()
    }

    /// Get the definition for a specific SSA variable
    pub fn get_definition(&self, var: &SsaVariable) -> Option<&SsaDefinition> {
        self.definitions.iter().find(|d| d.variable == *var)
    }

    /// Get all uses of a specific SSA variable
    pub fn get_uses(&self, var: &SsaVariable) -> Vec<&SsaUse> {
        self.uses.iter().filter(|u| u.variable == *var).collect()
    }
}

impl Default for SsaForm {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for constructing SSA form from CFG
pub struct SsaBuilder<'a> {
    cfg: &'a ControlFlowGraph,
    ssa: SsaForm,
    /// Variables defined in each CFG block (for phi placement)
    block_defs: HashMap<usize, HashSet<String>>,
    /// Stack of definitions for each variable (for renaming)
    def_stacks: HashMap<String, Vec<SsaVariable>>,
}

impl<'a> SsaBuilder<'a> {
    pub fn new(cfg: &'a ControlFlowGraph) -> Self {
        Self {
            cfg,
            ssa: SsaForm::new(),
            block_defs: HashMap::new(),
            def_stacks: HashMap::new(),
        }
    }

    /// Build SSA form from CFG and AST
    pub fn build(mut self, ast: &AstNode) -> SsaForm {
        // Step 1: Compute dominance information
        self.compute_dominance();

        // Step 2: Find all variable definitions in each block
        self.collect_definitions(ast);

        // Step 3: Place phi nodes using dominance frontiers
        self.place_phi_nodes();

        // Step 4: Rename variables (assign SSA versions)
        self.rename_variables(self.cfg.entry);

        self.ssa
    }

    /// Compute dominance frontiers using the Lengauer-Tarjan algorithm (simplified)
    fn compute_dominance(&mut self) {
        // Simple iterative dominator computation
        let nodes: Vec<CfgGraphIndex> = self.cfg.graph.node_indices().collect();
        let node_indices: Vec<usize> = nodes.iter().map(|n| n.index()).collect();

        // Initialize: entry dominates only itself
        let mut doms: HashMap<usize, HashSet<usize>> = HashMap::new();
        for &idx in &node_indices {
            if idx == self.cfg.entry.index() {
                let mut s = HashSet::new();
                s.insert(idx);
                doms.insert(idx, s);
            } else {
                doms.insert(idx, node_indices.iter().cloned().collect());
            }
        }

        // Iterate until fixed point
        let mut changed = true;
        while changed {
            changed = false;
            for &node in &nodes {
                let node_idx = node.index();
                if node_idx == self.cfg.entry.index() {
                    continue;
                }

                let preds = self.cfg.predecessors(node);
                if preds.is_empty() {
                    continue;
                }

                // Dom(n) = {n} ∪ (∩ Dom(p) for all predecessors p)
                let mut new_doms: Option<HashSet<usize>> = None;
                for pred in &preds {
                    let pred_idx = pred.index();
                    if let Some(pred_doms) = doms.get(&pred_idx) {
                        new_doms = Some(match new_doms {
                            None => pred_doms.clone(),
                            Some(d) => d.intersection(pred_doms).cloned().collect(),
                        });
                    }
                }

                if let Some(mut d) = new_doms {
                    d.insert(node_idx);
                    if d != *doms.get(&node_idx).unwrap_or(&HashSet::new()) {
                        doms.insert(node_idx, d);
                        changed = true;
                    }
                }
            }
        }

        // Compute immediate dominators
        for &node in &nodes {
            let node_idx = node.index();
            if node_idx == self.cfg.entry.index() {
                continue;
            }

            if let Some(node_doms) = doms.get(&node_idx) {
                // idom is the dominator closest to node (excluding node itself)
                let mut candidates: Vec<_> = node_doms.iter()
                    .filter(|&&d| d != node_idx)
                    .cloned()
                    .collect();

                // idom is the one dominated by all others
                for &d in node_doms {
                    if d == node_idx {
                        continue;
                    }
                    candidates.retain(|&c| c == d || !doms.get(&d).map_or(false, |dd| dd.contains(&c)));
                }

                if let Some(&idom) = candidates.last() {
                    self.ssa.idom.insert(node_idx, idom);
                }
            }
        }

        // Compute dominance frontiers
        for &node in &nodes {
            let node_idx = node.index();
            let preds = self.cfg.predecessors(node);
            if preds.len() >= 2 {
                // This is a join node
                for pred in preds {
                    let mut runner = pred.index();
                    let idom_of_node = self.ssa.idom.get(&node_idx).copied().unwrap_or(self.cfg.entry.index());
                    while runner != idom_of_node {
                        self.ssa.dominance_frontiers
                            .entry(runner)
                            .or_default()
                            .insert(node_idx);

                        if let Some(&idom) = self.ssa.idom.get(&runner) {
                            runner = idom;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Collect all variable definitions from AST
    fn collect_definitions(&mut self, ast: &AstNode) {
        self.collect_definitions_recursive(ast, self.cfg.entry.index());
    }

    fn collect_definitions_recursive(&mut self, node: &AstNode, cfg_node_idx: usize) {
        match &node.kind {
            AstNodeKind::VariableDeclaration { name, .. } => {
                self.block_defs
                    .entry(cfg_node_idx)
                    .or_default()
                    .insert(name.clone());
            }
            AstNodeKind::AssignmentExpression { .. } => {
                // For assignment, the target is typically the first child
                if let Some(target_child) = node.children.first() {
                    if let Some(name) = Self::extract_variable_name(target_child) {
                        self.block_defs
                            .entry(cfg_node_idx)
                            .or_default()
                            .insert(name);
                    }
                }
            }
            _ => {}
        }

        // Map AST nodes to CFG nodes based on node_map
        let next_cfg = self.cfg.node_map.get(&node.id).map_or(cfg_node_idx, |n| n.index());

        for child in &node.children {
            self.collect_definitions_recursive(child, next_cfg);
        }
    }

    /// Extract variable name from an AST node (handles Identifier, etc.)
    fn extract_variable_name(node: &AstNode) -> Option<String> {
        match &node.kind {
            AstNodeKind::Identifier { name } => Some(name.clone()),
            AstNodeKind::VariableDeclaration { name, .. } => Some(name.clone()),
            _ => None,
        }
    }

    /// Place phi nodes at dominance frontiers
    fn place_phi_nodes(&mut self) {
        // For each variable that is defined
        let all_vars: HashSet<String> = self.block_defs
            .values()
            .flat_map(|s| s.iter().cloned())
            .collect();

        for var in all_vars {
            // Blocks where var is defined
            let def_blocks: HashSet<usize> = self.block_defs
                .iter()
                .filter(|(_, vars)| vars.contains(&var))
                .map(|(&node, _)| node)
                .collect();

            // Worklist algorithm for phi placement
            let mut worklist: VecDeque<usize> = def_blocks.iter().cloned().collect();
            let mut phi_placed: HashSet<usize> = HashSet::new();
            let mut processed: HashSet<usize> = HashSet::new();

            // Clone dominance frontiers to avoid borrow issues
            let dominance_frontiers = self.ssa.dominance_frontiers.clone();

            while let Some(block) = worklist.pop_front() {
                if let Some(df) = dominance_frontiers.get(&block) {
                    for &frontier_node in df {
                        if !phi_placed.contains(&frontier_node) {
                            // Place phi node here
                            self.ssa.add_phi_node(CfgGraphIndex::new(frontier_node), &var);
                            phi_placed.insert(frontier_node);

                            if !processed.contains(&frontier_node) {
                                worklist.push_back(frontier_node);
                            }
                        }
                    }
                }
                processed.insert(block);
            }
        }
    }

    /// Rename variables by traversing CFG in dominator tree order
    fn rename_variables(&mut self, node: CfgGraphIndex) {
        let node_idx = node.index();

        // Process phi nodes first - each phi defines a new version
        if let Some(phis) = self.ssa.phi_nodes.get(&node_idx).cloned() {
            for phi in &phis {
                self.def_stacks
                    .entry(phi.result.name.clone())
                    .or_default()
                    .push(phi.result.clone());
            }
        }

        // Process definitions at this node
        if let Some(defs) = self.ssa.defs_at_node.get(&node_idx).cloned() {
            for def in defs {
                self.def_stacks
                    .entry(def.name.clone())
                    .or_default()
                    .push(def);
            }
        }

        // Update reaching definitions for this node
        for (name, stack) in &self.def_stacks {
            if let Some(var) = stack.last() {
                self.ssa.reaching_defs.insert((node_idx, name.clone()), var.clone());
            }
        }

        // Fill phi node operands in successors
        for succ in self.cfg.successors(node) {
            let succ_idx = succ.index();
            if let Some(phis) = self.ssa.phi_nodes.get_mut(&succ_idx) {
                for phi in phis {
                    if let Some(stack) = self.def_stacks.get(&phi.result.name) {
                        if let Some(var) = stack.last() {
                            phi.add_operand(node, var.clone());
                        }
                    }
                }
            }
        }

        // Recurse to dominated nodes
        let dominated: Vec<usize> = self.ssa.idom
            .iter()
            .filter(|(_, &idom)| idom == node_idx)
            .map(|(&n, _)| n)
            .collect();

        for child_idx in dominated {
            self.rename_variables(CfgGraphIndex::new(child_idx));
        }

        // Pop definitions from this node (restore stacks)
        if let Some(defs) = self.ssa.defs_at_node.get(&node_idx) {
            for def in defs {
                if let Some(stack) = self.def_stacks.get_mut(&def.name) {
                    stack.pop();
                }
            }
        }

        if let Some(phis) = self.ssa.phi_nodes.get(&node_idx) {
            for phi in phis {
                if let Some(stack) = self.def_stacks.get_mut(&phi.result.name) {
                    stack.pop();
                }
            }
        }
    }
}

/// SSA-based taint state (replaces HashSet<String>)
#[derive(Debug, Clone)]
pub struct SsaTaintState {
    /// Tainted SSA variables
    tainted: HashSet<SsaVariable>,
    /// SSA variables that have been sanitized for specific flow states
    sanitized_for: HashMap<SsaVariable, HashSet<crate::taint::FlowState>>,
}

impl SsaTaintState {
    pub fn new() -> Self {
        Self {
            tainted: HashSet::new(),
            sanitized_for: HashMap::new(),
        }
    }

    /// Mark an SSA variable as tainted
    pub fn add_taint(&mut self, var: SsaVariable) {
        self.tainted.insert(var);
    }

    /// Remove taint from an SSA variable
    pub fn remove_taint(&mut self, var: &SsaVariable) {
        self.tainted.remove(var);
        self.sanitized_for.remove(var);
    }

    /// Check if an SSA variable is tainted
    pub fn is_tainted(&self, var: &SsaVariable) -> bool {
        self.tainted.contains(var)
    }

    /// Check if any version of a variable is tainted
    pub fn is_var_tainted(&self, name: &str) -> bool {
        self.tainted.iter().any(|v| v.name == name)
    }

    /// Get the tainted versions of a variable
    pub fn get_tainted_versions(&self, name: &str) -> Vec<&SsaVariable> {
        self.tainted.iter().filter(|v| v.name == name).collect()
    }

    /// Mark an SSA variable as sanitized for a specific flow state
    pub fn add_sanitization(&mut self, var: SsaVariable, state: crate::taint::FlowState) {
        self.sanitized_for.entry(var).or_default().insert(state);
    }

    /// Check if an SSA variable is sanitized for a specific flow state
    pub fn is_sanitized_for(&self, var: &SsaVariable, state: &crate::taint::FlowState) -> bool {
        self.sanitized_for
            .get(var)
            .map_or(false, |states| states.contains(state))
    }

    /// Get all tainted variables
    pub fn get_tainted(&self) -> &HashSet<SsaVariable> {
        &self.tainted
    }

    /// Merge two taint states (for phi nodes)
    pub fn merge(&mut self, other: &SsaTaintState) {
        // Union of tainted variables
        self.tainted.extend(other.tainted.iter().cloned());

        // Intersection of sanitization (only keep if sanitized on all paths)
        let mut to_remove = Vec::new();
        for (var, states) in &self.sanitized_for {
            if let Some(other_states) = other.sanitized_for.get(var) {
                // Keep only states present in both
                let intersection: HashSet<_> = states.intersection(other_states).cloned().collect();
                if intersection.is_empty() {
                    to_remove.push(var.clone());
                }
            } else {
                to_remove.push(var.clone());
            }
        }
        for var in to_remove {
            self.sanitized_for.remove(&var);
        }
    }

    /// Convert from legacy tainted_vars (HashSet<String>) to SSA taint state
    /// This creates version 0 for each tainted variable (for migration)
    pub fn from_legacy(tainted_vars: &HashSet<String>) -> Self {
        let mut state = Self::new();
        for var in tainted_vars {
            state.add_taint(SsaVariable::new(var.clone(), 0));
        }
        state
    }

    /// Convert to legacy format (loses version info)
    pub fn to_legacy(&self) -> HashSet<String> {
        self.tainted.iter().map(|v| v.name.clone()).collect()
    }

    /// Propagate taint through a phi node
    /// Returns true if the phi result should be tainted
    ///
    /// A phi node result is tainted if ANY of its operands are tainted.
    /// This implements the conservative approach for control flow merges.
    pub fn propagate_phi_taint(&mut self, phi: &PhiNode) -> bool {
        let any_operand_tainted = phi.operands.values().any(|var| self.is_tainted(var));

        if any_operand_tainted {
            self.add_taint(phi.result.clone());
            true
        } else {
            false
        }
    }

    /// Propagate taint through all phi nodes at a CFG node
    pub fn propagate_all_phi_nodes(&mut self, ssa: &SsaForm, cfg_node_idx: usize) {
        if let Some(phi_nodes) = ssa.phi_nodes.get(&cfg_node_idx) {
            for phi in phi_nodes {
                self.propagate_phi_taint(phi);
            }
        }
    }

    /// Get taint status considering SSA versions
    /// Uses the reaching definition for the variable at the given CFG node
    pub fn is_var_tainted_at_node(&self, ssa: &SsaForm, var_name: &str, cfg_node_idx: usize) -> bool {
        if let Some(reaching_var) = ssa.reaching_defs.get(&(cfg_node_idx, var_name.to_string())) {
            self.is_tainted(reaching_var)
        } else {
            // Fall back to checking any version
            self.is_var_tainted(var_name)
        }
    }

    /// Handle assignment: kill old taint, propagate if RHS is tainted
    pub fn handle_assignment(
        &mut self,
        new_def: &SsaVariable,
        rhs_vars: &[SsaVariable],
    ) {
        // Check if any RHS variable is tainted
        let rhs_tainted = rhs_vars.iter().any(|v| self.is_tainted(v));

        if rhs_tainted {
            self.add_taint(new_def.clone());
        }
        // New definition doesn't carry old taints (strong update in SSA)
    }
}

impl Default for SsaTaintState {
    fn default() -> Self {
        Self::new()
    }
}

/// SSA-based taint analyzer that integrates with CFG traversal
pub struct SsaTaintAnalyzer {
    /// SSA form for the function being analyzed
    pub ssa: SsaForm,
    /// Current taint state
    pub state: SsaTaintState,
}

impl SsaTaintAnalyzer {
    pub fn new(ssa: SsaForm) -> Self {
        Self {
            ssa,
            state: SsaTaintState::new(),
        }
    }

    /// Mark a variable as tainted at a specific CFG node
    pub fn mark_tainted_at(&mut self, var_name: &str, cfg_node_idx: usize) {
        if let Some(var) = self.ssa.reaching_defs.get(&(cfg_node_idx, var_name.to_string())).cloned() {
            self.state.add_taint(var);
        } else {
            // No reaching def, create version 0
            self.state.add_taint(SsaVariable::new(var_name.to_string(), 0));
        }
    }

    /// Check if a variable is tainted at a specific CFG node
    pub fn is_tainted_at(&self, var_name: &str, cfg_node_idx: usize) -> bool {
        self.state.is_var_tainted_at_node(&self.ssa, var_name, cfg_node_idx)
    }

    /// Process phi nodes at a CFG node (call at control flow merge points)
    pub fn process_phi_nodes(&mut self, cfg_node_idx: usize) {
        self.state.propagate_all_phi_nodes(&self.ssa, cfg_node_idx);
    }

    /// Get the SSA variable for a name at a specific node (if defined)
    pub fn get_ssa_var(&self, var_name: &str, cfg_node_idx: usize) -> Option<SsaVariable> {
        self.ssa.reaching_defs.get(&(cfg_node_idx, var_name.to_string())).cloned()
    }

    /// Export current taint state to legacy format
    pub fn to_legacy_taint_set(&self) -> HashSet<String> {
        self.state.to_legacy()
    }

    /// Import taint state from legacy format
    pub fn from_legacy_taint_set(&mut self, legacy: &HashSet<String>) {
        self.state = SsaTaintState::from_legacy(legacy);
    }

    /// Get all tainted variable names (any version)
    pub fn tainted_var_names(&self) -> HashSet<String> {
        self.state.to_legacy()
    }

    /// Check if any version of a variable is tainted
    pub fn is_any_version_tainted(&self, var_name: &str) -> bool {
        self.state.is_var_tainted(var_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ssa_variable() {
        let var = SsaVariable::new("x".to_string(), 1);
        assert_eq!(var.display_name(), "x_1");
        assert_eq!(format!("{}", var), "x_1");
    }

    #[test]
    fn test_ssa_form_versioning() {
        let mut ssa = SsaForm::new();

        // First definition of x
        let x1 = ssa.define("x", CfgGraphIndex::new(0), 1, SsaDefKind::Assignment);
        assert_eq!(x1.version, 0);
        assert_eq!(x1.display_name(), "x_0");

        // Second definition of x
        let x2 = ssa.define("x", CfgGraphIndex::new(1), 2, SsaDefKind::Assignment);
        assert_eq!(x2.version, 1);
        assert_eq!(x2.display_name(), "x_1");

        // Definition of y
        let y1 = ssa.define("y", CfgGraphIndex::new(1), 3, SsaDefKind::Assignment);
        assert_eq!(y1.version, 0);
        assert_eq!(y1.display_name(), "y_0");
    }

    #[test]
    fn test_ssa_taint_state() {
        let mut state = SsaTaintState::new();
        let x1 = SsaVariable::new("x".to_string(), 1);
        let x2 = SsaVariable::new("x".to_string(), 2);

        state.add_taint(x1.clone());
        assert!(state.is_tainted(&x1));
        assert!(!state.is_tainted(&x2)); // Different version, not tainted

        // But is_var_tainted should return true
        assert!(state.is_var_tainted("x"));

        state.remove_taint(&x1);
        assert!(!state.is_tainted(&x1));
        assert!(!state.is_var_tainted("x"));
    }

    #[test]
    fn test_phi_node() {
        let result = SsaVariable::new("x".to_string(), 2);
        let mut phi = PhiNode::new(result.clone(), CfgGraphIndex::new(5));

        let x0 = SsaVariable::new("x".to_string(), 0);
        let x1 = SsaVariable::new("x".to_string(), 1);

        phi.add_operand(CfgGraphIndex::new(1), x0.clone());
        phi.add_operand(CfgGraphIndex::new(2), x1.clone());

        assert_eq!(phi.operands.len(), 2);
        assert_eq!(phi.operands.get(&1), Some(&x0));
        assert_eq!(phi.operands.get(&2), Some(&x1));
    }

    #[test]
    fn test_legacy_conversion() {
        let mut legacy = HashSet::new();
        legacy.insert("x".to_string());
        legacy.insert("y".to_string());

        let ssa_state = SsaTaintState::from_legacy(&legacy);
        assert!(ssa_state.is_var_tainted("x"));
        assert!(ssa_state.is_var_tainted("y"));
        assert!(!ssa_state.is_var_tainted("z"));

        let back_to_legacy = ssa_state.to_legacy();
        assert!(back_to_legacy.contains("x"));
        assert!(back_to_legacy.contains("y"));
    }

    #[test]
    fn test_phi_node_taint_propagation() {
        // Simulates:
        // if (cond) { x_0 = source(); } else { x_1 = safe(); }
        // At merge: x_2 = phi(x_0, x_1)
        // x_2 should be tainted because x_0 is tainted

        let mut state = SsaTaintState::new();
        let x0 = SsaVariable::new("x".to_string(), 0);
        let x1 = SsaVariable::new("x".to_string(), 1);
        let x2 = SsaVariable::new("x".to_string(), 2);

        // x_0 is tainted (from source)
        state.add_taint(x0.clone());

        // Create phi node: x_2 = phi(x_0, x_1)
        let mut phi = PhiNode::new(x2.clone(), CfgGraphIndex::new(5));
        phi.add_operand(CfgGraphIndex::new(1), x0.clone());
        phi.add_operand(CfgGraphIndex::new(2), x1.clone());

        // Propagate taint through phi node
        let result = state.propagate_phi_taint(&phi);
        assert!(result, "phi should propagate taint from x_0");
        assert!(state.is_tainted(&x2), "x_2 should be tainted after phi");
    }

    #[test]
    fn test_phi_node_no_taint() {
        // Simulates:
        // if (cond) { x_0 = safe1(); } else { x_1 = safe2(); }
        // At merge: x_2 = phi(x_0, x_1)
        // x_2 should NOT be tainted

        let mut state = SsaTaintState::new();
        let x0 = SsaVariable::new("x".to_string(), 0);
        let x1 = SsaVariable::new("x".to_string(), 1);
        let x2 = SsaVariable::new("x".to_string(), 2);

        // Neither x_0 nor x_1 is tainted

        // Create phi node: x_2 = phi(x_0, x_1)
        let mut phi = PhiNode::new(x2.clone(), CfgGraphIndex::new(5));
        phi.add_operand(CfgGraphIndex::new(1), x0);
        phi.add_operand(CfgGraphIndex::new(2), x1);

        // Propagate taint through phi node
        let result = state.propagate_phi_taint(&phi);
        assert!(!result, "phi should not propagate taint when no operands are tainted");
        assert!(!state.is_tainted(&x2), "x_2 should not be tainted");
    }

    #[test]
    fn test_assignment_strong_update() {
        // SSA enables strong updates:
        // x_0 = source();  // x_0 is tainted
        // x_1 = safe();    // x_1 is NOT tainted (strong update)
        // sink(x_1);       // Should NOT be flagged

        let mut state = SsaTaintState::new();
        let x0 = SsaVariable::new("x".to_string(), 0);
        let x1 = SsaVariable::new("x".to_string(), 1);

        // x_0 = source() makes x_0 tainted
        state.add_taint(x0.clone());
        assert!(state.is_tainted(&x0));

        // x_1 = safe() - new definition, RHS is not tainted
        let safe_var = SsaVariable::new("safe".to_string(), 0);
        state.handle_assignment(&x1, &[safe_var]);

        // x_1 should NOT be tainted (strong update)
        assert!(!state.is_tainted(&x1), "x_1 should not be tainted after assignment from safe");
        // x_0 is still tainted
        assert!(state.is_tainted(&x0), "x_0 should still be tainted");
    }

    #[test]
    fn test_assignment_taint_propagation() {
        // y_0 = x_0 where x_0 is tainted -> y_0 is tainted

        let mut state = SsaTaintState::new();
        let x0 = SsaVariable::new("x".to_string(), 0);
        let y0 = SsaVariable::new("y".to_string(), 0);

        // x_0 is tainted
        state.add_taint(x0.clone());

        // y_0 = x_0
        state.handle_assignment(&y0, &[x0]);

        assert!(state.is_tainted(&y0), "y_0 should be tainted from x_0");
    }

    #[test]
    fn test_taint_state_merge() {
        // Merge two states at control flow join
        let mut state1 = SsaTaintState::new();
        let mut state2 = SsaTaintState::new();

        let x0 = SsaVariable::new("x".to_string(), 0);
        let y0 = SsaVariable::new("y".to_string(), 0);
        let z0 = SsaVariable::new("z".to_string(), 0);

        // State 1: x is tainted
        state1.add_taint(x0.clone());
        // State 2: y is tainted
        state2.add_taint(y0.clone());

        // Merge: both x and y should be tainted
        state1.merge(&state2);
        assert!(state1.is_tainted(&x0), "x should be tainted after merge");
        assert!(state1.is_tainted(&y0), "y should be tainted after merge");
        assert!(!state1.is_tainted(&z0), "z should not be tainted");
    }
}
