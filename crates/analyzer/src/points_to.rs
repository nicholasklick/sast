//! Points-to analysis for determining what memory locations pointers may reference
//!
//! This module implements an Andersen-style flow-insensitive points-to analysis.
//! It computes a conservative approximation of what each pointer variable may point to.
//!
//! ## Algorithm
//!
//! The analysis is based on constraint generation and solving:
//!
//! 1. **Address-of constraints**: `x = &y` → `y ∈ pts(x)`
//! 2. **Copy constraints**: `x = y` → `pts(y) ⊆ pts(x)`
//! 3. **Load constraints**: `x = *y` → `∀z ∈ pts(y), pts(z) ⊆ pts(x)`
//! 4. **Store constraints**: `*x = y` → `∀z ∈ pts(x), pts(y) ⊆ pts(z)`
//!
//! ## Type-Aware Analysis
//!
//! When type information is available (via `TypeContext`), the analysis uses it to:
//! - Skip aliasing between incompatible types (e.g., `number` and `object`)
//! - Filter out primitive types from points-to sets (primitives can't hold references)
//! - Reduce points-to set sizes by filtering incompatible types
//!
//! ## Use Cases
//!
//! - Alias analysis (do two pointers point to the same location?)
//! - Improving taint analysis precision
//! - Call graph refinement (resolving function pointers)
//! - Memory safety analysis
//!
//! ## Example
//!
//! ```rust
//! use gittera_analyzer::{PointsToAnalysisBuilder, AbstractLocation};
//! use gittera_parser::{AstNode, AstNodeKind, Location, Span};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a simple AST for demonstration
//! let program = AstNode {
//!     id: 0,
//!     kind: AstNodeKind::Program,
//!     location: Location {
//!         file_path: "test.js".to_string(),
//!         span: Span {
//!             start_line: 1, start_column: 0,
//!             end_line: 1, end_column: 10,
//!             start_byte: 0, end_byte: 10,
//!         },
//!     },
//!     children: Vec::new(),
//!     text: String::new(),
//! };
//!
//! // Build points-to analysis
//! let pts = PointsToAnalysisBuilder::new().build(&program);
//!
//! // Get analysis statistics
//! let stats = pts.stats();
//! assert!(stats.num_locations >= 0);
//!
//! // Check if variables may alias
//! let may_alias = pts.may_alias("ptr1", "ptr2");
//! assert!(!may_alias);  // Non-existent variables don't alias
//!
//! # Ok(())
//! # }
//! ```

use crate::type_system::TypeContext;
use gittera_parser::ast::{AstNode, AstNodeKind, NodeId};
use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};

/// Represents a memory location (allocation site)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AbstractLocation {
    /// Variable (identified by name)
    Variable(String),
    /// Heap allocation (identified by AST node where allocated)
    HeapAllocation(NodeId),
    /// Field access on an object (base location + field name)
    Field {
        base: Box<AbstractLocation>,
        field: String,
    },
    /// Array element access
    ArrayElement {
        base: Box<AbstractLocation>,
        index: Option<i64>, // None means unknown index
    },
    /// Return value of a function
    ReturnValue(String),
    /// Parameter of a function
    Parameter {
        function: String,
        index: usize,
    },
    /// Global/module level object
    Global(String),
    /// Unknown/external location
    Unknown,
}

impl AbstractLocation {
    /// Create a simple variable location
    pub fn var(name: impl Into<String>) -> Self {
        AbstractLocation::Variable(name.into())
    }

    /// Create a heap allocation location
    pub fn heap(node_id: NodeId) -> Self {
        AbstractLocation::HeapAllocation(node_id)
    }

    /// Create a field access location
    pub fn field(base: AbstractLocation, field: impl Into<String>) -> Self {
        AbstractLocation::Field {
            base: Box::new(base),
            field: field.into(),
        }
    }

    /// Create an array element location
    pub fn array_element(base: AbstractLocation, index: Option<i64>) -> Self {
        AbstractLocation::ArrayElement {
            base: Box::new(base),
            index,
        }
    }

    /// Get a string representation for debugging
    pub fn to_string(&self) -> String {
        match self {
            AbstractLocation::Variable(name) => name.clone(),
            AbstractLocation::HeapAllocation(id) => format!("heap#{}", id),
            AbstractLocation::Field { base, field } => {
                format!("{}.{}", base.to_string(), field)
            }
            AbstractLocation::ArrayElement { base, index } => {
                if let Some(idx) = index {
                    format!("{}[{}]", base.to_string(), idx)
                } else {
                    format!("{}[*]", base.to_string())
                }
            }
            AbstractLocation::ReturnValue(func) => format!("return#{}", func),
            AbstractLocation::Parameter { function, index } => {
                format!("{}#param{}", function, index)
            }
            AbstractLocation::Global(name) => format!("global#{}", name),
            AbstractLocation::Unknown => "unknown".to_string(),
        }
    }
}

/// Constraint types for points-to analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PointsToConstraint {
    /// Address-of: lhs = &rhs (rhs is added to points-to set of lhs)
    AddressOf {
        lhs: AbstractLocation,
        rhs: AbstractLocation,
    },
    /// Copy: lhs = rhs (points-to(rhs) ⊆ points-to(lhs))
    Copy {
        lhs: AbstractLocation,
        rhs: AbstractLocation,
    },
    /// Load: lhs = *rhs (for all p in points-to(rhs), points-to(p) ⊆ points-to(lhs))
    Load {
        lhs: AbstractLocation,
        rhs: AbstractLocation,
    },
    /// Store: *lhs = rhs (for all p in points-to(lhs), points-to(rhs) ⊆ points-to(p))
    Store {
        lhs: AbstractLocation,
        rhs: AbstractLocation,
    },
}

/// Points-to analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointsToAnalysis {
    /// Maps each location to the set of locations it may point to
    points_to_sets: HashMap<AbstractLocation, HashSet<AbstractLocation>>,

    /// All constraints collected during analysis
    constraints: Vec<PointsToConstraint>,

    /// Map variable names to their abstract locations
    variable_locations: HashMap<String, AbstractLocation>,
}

impl PointsToAnalysis {
    /// Create a new empty points-to analysis result
    pub fn new() -> Self {
        Self {
            points_to_sets: HashMap::new(),
            constraints: Vec::new(),
            variable_locations: HashMap::new(),
        }
    }

    /// Get the points-to set for a variable by name
    pub fn points_to(&self, var_name: &str) -> HashSet<String> {
        if let Some(loc) = self.variable_locations.get(var_name) {
            if let Some(pts) = self.points_to_sets.get(loc) {
                return pts.iter()
                    .filter_map(|l| match l {
                        AbstractLocation::Variable(name) => Some(name.clone()),
                        AbstractLocation::HeapAllocation(id) => Some(format!("heap#{}", id)),
                        _ => Some(l.to_string()),
                    })
                    .collect();
            }
        }
        HashSet::new()
    }

    /// Get the points-to set for an abstract location
    pub fn points_to_location(&self, loc: &AbstractLocation) -> HashSet<AbstractLocation> {
        self.points_to_sets.get(loc).cloned().unwrap_or_default()
    }

    /// Check if two variables may alias (point to the same location)
    pub fn may_alias(&self, var1: &str, var2: &str) -> bool {
        let pts1 = self.points_to(var1);
        let pts2 = self.points_to(var2);

        !pts1.is_disjoint(&pts2)
    }

    /// Check if two variables may alias with type-aware filtering
    ///
    /// This method uses type information to rule out aliasing between
    /// incompatible types, reducing false positives in the analysis.
    ///
    /// # Example
    ///
    /// ```rust
    /// use gittera_analyzer::{PointsToAnalysisBuilder, TypeContext};
    /// # use gittera_parser::ast::{AstNode, AstNodeKind, Location, Span};
    /// # let program = AstNode::new(0, AstNodeKind::Program,
    /// #     Location { file_path: "test.ts".to_string(),
    /// #                span: Span { start_line: 1, start_column: 0,
    /// #                             end_line: 1, end_column: 10,
    /// #                             start_byte: 0, end_byte: 10 } },
    /// #     String::new());
    ///
    /// let type_ctx = TypeContext::from_ast(&program);
    /// let pts = PointsToAnalysisBuilder::new().build(&program);
    ///
    /// // Type-aware alias check considers type compatibility
    /// let may_alias = pts.may_alias_with_types("obj1", "obj2", &type_ctx);
    /// ```
    pub fn may_alias_with_types(
        &self,
        var1: &str,
        var2: &str,
        type_context: &TypeContext,
    ) -> bool {
        // First check type compatibility
        if !type_context.could_alias(var1, var2) {
            return false; // Types are incompatible - cannot alias
        }

        // Then check points-to sets
        self.may_alias(var1, var2)
    }

    /// Get all constraints
    pub fn constraints(&self) -> &[PointsToConstraint] {
        &self.constraints
    }

    /// Get the total number of abstract locations tracked
    pub fn location_count(&self) -> usize {
        self.points_to_sets.len()
    }

    /// Get statistics about the analysis
    pub fn stats(&self) -> PointsToStats {
        let total_points_to_relations: usize = self.points_to_sets
            .values()
            .map(|s| s.len())
            .sum();

        PointsToStats {
            num_locations: self.points_to_sets.len(),
            num_constraints: self.constraints.len(),
            num_variables: self.variable_locations.len(),
            total_points_to_relations,
            avg_points_to_set_size: if self.points_to_sets.is_empty() {
                0.0
            } else {
                total_points_to_relations as f64 / self.points_to_sets.len() as f64
            },
        }
    }
}

impl Default for PointsToAnalysis {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about points-to analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PointsToStats {
    pub num_locations: usize,
    pub num_constraints: usize,
    pub num_variables: usize,
    pub total_points_to_relations: usize,
    pub avg_points_to_set_size: f64,
}

/// Builder for points-to analysis
pub struct PointsToAnalysisBuilder {
    /// Maximum number of iterations for constraint solving
    max_iterations: usize,
    /// Optional type context for type-aware analysis
    type_context: Option<TypeContext>,
}

impl PointsToAnalysisBuilder {
    /// Create a new builder with default settings
    pub fn new() -> Self {
        Self {
            max_iterations: 100,
            type_context: None,
        }
    }

    /// Set the maximum number of iterations for constraint solving
    pub fn with_max_iterations(mut self, max: usize) -> Self {
        self.max_iterations = max;
        self
    }

    /// Enable type-aware analysis
    ///
    /// When type context is provided, the analysis will:
    /// - Skip aliasing between incompatible types
    /// - Filter out primitive types that cannot hold references
    /// - Produce smaller, more precise points-to sets
    ///
    /// # Example
    ///
    /// ```rust
    /// use gittera_analyzer::{PointsToAnalysisBuilder, TypeContext};
    /// # use gittera_parser::ast::{AstNode, AstNodeKind, Location, Span};
    /// # let program = AstNode::new(0, AstNodeKind::Program,
    /// #     Location { file_path: "test.ts".to_string(),
    /// #                span: Span { start_line: 1, start_column: 0,
    /// #                             end_line: 1, end_column: 10,
    /// #                             start_byte: 0, end_byte: 10 } },
    /// #     String::new());
    ///
    /// // Build type context from AST
    /// let type_ctx = TypeContext::from_ast(&program);
    ///
    /// // Build type-aware points-to analysis
    /// let pts = PointsToAnalysisBuilder::new()
    ///     .with_type_context(type_ctx)
    ///     .build(&program);
    /// ```
    pub fn with_type_context(mut self, type_context: TypeContext) -> Self {
        self.type_context = Some(type_context);
        self
    }

    /// Build the points-to analysis from an AST
    pub fn build(&self, ast: &AstNode) -> PointsToAnalysis {
        let mut analysis = PointsToAnalysis::new();

        // Step 1: Collect constraints from AST
        self.collect_constraints(ast, &mut analysis);

        // Step 2: Solve constraints using worklist algorithm
        self.solve_constraints(&mut analysis);

        analysis
    }

    /// Check if a variable type can hold references (for type-aware filtering)
    fn can_hold_reference(&self, var_name: &str) -> bool {
        if let Some(ref ctx) = self.type_context {
            if let Some(type_info) = ctx.get_variable_type(var_name) {
                return type_info.can_hold_reference();
            }
        }
        // Conservative: if no type info, assume it can hold references
        true
    }

    /// Check if two types could be aliased based on type compatibility
    fn types_could_alias(&self, var1: &str, var2: &str) -> bool {
        if let Some(ref ctx) = self.type_context {
            return ctx.could_alias(var1, var2);
        }
        // Conservative: if no type info, assume they could alias
        true
    }

    /// Collect constraints from the AST
    fn collect_constraints(&self, node: &AstNode, analysis: &mut PointsToAnalysis) {
        match &node.kind {
            // Variable declaration: let x = expr
            AstNodeKind::VariableDeclaration { name, var_type, .. } => {
                // TYPE-AWARE: Skip variables with primitive types that can't hold references
                if let Some(type_str) = var_type {
                    use crate::type_system::TypeInfo;
                    let type_info = TypeInfo::from_type_string(type_str);
                    if !type_info.can_hold_reference() {
                        // Primitive type - skip points-to tracking
                        // Still recurse into children
                        for child in &node.children {
                            self.collect_constraints(child, analysis);
                        }
                        return;
                    }
                }

                let var_loc = AbstractLocation::var(name);
                analysis.variable_locations.insert(name.clone(), var_loc.clone());

                // Look for initializer in children
                if node.children.len() > 0 {
                    if let Some(rhs_loc) = self.analyze_expression(&node.children[0], analysis) {
                        analysis.constraints.push(PointsToConstraint::Copy {
                            lhs: var_loc,
                            rhs: rhs_loc,
                        });
                    }
                }
            }

            // Assignment expression: x = expr
            AstNodeKind::AssignmentExpression { .. } => {
                // Left side is first child, right side is second child
                if node.children.len() >= 2 {
                    let left = &node.children[0];
                    let right = &node.children[1];

                    // TYPE-AWARE: Check if LHS can hold references
                    if let AstNodeKind::Identifier { name } = &left.kind {
                        if !self.can_hold_reference(name) {
                            // LHS is primitive type - skip constraint
                            for child in &node.children {
                                self.collect_constraints(child, analysis);
                            }
                            return;
                        }
                    }

                    if let Some(lhs_loc) = self.analyze_lvalue(left, analysis) {
                        if let Some(rhs_loc) = self.analyze_expression(right, analysis) {
                            analysis.constraints.push(PointsToConstraint::Copy {
                                lhs: lhs_loc,
                                rhs: rhs_loc,
                            });
                        }
                    }
                }
            }

            // Object/Array expressions create new heap locations
            AstNodeKind::ObjectExpression { .. } | AstNodeKind::ArrayExpression { .. } => {
                let heap_loc = AbstractLocation::heap(node.id);
                analysis.points_to_sets.insert(heap_loc, HashSet::new());
            }

            _ => {}
        }

        // Recursively process children
        for child in &node.children {
            self.collect_constraints(child, analysis);
        }
    }

    /// Analyze an expression and return its abstract location
    fn analyze_expression(&self, expr: &AstNode, analysis: &mut PointsToAnalysis) -> Option<AbstractLocation> {
        match &expr.kind {
            AstNodeKind::Identifier { name } => {
                let loc = AbstractLocation::var(name);
                analysis.variable_locations.insert(name.clone(), loc.clone());
                Some(loc)
            }

            AstNodeKind::ObjectExpression { .. } | AstNodeKind::ArrayExpression { .. } => {
                let heap_loc = AbstractLocation::heap(expr.id);
                analysis.points_to_sets.insert(heap_loc.clone(), HashSet::new());
                Some(heap_loc)
            }

            AstNodeKind::MemberExpression { object, property, .. } => {
                // object and property are strings in the AST, not child nodes
                let base_loc = AbstractLocation::var(object);
                Some(AbstractLocation::field(base_loc, property))
            }

            AstNodeKind::CallExpression { callee, .. } => {
                // Return value of a function call (callee is a string)
                Some(AbstractLocation::ReturnValue(callee.clone()))
            }

            AstNodeKind::UnaryExpression { operator } if operator == "&" => {
                // Address-of operator - check first child
                if expr.children.len() > 0 {
                    if let Some(arg_loc) = self.analyze_expression(&expr.children[0], analysis) {
                        let result_loc = AbstractLocation::heap(expr.id);
                        analysis.constraints.push(PointsToConstraint::AddressOf {
                            lhs: result_loc.clone(),
                            rhs: arg_loc,
                        });
                        return Some(result_loc);
                    }
                }
                None
            }

            AstNodeKind::UnaryExpression { operator } if operator == "*" => {
                // Dereference operator - check first child
                if expr.children.len() > 0 {
                    if let Some(arg_loc) = self.analyze_expression(&expr.children[0], analysis) {
                        let result_loc = AbstractLocation::heap(expr.id);
                        analysis.constraints.push(PointsToConstraint::Load {
                            lhs: result_loc.clone(),
                            rhs: arg_loc,
                        });
                        return Some(result_loc);
                    }
                }
                None
            }

            _ => None,
        }
    }

    /// Analyze an lvalue (left-hand side of assignment)
    fn analyze_lvalue(&self, expr: &AstNode, analysis: &mut PointsToAnalysis) -> Option<AbstractLocation> {
        self.analyze_expression(expr, analysis)
    }

    /// Solve the collected constraints using a worklist algorithm
    fn solve_constraints(&self, analysis: &mut PointsToAnalysis) {
        let mut changed = true;
        let mut iterations = 0;

        while changed && iterations < self.max_iterations {
            changed = false;
            iterations += 1;

            for constraint in analysis.constraints.clone() {
                match constraint {
                    PointsToConstraint::AddressOf { lhs, rhs } => {
                        // pts(lhs) = {rhs}
                        let pts = analysis.points_to_sets.entry(lhs).or_insert_with(HashSet::new);
                        if pts.insert(rhs) {
                            changed = true;
                        }
                    }

                    PointsToConstraint::Copy { lhs, rhs } => {
                        // pts(lhs) ⊇ pts(rhs)
                        if let Some(rhs_pts) = analysis.points_to_sets.get(&rhs).cloned() {
                            let lhs_pts = analysis.points_to_sets.entry(lhs).or_insert_with(HashSet::new);
                            for loc in rhs_pts {
                                if lhs_pts.insert(loc) {
                                    changed = true;
                                }
                            }
                        }
                    }

                    PointsToConstraint::Load { lhs, rhs } => {
                        // For all p in pts(rhs): pts(lhs) ⊇ pts(p)
                        if let Some(rhs_pts) = analysis.points_to_sets.get(&rhs).cloned() {
                            for p in rhs_pts {
                                if let Some(p_pts) = analysis.points_to_sets.get(&p).cloned() {
                                    let lhs_pts = analysis.points_to_sets.entry(lhs.clone())
                                        .or_insert_with(HashSet::new);
                                    for loc in p_pts {
                                        if lhs_pts.insert(loc) {
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }

                    PointsToConstraint::Store { lhs, rhs } => {
                        // For all p in pts(lhs): pts(p) ⊇ pts(rhs)
                        if let Some(lhs_pts) = analysis.points_to_sets.get(&lhs).cloned() {
                            if let Some(rhs_pts) = analysis.points_to_sets.get(&rhs).cloned() {
                                for p in lhs_pts {
                                    let p_pts = analysis.points_to_sets.entry(p)
                                        .or_insert_with(HashSet::new);
                                    for loc in &rhs_pts {
                                        if p_pts.insert(loc.clone()) {
                                            changed = true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if iterations >= self.max_iterations {
            eprintln!("Warning: Points-to analysis reached maximum iterations ({})", self.max_iterations);
        }
    }
}

impl Default for PointsToAnalysisBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_field_access() {
        let loc1 = AbstractLocation::var("obj");
        let field = AbstractLocation::field(loc1, "name");

        assert_eq!(field.to_string(), "obj.name");
    }

    #[test]
    fn test_array_element() {
        let loc1 = AbstractLocation::var("arr");
        let elem = AbstractLocation::array_element(loc1, Some(5));

        assert_eq!(elem.to_string(), "arr[5]");
    }

    #[test]
    fn test_abstract_location_types() {
        let var = AbstractLocation::var("x");
        assert_eq!(var.to_string(), "x");

        let heap = AbstractLocation::heap(42);
        assert_eq!(heap.to_string(), "heap#42");

        let ret = AbstractLocation::ReturnValue("foo".to_string());
        assert_eq!(ret.to_string(), "return#foo");

        let param = AbstractLocation::Parameter {
            function: "bar".to_string(),
            index: 0,
        };
        assert_eq!(param.to_string(), "bar#param0");

        let global = AbstractLocation::Global("config".to_string());
        assert_eq!(global.to_string(), "global#config");

        let unknown = AbstractLocation::Unknown;
        assert_eq!(unknown.to_string(), "unknown");
    }
}
