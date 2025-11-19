# Taint Analysis Refactor - Technical Specification

**Status**: 🚧 IN PROGRESS
**Priority**: 🔴 CRITICAL
**Estimated Effort**: 80-100 hours

---

## Current Implementation Analysis

### Critical Flaws Identified

#### 1. String-Based Transfer Function (Lines 269-320, 324-444)
**Problem**: The `OwnedTaintTransferFunction` operates on string labels from `CfgNode.label` instead of analyzing the actual AST structure.

**Examples of Broken Behavior**:

```rust
// Current code (line 275):
if label.contains('=') && !label.contains("==") {
    if let Some(var_part) = label.split('=').next() {
        let var_name = var_part.trim().to_string();
        // ...
    }
}
```

**Why this fails**:
- ❌ `arr[i] = x` - Extracts `arr[i]` as variable name (wrong!)
- ❌ `obj.field = x` - Extracts `obj.field` as variable name (wrong!)
- ❌ `*ptr = x` - Extracts `*ptr` as variable name (wrong!)
- ❌ `let (a, b) = tuple` - Can't handle destructuring
- ❌ `x = y + z` - Doesn't track taint from both `y` and `z`
- ❌ `x = sanitize(y)` - Can't determine if sanitizer was actually called

#### 2. Brittle Variable Extraction (Lines 299-320)
**Problem**: `extract_referenced_variables()` uses regex-style word splitting.

```rust
// Current code (line 306):
for word in label.split(|c: char| !c.is_alphanumeric() && c != '_') {
    if !word.is_empty() && !word.chars().next().unwrap().is_numeric() {
        vars.push(word.to_string());
    }
}
```

**Why this fails**:
- ❌ `x.y.z` → Extracts `["x", "y", "z"]` (loses structure)
- ❌ `arr[index]` → Extracts `["arr", "index"]` (loses array access)
- ❌ `func(arg1, arg2)` → Extracts `["func", "arg1", "arg2"]` (loses call structure)
- ❌ Doesn't distinguish between LHS and RHS of assignment

#### 3. Massive Performance Issue (Line 105)
**Problem**: CFG is cloned entirely for every taint analysis run.

```rust
let cfg_for_transfer = clone_cfg(cfg);  // ❌ Clones entire graph!
```

**Impact**:
- 1,000-node CFG: ~50KB + 10ms
- 10,000-node CFG: ~500KB + 100ms
- 100,000-node CFG: ~5MB + 1s

**Root cause**: `TransferFunction` trait requires `'static` lifetime (line 14 in dataflow.rs).

#### 4. Incorrect Taint Propagation (Lines 389-410)
**Problem**: Taint propagation logic doesn't correctly handle all cases.

**Broken Cases**:
```rust
// Case 1: Binary operations
let y = x + z;  // If x is tainted, y should be tainted
                // Current code might miss this

// Case 2: Member expressions
let result = obj.method(tainted);  // Should track taint through method call
                                   // Current code can't analyze this

// Case 3: Nested expressions
let final = outer(inner(tainted));  // Should track through nested calls
                                    // Current code can't handle nesting
```

---

## New Architecture Design

### Phase 1: AST-Based Transfer Function

#### New TransferFunction Trait (With Lifetimes)

```rust
/// New trait that works with AST nodes and references
pub trait TransferFunction<'a, T>
where
    T: Clone + Eq + Hash + Debug,
{
    /// Apply transfer function with full AST access
    fn transfer(
        &self,
        cfg_node: &CfgNode,
        ast: &'a AstNode,           // Full AST access
        cfg: &'a ControlFlowGraph,  // CFG reference (no clone!)
        input: &HashSet<T>
    ) -> HashSet<T>;

    fn initial_state(&self) -> HashSet<T>;
}
```

#### New DataFlowAnalysis (With Lifetimes)

```rust
pub struct DataFlowAnalysis<'a, T, F>
where
    T: Clone + Eq + Hash + Debug,
    F: TransferFunction<'a, T>,
{
    direction: DataFlowDirection,
    transfer_fn: F,
    _phantom: PhantomData<&'a ()>,
}

impl<'a, T, F> DataFlowAnalysis<'a, T, F>
where
    T: Clone + Eq + Hash + Debug,
    F: TransferFunction<'a, T>,
{
    pub fn analyze(
        &self,
        cfg: &'a ControlFlowGraph,
        ast: &'a AstNode
    ) -> DataFlowResult<T> {
        // Now we can pass cfg and ast by reference!
        // No cloning needed!
    }
}
```

#### New TaintTransferFunction

```rust
pub struct TaintTransferFunction<'a> {
    sources: &'a [TaintSource],
    sinks: &'a [TaintSink],
    sanitizers: &'a HashSet<String>,
    ast_map: HashMap<NodeId, &'a AstNode>,  // Fast AST lookup
}

impl<'a> TaintTransferFunction<'a> {
    pub fn new(
        sources: &'a [TaintSource],
        sinks: &'a [TaintSink],
        sanitizers: &'a HashSet<String>,
        ast: &'a AstNode,
    ) -> Self {
        // Build AST node ID → node mapping for fast lookup
        let mut ast_map = HashMap::new();
        Self::build_ast_map(ast, &mut ast_map);

        Self {
            sources,
            sinks,
            sanitizers,
            ast_map,
        }
    }

    fn build_ast_map(node: &'a AstNode, map: &mut HashMap<NodeId, &'a AstNode>) {
        map.insert(node.id, node);
        for child in &node.children {
            Self::build_ast_map(child, map);
        }
    }
}

impl<'a> TransferFunction<'a, TaintValue> for TaintTransferFunction<'a> {
    fn transfer(
        &self,
        cfg_node: &CfgNode,
        ast: &'a AstNode,
        cfg: &'a ControlFlowGraph,
        input: &HashSet<TaintValue>
    ) -> HashSet<TaintValue> {
        let mut output = input.clone();

        // Get the actual AST node for this CFG node
        let ast_node = match self.ast_map.get(&cfg_node.ast_node_id) {
            Some(node) => node,
            None => return output,  // No AST node found
        };

        // Now we can properly analyze the AST!
        match &ast_node.kind {
            AstNodeKind::AssignmentExpression { .. } => {
                self.handle_assignment(ast_node, &mut output, input)
            }

            AstNodeKind::CallExpression { .. } => {
                self.handle_call(ast_node, &mut output, input)
            }

            AstNodeKind::VariableDeclaration { .. } => {
                self.handle_variable_declaration(ast_node, &mut output, input)
            }

            _ => {}
        }

        output
    }

    fn initial_state(&self) -> HashSet<TaintValue> {
        HashSet::new()
    }
}
```

### Phase 2: Expression Evaluation

#### Expression Evaluator

```rust
impl<'a> TaintTransferFunction<'a> {
    /// Evaluate an expression to determine if it's tainted
    fn evaluate_expression(
        &self,
        expr: &AstNode,
        taint_set: &HashSet<TaintValue>
    ) -> Option<TaintValue> {
        match &expr.kind {
            AstNodeKind::Identifier { name } => {
                // Look up identifier in taint set
                taint_set.iter()
                    .find(|t| t.variable == *name)
                    .cloned()
            }

            AstNodeKind::BinaryExpression { operator } => {
                // Taint propagates through binary ops
                let left = expr.children.get(0)?;
                let right = expr.children.get(1)?;

                let left_taint = self.evaluate_expression(left, taint_set);
                let right_taint = self.evaluate_expression(right, taint_set);

                // If either side is tainted, result is tainted
                left_taint.or(right_taint)
            }

            AstNodeKind::CallExpression { callee, .. } => {
                // Check if this is a taint source
                if self.is_taint_source(callee) {
                    return Some(TaintValue::new(
                        expr.text.clone(),
                        self.get_source_kind(callee)
                    ));
                }

                // Check if this is a sanitizer
                if self.sanitizers.contains(callee) {
                    return None;  // Sanitizer produces clean value
                }

                // Otherwise, propagate taint from arguments
                for arg in &expr.children {
                    if let Some(taint) = self.evaluate_expression(arg, taint_set) {
                        return Some(taint);
                    }
                }

                None
            }

            AstNodeKind::MemberExpression { object, property, .. } => {
                // Taint propagates through member access
                // If obj is tainted, obj.prop is tainted
                if let Some(obj_node) = expr.children.first() {
                    self.evaluate_expression(obj_node, taint_set)
                } else {
                    None
                }
            }

            AstNodeKind::Literal { .. } => {
                // Literals are never tainted
                None
            }

            _ => None
        }
    }
}
```

### Phase 3: Assignment Handling

#### LValue Extraction

```rust
impl<'a> TaintTransferFunction<'a> {
    /// Extract all variables being assigned to (left-hand side)
    fn extract_lvalues(&self, lhs: &AstNode) -> Vec<String> {
        let mut vars = Vec::new();

        match &lhs.kind {
            AstNodeKind::Identifier { name } => {
                vars.push(name.clone());
            }

            // Array pattern: [a, b, c] = ...
            AstNodeKind::ArrayPattern => {
                for child in &lhs.children {
                    vars.extend(self.extract_lvalues(child));
                }
            }

            // Object pattern: {a, b: c} = ...
            AstNodeKind::ObjectPattern => {
                for child in &lhs.children {
                    vars.extend(self.extract_lvalues(child));
                }
            }

            // Member expression: obj.field = ...
            AstNodeKind::MemberExpression { object, property, .. } => {
                // For now, just track the property
                // In full implementation, we'd track obj.field as a path
                vars.push(property.clone());
            }

            _ => {}
        }

        vars
    }

    /// Handle assignment expression
    fn handle_assignment(
        &self,
        node: &AstNode,
        output: &mut HashSet<TaintValue>,
        input: &HashSet<TaintValue>
    ) {
        // Assignment has 2 children: LHS and RHS
        if node.children.len() != 2 {
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
            // RHS is tainted - propagate to LHS
            for var in lhs_vars {
                output.insert(TaintValue::new(var, taint.source.clone()));
            }
        } else {
            // RHS is clean - kill taint for LHS
            for var in &lhs_vars {
                output.retain(|t| &t.variable != var);
            }
        }
    }
}
```

---

## Implementation Plan

### Task 1: Update DataFlowAnalysis Trait (8-10 hours)
- [ ] 1.1: Add lifetime parameter to `TransferFunction` trait
- [ ] 1.2: Change `transfer()` signature to accept AST + CFG references
- [ ] 1.3: Remove `'static` bound from trait
- [ ] 1.4: Update `DataFlowAnalysis` struct with lifetimes
- [ ] 1.5: Update `analyze()` to pass AST and CFG by reference
- [ ] 1.6: Fix compilation errors in existing code

**Files to modify**:
- `crates/analyzer/src/dataflow.rs`

### Task 2: Implement AST-Based TaintTransferFunction (20-25 hours)
- [ ] 2.1: Create new `TaintTransferFunction` struct with lifetimes
- [ ] 2.2: Implement AST node ID mapping for fast lookup
- [ ] 2.3: Implement `handle_assignment()`
- [ ] 2.4: Implement `handle_call()`
- [ ] 2.5: Implement `handle_variable_declaration()`
- [ ] 2.6: Implement source/sink/sanitizer detection from AST

**Files to modify**:
- `crates/analyzer/src/taint.rs`

### Task 3: Implement Expression Evaluator (25-30 hours)
- [ ] 3.1: Implement `evaluate_expression()` framework
- [ ] 3.2: Handle `Identifier` expressions
- [ ] 3.3: Handle `BinaryExpression` (taint from either operand)
- [ ] 3.4: Handle `UnaryExpression`
- [ ] 3.5: Handle `CallExpression` (sources, sanitizers, propagation)
- [ ] 3.6: Handle `MemberExpression` (obj.prop)
- [ ] 3.7: Handle `Literal` (never tainted)
- [ ] 3.8: Handle array access expressions
- [ ] 3.9: Handle conditional expressions (ternary)
- [ ] 3.10: Add comprehensive unit tests

**Files to modify**:
- `crates/analyzer/src/taint.rs`

### Task 4: Implement LValue Extraction (15-20 hours)
- [ ] 4.1: Implement `extract_lvalues()` for identifiers
- [ ] 4.2: Handle array patterns `[a, b] = ...`
- [ ] 4.3: Handle object patterns `{a, b} = ...`
- [ ] 4.4: Handle member expressions `obj.field = ...`
- [ ] 4.5: Handle array element assignment `arr[i] = ...`
- [ ] 4.6: Handle destructuring `{ a: { b } } = ...`
- [ ] 4.7: Add unit tests

**Files to modify**:
- `crates/analyzer/src/taint.rs`

### Task 5: Update TaintAnalysis Main API (8-10 hours)
- [ ] 5.1: Update `analyze()` to pass AST to transfer function
- [ ] 5.2: Remove CFG cloning (delete `clone_cfg()` function!)
- [ ] 5.3: Update all callers
- [ ] 5.4: Fix integration with query executor

**Files to modify**:
- `crates/analyzer/src/taint.rs`
- `crates/query/src/executor.rs`

### Task 6: Comprehensive Testing (12-15 hours)
- [ ] 6.1: Unit tests for `evaluate_expression()` (30+ cases)
- [ ] 6.2: Unit tests for `extract_lvalues()` (20+ cases)
- [ ] 6.3: Unit tests for `handle_assignment()` (25+ cases)
- [ ] 6.4: Unit tests for `handle_call()` (20+ cases)
- [ ] 6.5: Integration tests with real vulnerability patterns
- [ ] 6.6: Integration tests with clean code (no false positives)

**Files to create/modify**:
- `crates/analyzer/src/taint.rs` (tests module)
- `tests/test_taint_accuracy.rs` (new integration tests)

### Task 7: Performance Benchmarking (4-6 hours)
- [ ] 7.1: Benchmark CFG cloning overhead (before)
- [ ] 7.2: Benchmark new implementation (after)
- [ ] 7.3: Verify 50-80% performance improvement
- [ ] 7.4: Profile with large CFGs (10K+ nodes)

**Files to create**:
- `benches/taint_analysis_benchmark.rs`

---

## Success Criteria

### Correctness
- ✅ Correctly handles `x = y` (simple assignment)
- ✅ Correctly handles `x = y + z` (taint from multiple sources)
- ✅ Correctly handles `x = obj.field` (member expressions)
- ✅ Correctly handles `x = arr[i]` (array access)
- ✅ Correctly handles `x = sanitize(y)` (sanitization)
- ✅ Correctly handles `x = source()` (taint source detection)
- ✅ Correctly handles `[a, b] = tuple` (destructuring)
- ✅ Correctly handles `obj.field = tainted` (member assignment)
- ✅ No false positives on clean code
- ✅ Detects all vulnerable patterns in test fixtures

### Performance
- ✅ 50-80% faster than current implementation
- ✅ No CFG cloning (verify with `grep -r "clone_cfg"`)
- ✅ Handles 10K+ node CFGs in <1 second
- ✅ Memory usage reduced by 40-60%

### Code Quality
- ✅ All new code has unit tests (>80% coverage)
- ✅ Integration tests with 15 language fixtures
- ✅ No compiler warnings
- ✅ Passes all existing tests
- ✅ Documentation for all public APIs

---

## Timeline

**Total Estimated Effort**: 80-100 hours

### Week 1 (Tasks 1-2): Foundation
- Days 1-2: Update TransferFunction trait (Task 1)
- Days 3-7: Implement AST-based TaintTransferFunction (Task 2)

### Week 2 (Task 3): Expression Evaluation
- Days 8-14: Implement evaluate_expression() for all types (Task 3)

### Week 3 (Tasks 4-5): LValue Extraction & API Updates
- Days 15-18: Implement extract_lvalues() (Task 4)
- Days 19-21: Update main API, remove CFG cloning (Task 5)

### Week 4 (Tasks 6-7): Testing & Benchmarking
- Days 22-26: Comprehensive testing (Task 6)
- Days 27-28: Performance benchmarking (Task 7)

---

## Risk Mitigation

### Risk 1: Breaking Changes to DataFlowAnalysis
**Likelihood**: High
**Impact**: Critical (blocks all dataflow analyses)
**Mitigation**:
- Keep old implementation temporarily as `DataFlowAnalysisLegacy`
- Migrate incrementally, one analysis at a time
- A/B test results between old and new

### Risk 2: Lifetime Complexity
**Likelihood**: Medium
**Impact**: High (compiler errors, delays)
**Mitigation**:
- Start with simple cases (no lifetimes in struct fields)
- Use `Rc`/`Arc` as fallback if lifetimes become too complex
- Consult Rust experts if blocked

### Risk 3: Performance Regression
**Likelihood**: Low
**Impact**: Medium
**Mitigation**:
- Benchmark before starting (establish baseline)
- Benchmark after each major change
- Revert if regression >10%

---

## Next Steps

1. **Review this spec** with team
2. **Get approval** to proceed
3. **Create feature branch**: `feature/ast-based-taint-analysis`
4. **Begin Task 1**: Update TransferFunction trait
5. **Daily progress updates** to stakeholders

---

**Status**: 📋 **READY TO IMPLEMENT**
**Assignee**: TBD
**Start Date**: TBD
