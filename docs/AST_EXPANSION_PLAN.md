# AST Classification Expansion Plan

**Task**: Expand AstNodeKind from ~30 to 50+ variants
**Priority**: 🔴 CRITICAL
**Estimated Effort**: 40-60 hours
**Date**: November 19, 2024

---

## Current State Analysis

### What We Have (30 variants)

**Program Structure** (3):
- Program, Module, Package

**Declarations** (6):
- FunctionDeclaration
- ClassDeclaration
- MethodDeclaration
- VariableDeclaration
- InterfaceDeclaration
- TypeAlias
- EnumDeclaration

**Statements** (9):
- ExpressionStatement
- ReturnStatement
- IfStatement
- WhileStatement
- ForStatement
- TryStatement
- CatchClause
- ThrowStatement
- Block

**Expressions** (12):
- BinaryExpression
- UnaryExpression
- CallExpression
- MemberExpression
- Identifier
- Literal
- AssignmentExpression
- ArrowFunction
- ObjectExpression
- ArrayExpression
- AwaitExpression
- YieldExpression
- TemplateString

**Special** (3):
- ImportDeclaration
- ExportDeclaration
- Decorator
- Comment

**Fallback** (1):
- Other (catches ~40% of constructs!)

---

## What's Missing (Critical Gaps)

### Control Flow Statements (CRITICAL for CFG)

Currently falling back to `Other`:
- ✗ **switch_statement** / **switch_case** → Needed for CFG branch analysis
- ✗ **do_statement** → Do-while loops have different CFG structure
- ✗ **break_statement** / **continue_statement** → Jump edges in CFG
- ✗ **labeled_statement** → For break/continue targets
- ✗ **with_statement** (JS) → Scope modification
- ✗ **finally_clause** → Exception flow in CFG

**Impact**: CFG is incomplete for ~30% of control flow patterns

---

### Exception Handling (CRITICAL)

Currently partial:
- ✓ TryStatement (exists)
- ✓ CatchClause (exists)
- ✗ **finally_clause** → Missing finally block
- ✗ Multiple catch handlers → Not modeled
- ✗ **throw_expression** vs throw_statement

**Impact**: Exception flow analysis is incomplete

---

### Expression Types (HIGH PRIORITY)

Currently falling back to `Other`:
- ✗ **conditional_expression** (ternary: `a ? b : c`)
- ✗ **update_expression** (`i++`, `--x`)
- ✗ **sequence_expression** (`a, b, c`)
- ✗ **new_expression** (`new Constructor()`)
- ✗ **this_expression** / **super_expression**
- ✗ **spread_element** (`...args`)
- ✗ **rest_element** (function params)
- ✗ **parenthesized_expression**
- ✗ **tagged_template_expression** (`` tag`template` ``)
- ✗ **class_expression** (anonymous classes)
- ✗ **function_expression** (anonymous functions)

**Impact**: Query matching fails, taint analysis can't track through these

---

### Pattern Matching & Destructuring (HIGH)

Currently falling back to `Other`:
- ✗ **array_pattern** (`[a, b] = arr`)
- ✗ **object_pattern** (`{x, y} = obj`)
- ✗ **assignment_pattern** (default values: `{x = 5}`)
- ✗ **rest_pattern** (`{...rest}`)

**Impact**: Can't track variable assignments through destructuring (common in modern JS/TS)

---

### Object/Array Constructs (MEDIUM)

Currently too generic:
- ✓ ObjectExpression (exists but limited)
- ✓ ArrayExpression (exists but limited)
- ✗ **property** (object property)
- ✗ **computed_property_name** (`{[key]: value}`)
- ✗ **shorthand_property** (`{x}` instead of `{x: x}`)
- ✗ **spread_property** (`{...obj}`)
- ✗ **method_definition** (inside objects)
- ✗ **getter** / **setter**

**Impact**: Object tracking incomplete

---

### Module System (MEDIUM)

Currently partial:
- ✓ ImportDeclaration (exists)
- ✓ ExportDeclaration (exists)
- ✗ **import_specifier** → Not modeled separately
- ✗ **export_specifier** → Not modeled separately
- ✗ **import_default_specifier**
- ✗ **import_namespace_specifier** (`import * as X`)
- ✗ **export_all_declaration** (`export * from`)

**Impact**: Module dependency analysis incomplete

---

### Type System (TypeScript/Typed Languages) (LOW)

Currently falling back to `Other`:
- ✗ **type_annotation**
- ✗ **type_arguments** (generics)
- ✗ **type_parameters**
- ✗ **as_expression** (type casting)
- ✗ **satisfies_expression** (TS 4.9+)
- ✗ **non_null_assertion** (`x!`)

**Impact**: Type-aware analysis not possible

---

### Class Features (MEDIUM)

Currently partial:
- ✓ ClassDeclaration (exists)
- ✓ MethodDeclaration (exists)
- ✗ **field_definition** (class properties)
- ✗ **static_block** (static initialization)
- ✗ **accessor_property** (getters/setters)
- ✗ **constructor_definition**

**Impact**: OOP analysis incomplete

---

### Generators & Async (LOW)

Currently partial:
- ✓ AwaitExpression (exists)
- ✓ YieldExpression (exists)
- ✗ **yield_from** (Python: `yield from`)
- ✗ **async_function** vs regular function flag

**Impact**: Async flow analysis limited

---

## Proposed New AstNodeKind Variants

### Phase 1: Control Flow (CRITICAL)

```rust
// Switch statements
SwitchStatement {
    discriminant: String,  // Expression being switched on
    cases_count: usize,
},
SwitchCase {
    test: Option<String>,  // None for default case
    consequent_count: usize,
},

// Do-while
DoWhileStatement {
    test: String,  // Condition
},

// Break/continue
BreakStatement {
    label: Option<String>,
},
ContinueStatement {
    label: Option<String>,
},

// Labels
LabeledStatement {
    label: String,
},

// Exception handling
FinallyClause,

// With statement (JS)
WithStatement {
    object: String,
},
```

**Effort**: 8-10 hours (implementation + tests)
**Impact**: Unlocks complete CFG construction

---

### Phase 2: Expressions (HIGH)

```rust
// Ternary
ConditionalExpression {
    test: String,
},

// Update expressions
UpdateExpression {
    operator: String,  // ++, --
    prefix: bool,      // ++i vs i++
},

// Sequence
SequenceExpression {
    expressions_count: usize,
},

// new
NewExpression {
    callee: String,
    arguments_count: usize,
},

// this/super
ThisExpression,
SuperExpression,

// Spread/rest
SpreadElement,
RestElement {
    is_parameter: bool,  // In function params vs array
},

// Parenthesized
ParenthesizedExpression,

// Tagged template
TaggedTemplateExpression {
    tag: String,
},

// Anonymous functions/classes
FunctionExpression {
    name: Option<String>,
    parameters: Vec<Parameter>,
    return_type: Option<String>,
    is_async: bool,
    is_generator: bool,
},
ClassExpression {
    name: Option<String>,
},
```

**Effort**: 12-15 hours
**Impact**: Query matching and taint analysis can handle 95% of expressions

---

### Phase 3: Patterns & Destructuring (HIGH)

```rust
// Array destructuring
ArrayPattern {
    elements_count: usize,
    has_rest: bool,
},

// Object destructuring
ObjectPattern {
    properties_count: usize,
    has_rest: bool,
},

// Assignment pattern (defaults)
AssignmentPattern {
    has_default: bool,
},

// Rest pattern
RestPattern {
    is_array: bool,
},
```

**Effort**: 8-10 hours
**Impact**: Modern JS/TS code analysis complete

---

### Phase 4: Object/Array Details (MEDIUM)

```rust
// Object properties
Property {
    key: String,
    value: Option<String>,
    is_computed: bool,
    is_shorthand: bool,
    is_method: bool,
},

// Getters/setters
GetterDeclaration {
    name: String,
},
SetterDeclaration {
    name: String,
},

// Computed property name
ComputedPropertyName,
```

**Effort**: 6-8 hours
**Impact**: Object analysis more precise

---

### Phase 5: Module System (MEDIUM)

```rust
// Import specifiers
ImportSpecifier {
    imported: String,
    local: String,
},
ImportDefaultSpecifier {
    local: String,
},
ImportNamespaceSpecifier {
    local: String,
},

// Export specifiers
ExportSpecifier {
    exported: String,
    local: String,
},
ExportAllDeclaration {
    source: String,
},
ExportDefaultDeclaration,
```

**Effort**: 4-6 hours
**Impact**: Module dependency tracking complete

---

### Phase 6: TypeScript Support (LOW)

```rust
// Type annotations
TypeAnnotation {
    type_string: String,
},

// Type arguments (generics)
TypeArguments {
    types: Vec<String>,
},

// Type parameters
TypeParameters {
    parameters: Vec<String>,
},

// Type assertions
AsExpression {
    type_string: String,
},
SatisfiesExpression {
    type_string: String,
},
NonNullAssertion,

// Type guards
TypePredicate {
    parameter_name: String,
    type_name: String,
},
```

**Effort**: 6-8 hours
**Impact**: TypeScript-specific analysis enabled

---

### Phase 7: Class Enhancements (MEDIUM)

```rust
// Class fields
FieldDefinition {
    name: String,
    field_type: Option<String>,
    is_static: bool,
    visibility: Visibility,
    has_initializer: bool,
},

// Constructor
ConstructorDeclaration {
    parameters: Vec<Parameter>,
    visibility: Visibility,
},

// Static block
StaticBlock,

// Accessor properties
AccessorProperty {
    name: String,
    kind: AccessorKind,  // get or set
},

pub enum AccessorKind {
    Get,
    Set,
}
```

**Effort**: 4-6 hours
**Impact**: OOP analysis complete

---

## Implementation Strategy

### Week 1: Control Flow (24 hours)

**Days 1-2** (16 hours):
- Add Phase 1 variants to `AstNodeKind` enum
- Update `classify_node()` to map tree-sitter nodes:
  - `switch_statement` → `SwitchStatement`
  - `switch_case` → `SwitchCase`
  - `do_statement` → `DoWhileStatement`
  - `break_statement` → `BreakStatement`
  - `continue_statement` → `ContinueStatement`
  - `labeled_statement` → `LabeledStatement`
  - `finally_clause` → `FinallyClause`
  - `with_statement` → `WithStatement`

**Days 3** (8 hours):
- Create parser helper methods:
  - `parse_switch_statement()`
  - `parse_switch_case()`
  - `parse_break_continue()`
  - etc.
- Add unit tests (50+ test cases)

---

### Week 2: Expressions & Patterns (24 hours)

**Days 1-2** (16 hours):
- Add Phase 2 & 3 variants
- Update `classify_node()` for expressions and patterns
- Create parser methods

**Day 3** (8 hours):
- Update taint analysis to handle new expression types
- Update CFG builder to handle new control flow
- Add tests (80+ test cases)

---

### Week 3: Objects, Modules, Types (16 hours)

**Days 1-2** (12 hours):
- Add Phase 4, 5, 6 variants
- Update `classify_node()`
- Create parser methods

**Day 3** (4 hours):
- Update query executor pattern matching
- Add tests (50+ test cases)

---

### Week 4: Class Features & Integration (16 hours)

**Days 1** (8 hours):
- Add Phase 7 variants
- Update `classify_node()`
- Tests

**Days 2-3** (8 hours):
- Update ALL match statements across codebase:
  - `analyzer/src/cfg.rs`
  - `analyzer/src/taint_ast_based.rs`
  - `query/src/executor.rs`
  - `analyzer/src/symbol_table.rs`
- Integration testing with real files

---

## Language-Specific Mappings

### JavaScript/TypeScript

```rust
"switch_statement" => SwitchStatement
"switch_case" => SwitchCase
"do_statement" => DoWhileStatement
"break_statement" => BreakStatement
"continue_statement" => ContinueStatement
"labeled_statement" => LabeledStatement
"with_statement" => WithStatement
"finally_clause" => FinallyClause
"ternary_expression" => ConditionalExpression
"update_expression" => UpdateExpression
"sequence_expression" => SequenceExpression
"new_expression" => NewExpression
"this" => ThisExpression
"super" => SuperExpression
"spread_element" => SpreadElement
"rest_pattern" => RestElement
"array_pattern" => ArrayPattern
"object_pattern" => ObjectPattern
"assignment_pattern" => AssignmentPattern
"property" => Property
"method_definition" => Property { is_method: true }
"computed_property_name" => ComputedPropertyName
```

### Python

```rust
"match_statement" => SwitchStatement  // Python 3.10+
"case_clause" => SwitchCase
"while_statement" => WhileStatement
"break_statement" => BreakStatement
"continue_statement" => ContinueStatement
"with_statement" => WithStatement
"finally_clause" => FinallyClause
"conditional_expression" => ConditionalExpression
"list_comprehension" => ArrayExpression  // Or new variant?
"dictionary_comprehension" => ObjectExpression
"yield_from_expression" => YieldExpression { is_delegate: true }
```

### Rust

```rust
"match_expression" => SwitchStatement
"match_arm" => SwitchCase
"loop_expression" => WhileStatement { test: "true" }  // Infinite loop
"while_expression" => WhileStatement
"break_expression" => BreakStatement
"continue_expression" => ContinueStatement
"if_expression" => ConditionalExpression  // Rust if is expression
"field_expression" => MemberExpression
```

### Go

```rust
"switch_statement" => SwitchStatement
"expression_case" => SwitchCase
"type_switch_statement" => SwitchStatement  // Type switch variant?
"for_statement" => WhileStatement  // Go for is while
"break_statement" => BreakStatement
"continue_statement" => ContinueStatement
"goto_statement" => BreakStatement { label: Some(...) }  // Similar
"defer_statement" => FinallyClause  // Similar semantics
```

### Java/C#

```rust
"switch_expression" => SwitchStatement
"switch_label" => SwitchCase
"do_statement" => DoWhileStatement
"break_statement" => BreakStatement
"continue_statement" => ContinueStatement
"labeled_statement" => LabeledStatement
"finally_clause" => FinallyClause
"ternary_expression" => ConditionalExpression
"instanceof" => BinaryExpression { operator: "instanceof" }
"new_expression" => NewExpression
"this" => ThisExpression
"super" => SuperExpression
```

---

## Breaking Changes & Migration

### Affected Files

**Parser Crate** (Will break):
- `parser/src/ast.rs` - Enum expansion
- `parser/src/parser.rs` - classify_node() updates
- `parser/src/parser_arena.rs` - Same updates

**Analyzer Crate** (Will break):
- `analyzer/src/cfg.rs` - Need to handle new control flow
- `analyzer/src/taint_ast_based.rs` - Add new expression cases
- `analyzer/src/symbol_table.rs` - May need updates
- `analyzer/src/call_graph.rs` - May need updates

**Query Crate** (Will break):
- `query/src/executor.rs` - Pattern matching updates

**Tests** (Will break):
- All tests that match on `AstNodeKind::Other` will need updates
- Integration tests may need fixture updates

### Migration Strategy

1. **Add new variants first** (non-breaking)
2. **Update classify_node() to use them** (still non-breaking for existing code)
3. **Update match statements** with `_ => {}` catch-all (breaks exhaustive matching)
4. **Add tests for new variants**
5. **Update consumers one by one**

### Deprecation Path

```rust
// Mark Other as deprecated
#[deprecated(since = "0.2.0", note = "Most constructs now have specific variants")]
Other {
    node_type: String,
},
```

---

## Testing Plan

### Unit Tests (200+ tests)

**Per new variant**:
- Parse simple example
- Extract correct metadata
- Children are correct
- Location is accurate

**Example**:
```rust
#[test]
fn test_parse_switch_statement() {
    let code = r#"
        switch (x) {
            case 1:
                break;
            case 2:
                return;
            default:
                throw new Error();
        }
    "#;

    let ast = parse_typescript(code);
    let switch_node = find_node_by_kind(&ast, AstNodeKind::SwitchStatement { .. });

    assert!(switch_node.is_some());
    assert_eq!(switch_node.unwrap().children.len(), 3); // 3 cases
}
```

### Integration Tests (50+ tests)

**Real code patterns**:
- Test switch statements from popular repos
- Test destructuring from React code
- Test async/await patterns
- Test ternary expressions
- Test break/continue in loops

**Example**:
```rust
#[test]
fn test_real_world_switch() {
    let code = include_str!("../fixtures/real_switch.ts");
    let ast = parse_typescript(code);

    // Should not have any Other nodes for switch constructs
    let other_nodes = find_all_other_nodes(&ast);
    assert!(
        !other_nodes.iter().any(|n| matches!(n, AstNodeKind::Other { node_type } if node_type.contains("switch"))),
        "Switch constructs should not fall back to Other"
    );
}
```

### Regression Tests

- **Before/after AST comparison**: Ensure existing classifications don't change
- **Performance regression**: Parse speed shouldn't decrease >10%
- **CFG correctness**: CFG should handle new constructs

---

## Success Metrics

### Quantitative

- **Other node reduction**: From ~40% to <5% of all nodes
- **Test coverage**: 95%+ for new variants
- **Parse performance**: <10% regression
- **CFG completeness**: From ~20% to >90% control flow coverage

### Qualitative

- CFG builder can handle 90%+ of real-world code
- Taint analysis can track through all expression types
- Query executor can match on specific constructs (not generic "Other")
- Symbol table can track all declaration types

---

## Risk Mitigation

### Risk 1: Breaking Changes

**Mitigation**:
- Implement behind feature flag initially
- Add compatibility layer for old code
- Update tests incrementally
- Document migration path

### Risk 2: Performance Regression

**Mitigation**:
- Benchmark before/after
- Optimize hot paths (classify_node called millions of times)
- Consider caching classification results
- Profile with large files (100K+ LOC)

### Risk 3: Incomplete Language Coverage

**Mitigation**:
- Start with JavaScript/TypeScript (most common)
- Document which languages are complete
- Add TODO comments for language-specific variants
- Community can contribute language-specific mappings

### Risk 4: Maintenance Burden

**Mitigation**:
- Generate boilerplate with macros
- Create language mapping tables (JSON/YAML)
- Automate test generation
- Clear documentation for adding new variants

---

## Next Steps

1. **Review this plan** with stakeholders
2. **Approve scope** (all phases or subset?)
3. **Create feature branch**: `feature/rich-ast-classification`
4. **Begin Phase 1**: Control flow statements
5. **Daily progress updates**

---

**Status**: 📋 **READY TO START**
**Estimated Completion**: 3-4 weeks (1 developer) or 2 weeks (2 developers)
**Dependencies**: None (can start immediately)
