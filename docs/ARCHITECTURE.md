# Gittera SAST Architecture

## System Overview

Gittera is a multi-stage static analysis pipeline that transforms source code into actionable security findings.

```
┌─────────────┐      ┌──────────────┐      ┌─────────────┐      ┌──────────────┐
│   Source    │─────▶│    Parser    │─────▶│  Analyzer   │─────▶│   Reporter   │
│    Code     │      │  (Tree-sitter)│      │ (CFG+Taint) │      │ (SARIF/JSON) │
└─────────────┘      └──────────────┘      └─────────────┘      └──────────────┘
                              │                     │
                              ▼                     ▼
                         ┌─────────┐         ┌──────────┐
                         │   AST   │         │   CFG    │
                         └─────────┘         └──────────┘
                              │                     │
                              └──────────┬──────────┘
                                         ▼
                                   ┌──────────┐
                                   │  Query   │
                                   │ Executor │
                                   └──────────┘
```

## Module Breakdown

### 1. Parser Module (`crates/parser`)

**Purpose**: Convert source code from multiple languages into a unified AST representation.

**Components**:

#### Language Support (`language.rs`)
```rust
pub enum Language {
    Rust, Python, JavaScript, TypeScript,
    Java, Go, C, Cpp, CSharp, Ruby, Php
}

impl Language {
    fn tree_sitter_language(&self) -> tree_sitter::Language;
    fn from_path(path: &Path) -> Result<Self>;
}
```

#### AST Nodes (`ast.rs`)
```rust
pub struct AstNode {
    id: NodeId,
    kind: AstNodeKind,
    location: Location,
    children: Vec<AstNode>,
    text: String,
}

pub enum AstNodeKind {
    FunctionDeclaration { name, parameters, return_type },
    CallExpression { callee, arguments_count },
    BinaryExpression { operator },
    // ... 100+ variants
}
```

**Design Decisions**:
- Language-agnostic AST for unified analysis
- Clone-based ownership to avoid lifetime complexity
- Span tracking for precise error reporting
- Visitor pattern for traversal

#### Parser (`parser.rs`)
```rust
pub struct Parser {
    config: LanguageConfig,
    file_path: PathBuf,
}

impl Parser {
    pub fn parse_file(&self) -> ParseResult<AstNode>;
    pub fn parse_source(&self, source: &str) -> ParseResult<AstNode>;

    fn convert_node(&self, node: &Node, source: &str) -> AstNode;
    fn classify_node(&self, node: &Node, source: &str) -> AstNodeKind;
}
```

**Key Algorithms**:
1. Recursive descent over Tree-sitter CST
2. Pattern matching for node classification
3. Child extraction with cursor management
4. Metadata preservation (location, text)

---

### 2. Analyzer Module (`crates/analyzer`)

**Purpose**: Build program representations (CFG) and perform data flow analysis.

#### Control Flow Graph (`cfg.rs`)

**Data Structures**:
```rust
pub struct ControlFlowGraph {
    graph: DiGraph<CfgNode, CfgEdge>,
    entry: CfgGraphIndex,
    exit: CfgGraphIndex,
    node_map: HashMap<NodeId, CfgGraphIndex>,
}

pub struct CfgNode {
    id: NodeId,
    ast_node_id: NodeId,
    kind: CfgNodeKind,
    label: String,
}

pub enum CfgNodeKind {
    Entry, Exit, Statement, Branch, Loop, Return
}
```

**CFG Construction Algorithm**:

```
Build(ast_node, predecessor):
  1. Match ast_node.kind:
     - Block: Build sequential flow
     - If: Build diamond with merge node
     - Loop: Build cycle with back edge
     - Return: Connect to exit
     - Other: Single node
  2. Return last node in sequence
```

**Example CFG**:
```
Entry
  │
  ▼
If-Condition
  ├─True──▶ Then-Block ──┐
  │                       │
  └─False─▶ Else-Block ───┤
                          ▼
                      Merge-Node
                          │
                          ▼
                        Exit
```

#### Data Flow Analysis (`dataflow.rs`)

**Framework**:
```rust
pub trait TransferFunction<T> {
    fn transfer(&self, node: CfgGraphIndex, input: &HashSet<T>) -> HashSet<T>;
    fn initial_state(&self) -> HashSet<T>;
}

pub struct DataFlowAnalysis<T> {
    direction: DataFlowDirection,  // Forward or Backward
    transfer_fn: Box<dyn TransferFunction<T>>,
}
```

**Worklist Algorithm**:
```
1. Initialize:
   - Add entry node to worklist
   - Set initial state

2. While worklist not empty:
   - Remove node N
   - Merge inputs from predecessors (forward) or successors (backward)
   - Apply transfer function: OUT[N] = Transfer(IN[N])
   - If OUT[N] changed:
     - Add successors/predecessors to worklist

3. Return fixed point: IN/OUT sets for all nodes
```

**Complexity**: O(N × H) where N = nodes, H = height of lattice

#### Taint Analysis (`taint.rs`)

**Concepts**:
```rust
pub struct TaintSource {
    name: String,
    kind: TaintSourceKind,  // UserInput, FileRead, Network, etc.
    node_id: NodeId,
}

pub struct TaintSink {
    name: String,
    kind: TaintSinkKind,    // SqlQuery, CommandExec, etc.
    node_id: NodeId,
}

pub struct TaintValue {
    variable: String,
    source: TaintSourceKind,
    sanitized: bool,
}
```

**Taint Propagation**:
```
1. Mark sources as tainted
2. Propagate through data flow:
   - Assignments: target becomes tainted if source is tainted
   - Function calls: arguments taint return value
   - Sanitizers: remove taint
3. Check sinks: report if tainted value reaches sink
```

**Transfer Function**:
```rust
fn transfer(&self, node: CfgGraphIndex, input: &HashSet<TaintValue>)
    -> HashSet<TaintValue>
{
    let mut output = input.clone();

    match cfg_node.kind {
        FunctionCall if is_source() => output.insert(new_taint),
        FunctionCall if is_sanitizer() => mark_all_sanitized(output),
        _ => output,  // Pass through
    }

    output
}
```

---

### 3. Query Module (`crates/query`)

**Purpose**: Define and execute security queries using KQL.

#### KQL AST (`ast.rs`)

**Grammar**:
```kql
Query ::= FROM_CLAUSE WHERE_CLAUSE SELECT_CLAUSE

FROM_CLAUSE ::= "from" EntityType Variable

WHERE_CLAUSE ::= "where" Predicate ("and" Predicate)*

SELECT_CLAUSE ::= "select" Variable "," Message
```

**AST Structure**:
```rust
pub struct Query {
    from: FromClause,
    where_clause: Option<WhereClause>,
    select: SelectClause,
}

pub enum Predicate {
    MethodName { variable, operator, value },
    Comparison { left, operator, right },
    And { left, right },
    Or { left, right },
}
```

#### Query Executor (`executor.rs`)

**Execution Model**:
```
1. Traverse AST recursively
2. For each node:
   - Check if matches FROM clause (entity type)
   - Evaluate WHERE predicates
   - If all match: create Finding
3. Return all findings
```

**Example**:
```kql
from CallExpression call
where call.callee = "execute"
select call, "Potential SQL injection"
```

Translates to:
```rust
fn execute(query: &Query, ast: &AstNode) -> Vec<Finding> {
    ast.find_descendants(|node| {
        matches_entity(query.from.entity, node.kind) &&
        evaluate_where(query.where_clause, node)
    })
}
```

#### Standard Library (`stdlib.rs`)

**Pre-built Queries**:
```rust
impl StandardLibrary {
    pub fn sql_injection_query() -> Query {
        Query::new(
            FromClause::new(EntityType::MethodCall, "mc"),
            Some(WhereClause::new(vec![
                Predicate::MethodName {
                    variable: "mc",
                    operator: Equal,
                    value: "execute",
                }
            ])),
            SelectClause::new(...)
        )
    }
}
```

---

### 4. Reporter Module (`crates/reporter`)

**Purpose**: Format and output analysis results.

#### Report Structure
```rust
pub struct Report {
    findings: Vec<Finding>,
    summary: Summary,
}

pub struct Finding {
    file_path: String,
    line: usize,
    column: usize,
    message: String,
    severity: String,
    code_snippet: String,
}
```

#### Output Formats

**Text** (`formats.rs`):
- Colored terminal output
- Human-readable
- Severity-based coloring (red/yellow/green)

**JSON**:
```json
{
  "findings": [...],
  "summary": {
    "total_findings": 10,
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 0
  }
}
```

**SARIF** (`sarif.rs`):
```json
{
  "version": "2.1.0",
  "$schema": "...",
  "runs": [{
    "tool": { "driver": { "name": "Gittera SAST" } },
    "results": [...]
  }]
}
```

---

## Data Flow Through the System

### Parsing Phase
```
Source Code (String)
    │
    ▼ [Tree-sitter Parse]
Tree-sitter CST (tree_sitter::Tree)
    │
    ▼ [AST Conversion]
Gittera AST (AstNode)
```

### Analysis Phase
```
AstNode
    │
    ├──▶ [CFG Builder] ──▶ ControlFlowGraph
    │
    └──▶ [Symbol Table Builder] ──▶ SymbolTable
                                        │
                                        ▼
                                [Data Flow Analysis]
                                        │
                                        ├──▶ DataFlowResult
                                        │
                                        └──▶ TaintAnalysisResult
```

### Query Phase
```
Query (KQL)
    │
    ▼ [Parser]
QueryAst
    │
    ▼ [Executor with AST + CFG]
QueryResult (Vec<Finding>)
```

### Reporting Phase
```
Vec<Finding>
    │
    ▼ [Reporter]
    ├──▶ Text Output
    ├──▶ JSON Output
    └──▶ SARIF Output
```

---

## Key Design Patterns

### 1. Builder Pattern
```rust
let cfg = CfgBuilder::new()
    .build(&ast);
```

### 2. Visitor Pattern
```rust
trait AstVisitor {
    fn visit_enter(&mut self, node: &AstNode) -> Result;
    fn visit_exit(&mut self, node: &AstNode) -> Result;
}
```

### 3. Strategy Pattern
```rust
trait TransferFunction<T> {
    fn transfer(&self, node, input) -> output;
}
```

### 4. Factory Pattern
```rust
Language::from_path(path)?
    .tree_sitter_language()
```

---

## Performance Considerations

### Memory Usage
- **AST**: Clone-based (trades memory for simplicity)
- **CFG**: petgraph arena allocation
- **Taint Sets**: HashSet with small element optimization

### Time Complexity
| Operation | Complexity | Notes |
|-----------|-----------|-------|
| Parse | O(n) | Tree-sitter |
| AST Build | O(n) | Linear traversal |
| CFG Build | O(n) | Per node |
| Data Flow | O(n × h) | n=nodes, h=lattice height |
| Query Exec | O(n × q) | n=nodes, q=queries |

### Optimization Opportunities
1. **Parallel Parsing**: Parse files concurrently
2. **Incremental Analysis**: Re-analyze changed functions only
3. **Query Caching**: Cache AST patterns
4. **Lazy CFG**: Build on-demand per function

---

## Extension Points

### Adding a New Language
```rust
// 1. Add to Language enum
pub enum Language {
    // ...
    NewLang,
}

// 2. Add parser dependency
[dependencies]
tree-sitter-newlang = "0.x"

// 3. Implement mapping
fn tree_sitter_language(&self) -> tree_sitter::Language {
    match self {
        Language::NewLang => tree_sitter_newlang::language(),
        // ...
    }
}
```

### Adding a New Query
```rust
// queries/my-check.kql
from CallExpression call
where call.callee = "dangerous_function"
select call, "Dangerous function called"

// Add to stdlib
impl StandardLibrary {
    pub fn my_check_query() -> Query {
        // ... construct query AST
    }
}
```

### Adding a New Analysis
```rust
// 1. Define transfer function
struct MyTransferFunction;

impl TransferFunction<MyValue> for MyTransferFunction {
    fn transfer(&self, node, input) -> output {
        // ... analysis logic
    }
}

// 2. Run analysis
let analysis = DataFlowAnalysis::new(direction, Box::new(transfer));
let result = analysis.analyze(&cfg);
```

---

## Testing Strategy

### Unit Tests
```rust
#[cfg(test)]
mod tests {
    #[test]
    fn test_parse_simple_rust() {
        let source = "fn main() {}";
        let ast = parse_source(source).unwrap();
        assert_eq!(ast.kind, AstNodeKind::Program);
    }
}
```

### Integration Tests
```rust
#[test]
fn test_end_to_end_scan() {
    let result = scan_file("test.rs").unwrap();
    assert!(result.findings.len() > 0);
}
```

### Property-based Testing (Future)
```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn parse_never_panics(s in "\\PC*") {
        let _ = parse_source(&s);
    }
}
```

---

## Concurrency Model

### Current: Single-threaded
- Simple, predictable
- Good for proof-of-concept

### Future: Multi-threaded
```rust
use rayon::prelude::*;

files.par_iter()
    .map(|file| scan_file(file))
    .collect()
```

**Considerations**:
- Thread-safe AST sharing (Arc)
- Concurrent CFG construction
- Parallel query execution

---

## Error Handling Strategy

### Parse Errors
```rust
pub enum ParseError {
    IoError(std::io::Error),
    FileTooLarge(usize, usize),
    TreeSitterError(String),
    LanguageError(LanguageError),
}
```

### Analysis Errors
- Non-fatal: Log and continue
- Fatal: Return error to user

### Query Errors
```rust
pub enum QueryError {
    ParseError(ParseError),
    ExecutionError(String),
}
```

---

## Logging & Observability

### Tracing Integration
```rust
use tracing::{info, debug, warn, error};

#[instrument]
fn parse_file(path: &Path) -> Result<AstNode> {
    info!("Parsing file: {}", path.display());
    debug!("Language: {:?}", language);
    // ...
}
```

### Log Levels
- ERROR: Unrecoverable failures
- WARN: Skipped files, partial results
- INFO: High-level progress
- DEBUG: Detailed analysis steps
- TRACE: Full AST/CFG dumps

---

## Future Architecture Enhancements

### 1. Language Server Protocol (LSP)
```
┌──────────┐         ┌──────────────┐
│   IDE    │◀───────▶│  LSP Server  │
└──────────┘         └──────────────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ Gittera Core  │
                     └──────────────┘
```

### 2. Incremental Computation
```rust
struct IncrementalCache {
    ast_cache: HashMap<FileHash, AstNode>,
    cfg_cache: HashMap<FunctionId, ControlFlowGraph>,
}
```

### 3. Distributed Analysis
```
┌─────────┐     ┌─────────┐     ┌─────────┐
│ Worker1 │────▶│ Reducer │◀────│ Worker2 │
└─────────┘     └─────────┘     └─────────┘
                      │
                      ▼
                  Results
```

---

## Contribution Guidelines

### Code Style
- Follow Rust conventions (`cargo fmt`)
- Use `cargo clippy` for lints
- Document public APIs
- Add tests for new features

### Pull Request Checklist
- [ ] Tests pass (`cargo test`)
- [ ] Code formatted (`cargo fmt`)
- [ ] No clippy warnings (`cargo clippy`)
- [ ] Documentation updated
- [ ] Examples added if needed

---

## References

- **Tree-sitter**: https://tree-sitter.github.io/
- **Petgraph**: https://docs.rs/petgraph/
- **SARIF**: https://sarifweb.azurewebsites.net/
- **Data Flow Analysis**: "Compilers: Principles, Techniques, and Tools" (Dragon Book)
- **Taint Analysis**: "Secure Data Flow" by Denning & Denning
