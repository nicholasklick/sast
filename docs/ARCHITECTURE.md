# Gittera SAST Architecture

## Overview

Gittera SAST is a high-performance static application security testing engine written in Rust. It supports 18 programming languages and achieves 96.4% precision on the OWASP Java Benchmark—significantly outperforming Semgrep (67.2%) and CodeQL (57.4%).

### Key Metrics (December 2024)

| Metric | Value |
|--------|-------|
| Languages Supported | 18 |
| OWASP Java Precision | 96.4% |
| OWASP Java F1 Score | 84.3% |
| False Positive Rate | 2.6% |
| Analysis Speed | ~75 files/sec |

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              CLI (src/main.rs)                               │
│                    Commands: analyze, scan, query, parse                     │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
            ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
            │  Discovery  │   │  Parallel   │   │   Cache     │
            │ (src/)      │   │  Analyzer   │   │  Manager    │
            └─────────────┘   └─────────────┘   └─────────────┘
                    │                 │
                    └────────┬────────┘
                             ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Analysis Pipeline                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────┐   ┌──────────┐   ┌──────────────┐   ┌──────────────────┐     │
│  │  Parser  │──▶│   CFG    │──▶│  Symbol      │──▶│  Call Graph      │     │
│  │          │   │ Builder  │   │  Table       │   │  Builder         │     │
│  └──────────┘   └──────────┘   └──────────────┘   └──────────────────┘     │
│       │              │               │                    │                 │
│       ▼              ▼               ▼                    ▼                 │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                   Interprocedural Taint Analysis                  │      │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌──────────────┐   │      │
│  │  │ DataFlow   │ │ Access     │ │ Call       │ │ Flow         │   │      │
│  │  │ Node       │ │ Path       │ │ Context    │ │ Summary      │   │      │
│  │  └────────────┘ └────────────┘ └────────────┘ └──────────────┘   │      │
│  └──────────────────────────────────────────────────────────────────┘      │
│                              │                                              │
│                              ▼                                              │
│  ┌──────────────────────────────────────────────────────────────────┐      │
│  │                      Query Executor                               │      │
│  │              (GQL + Extended Security Queries)                    │      │
│  └──────────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Reporter                                        │
│                    Formats: Text, JSON, SARIF                               │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

```
gittera-sast/
├── src/                          # Main binary
│   ├── main.rs                   # CLI entry point
│   ├── discovery.rs              # File discovery & filtering
│   └── parallel.rs               # Parallel analysis orchestration
│
├── crates/
│   ├── parser/                   # Multi-language parsing
│   │   └── src/
│   │       ├── parser.rs         # Tree-sitter wrapper
│   │       ├── ast.rs            # Unified AST representation
│   │       └── language.rs       # 18 language definitions
│   │
│   ├── analyzer/                 # Core analysis engine
│   │   └── src/
│   │       ├── cfg.rs                    # Control flow graph
│   │       ├── call_graph.rs             # Inter-file call graph
│   │       ├── symbol_table.rs           # Symbol resolution
│   │       ├── interprocedural_taint.rs  # Main taint engine (175KB)
│   │       ├── taint_config.rs           # Language configs (106KB)
│   │       ├── taint.rs                  # Core taint types
│   │       ├── taint_pipeline.rs         # Staged analysis
│   │       ├── dataflow_node.rs          # CodeQL-style nodes
│   │       ├── access_path.rs            # Field-sensitive tracking
│   │       ├── call_context.rs           # k-CFA context sensitivity
│   │       ├── content.rs                # Content tracking
│   │       ├── flow_summary.rs           # MaD-style summaries
│   │       ├── language_handler.rs       # Per-language handlers
│   │       ├── symbolic.rs               # Constant propagation
│   │       ├── points_to.rs              # Alias analysis
│   │       ├── collection_ops.rs         # Collection taint tracking
│   │       ├── type_system.rs            # Type inference
│   │       └── yaml_config.rs            # YAML model loading
│   │
│   ├── query/                    # Query engine
│   │   └── src/
│   │       ├── parser.rs         # GQL parser
│   │       ├── executor.rs       # Query execution
│   │       ├── stdlib.rs         # Built-in queries
│   │       └── extended_stdlib.rs # Security query suite
│   │
│   ├── reporter/                 # Output formatting
│   │   └── src/
│   │       ├── formats.rs        # Text/JSON output
│   │       └── sarif.rs          # SARIF 2.1.0 output
│   │
│   └── cache/                    # Incremental analysis
│       └── src/
│           └── lib.rs            # Finding fingerprints & caching
│
└── models/                       # YAML taint configurations
    ├── java/
    ├── python/
    ├── javascript/
    └── ruby/
```

---

## Core Components

### 1. Parser (`crates/parser`)

Multi-language parsing using Tree-sitter with unified AST output.

**Supported Languages (18):**

| Category | Languages |
|----------|-----------|
| JVM | Java, Kotlin, Scala |
| Web | JavaScript, TypeScript, PHP |
| Scripting | Python, Ruby, Perl, Lua |
| Systems | Rust, Go, C, C++ |
| Mobile | Swift, Dart |
| Other | C#, Bash |

**Key Types:**
```rust
pub struct AstNode {
    pub id: NodeId,
    pub kind: AstNodeKind,
    pub location: Location,
    pub children: Vec<AstNode>,
    pub text: String,
}

pub enum AstNodeKind {
    FunctionDeclaration { name, parameters, return_type, body },
    CallExpression { callee, arguments_count },
    MemberExpression { object, property },
    AssignmentExpression { operator },
    // ... 100+ variants
}
```

### 2. Analyzer (`crates/analyzer`)

The core analysis engine implementing CodeQL-inspired dataflow analysis.

#### 2.1 Control Flow Graph (`cfg.rs`)

```rust
pub struct ControlFlowGraph {
    graph: DiGraph<CfgNode, CfgEdge>,
    entry: CfgGraphIndex,
    exit: CfgGraphIndex,
    node_map: HashMap<NodeId, CfgGraphIndex>,
}
```

#### 2.2 Interprocedural Taint Analysis (`interprocedural_taint.rs`)

The main analysis engine (~175KB, 4000+ lines). Implements:

- **Source Detection**: HTTP parameters, file reads, environment variables
- **Sink Detection**: SQL queries, command execution, file writes, XSS outputs
- **Sanitizer Recognition**: Encoding functions, validation, escaping
- **Flow Tracking**: Through assignments, function calls, returns, collections

```rust
pub struct InterproceduralTaintAnalysis {
    sources: Vec<TaintSource>,
    sinks: Vec<TaintSink>,
    sanitizers: Vec<Sanitizer>,
    call_graph: CallGraph,
    taint_state: HashMap<String, TaintValue>,
}
```

#### 2.3 CodeQL-Inspired Infrastructure

**DataFlow Node (`dataflow_node.rs`):**
```rust
pub enum DataFlowNode {
    ParameterNode { function_name, param_index, param_name },
    ArgumentNode { call_site, arg_index },
    ReturnNode { function_name },
    ExpressionNode { node_id, expression_type },
}
```

**Access Path (`access_path.rs`):**
Tracks field-sensitive taint up to depth 5.
```rust
pub struct AccessPath {
    base: String,
    components: Vec<AccessPathComponent>,  // .field, [index], .method()
}
```

**Call Context (`call_context.rs`):**
Implements k-CFA (k=1) for context-sensitive analysis.
```rust
pub struct CallContext {
    call_stack: Vec<CallSite>,
    max_depth: usize,  // default: 1
}
```

**Flow Summary (`flow_summary.rs`):**
Models-as-Data (MaD) style function summaries.
```rust
pub struct FlowSummary {
    function_signature: String,
    input: FlowEndpoint,   // Argument[0], Argument[this]
    output: FlowEndpoint,  // ReturnValue, Argument[0].field
    preserves_taint: bool,
    preserves_sanitization: bool,
}
```

#### 2.4 Taint Configuration (`taint_config.rs`)

Language-specific source/sink/sanitizer definitions (~106KB).

```rust
impl TaintConfig {
    pub fn java_config() -> Self;
    pub fn python_config() -> Self;
    pub fn javascript_config(lang: Language) -> Self;
    pub fn ruby_config() -> Self;
    pub fn php_config() -> Self;
    pub fn go_config() -> Self;
    // ... 18 languages
}
```

**Example Configuration:**
```rust
TaintConfig {
    sources: vec![
        ("getParameter", Source::HttpParam),
        ("getHeader", Source::HttpHeader),
        ("getCookies", Source::Cookie),
    ],
    sinks: vec![
        ("executeQuery", Sink::SqlQuery),
        ("exec", Sink::CommandExec),
        ("write", Sink::FileWrite),
    ],
    sanitizers: vec![
        "escapeHtml", "encodeURIComponent", "PreparedStatement",
    ],
}
```

### 3. Query Engine (`crates/query`)

GQL (Gittera Query Language) for custom security queries.

**Example Query:**
```gql
from CallExpression call
where call.callee = "eval"
  and call.hasArgument(TaintedValue)
select call, "Code injection via eval()"
```

**Extended Security Queries (`extended_stdlib.rs`):**
- SQL Injection (9 variants)
- Command Injection (5 variants)
- XSS (6 variants)
- Path Traversal (4 variants)
- LDAP/XPath Injection
- Weak Cryptography
- Insecure Randomness
- Trust Boundary Violations

### 4. Reporter (`crates/reporter`)

**Output Formats:**

| Format | Use Case |
|--------|----------|
| Text | Human-readable terminal output |
| JSON | CI/CD integration, programmatic access |
| SARIF | GitHub Code Scanning, IDE integration |

---

## Analysis Pipeline

### Phase 1: Discovery & Parsing

```
Source Directory
      │
      ▼
┌─────────────────┐
│ File Discovery  │  - Filter by extension
│                 │  - Exclude vendor/, node_modules/
│                 │  - Respect .gitignore
└─────────────────┘
      │
      ▼
┌─────────────────┐
│ Parallel Parse  │  - Rayon thread pool
│                 │  - Tree-sitter per language
│                 │  - Unified AST output
└─────────────────┘
```

### Phase 2: Program Analysis

```
AST per file
      │
      ├──▶ CFG Construction
      │
      ├──▶ Symbol Table Building
      │
      ├──▶ Call Graph Construction (inter-file)
      │
      └──▶ Points-To Analysis
              │
              ▼
┌─────────────────────────────────────┐
│     Interprocedural Taint Analysis  │
│                                     │
│  1. Identify sources (user input)   │
│  2. Track flow through CFG          │
│  3. Handle function calls           │
│  4. Check sanitization              │
│  5. Report at sinks                 │
└─────────────────────────────────────┘
```

### Phase 3: Query Execution

```
Taint Results + AST
      │
      ▼
┌─────────────────┐
│ Query Executor  │  - Run 42 default queries
│                 │  - Pattern matching
│                 │  - Taint-aware predicates
└─────────────────┘
      │
      ▼
   Findings
```

### Phase 4: Reporting

```
Findings
      │
      ├──▶ Deduplication
      │
      ├──▶ Severity Assignment
      │
      ├──▶ Code Snippet Extraction
      │
      └──▶ Format Output (Text/JSON/SARIF)
```

---

## Taint Propagation Rules

### Source → Sink Flow

```
1. SOURCE: request.getParameter("input")
       │
       ▼
2. ASSIGNMENT: String data = source
       │
       ▼
3. TRANSFORMATION: String upper = data.toUpperCase()
       │         (taint preserved)
       ▼
4. FUNCTION CALL: process(upper)
       │         (taint flows to callee)
       ▼
5. RETURN: return result
       │         (taint flows to caller)
       ▼
6. SINK: db.execute(result)  ← VULNERABILITY REPORTED
```

### Sanitization

```
String input = request.getParameter("q");  // TAINTED
String safe = escapeHtml(input);           // SANITIZED
response.write(safe);                      // NO ALERT (sanitized)
```

### Collection Tracking

```
List<String> items = new ArrayList<>();
items.add(request.getParameter("x"));  // List becomes tainted
String first = items.get(0);            // Taint propagates
sink(first);                            // VULNERABILITY
```

---

## Performance Optimizations

### Parallelization

```rust
// Parallel file analysis using Rayon
files.par_iter()
    .map(|file| analyze_file(file))
    .collect::<Vec<_>>()
```

### Caching

- **AST Cache**: Avoid re-parsing unchanged files
- **Finding Fingerprints**: Stable IDs for deduplication
- **Incremental Analysis**: Only analyze changed files

### Memory Efficiency

- **Arena Allocation**: CFG nodes in petgraph
- **String Interning**: Deduplicate identifiers
- **Lazy Loading**: Parse files on demand

---

## Comparison with Competitors

### OWASP Java Benchmark (2,740 test cases)

| Tool | Precision | Recall | F1 | False Positives |
|------|-----------|--------|-----|-----------------|
| **Gittera** | **96.4%** | 75.0% | **84.3%** | **40** |
| Semgrep | 67.2% | 88.2% | 76.3% | 608 |
| CodeQL | 57.4% | 90.9% | 70.3% | 956 |

### Speed Comparison

| Tool | Time | Relative |
|------|------|----------|
| Semgrep | 64s | 1.0x |
| Gittera | 203s | 3.2x |
| CodeQL | 565s | 8.8x |

**Gittera's advantage**: 3x slower than Semgrep but 15x fewer false positives.

---

## Extension Points

### Adding a New Language

1. Add Tree-sitter grammar dependency
2. Extend `Language` enum in `crates/parser/src/language.rs`
3. Add AST node mappings in `parser.rs`
4. Create taint config in `crates/analyzer/src/taint_config.rs`

### Adding a New Vulnerability Type

1. Define source/sink patterns in `taint_config.rs`
2. Add query in `crates/query/src/extended_stdlib.rs`
3. Map to CWE in reporter

### Adding Framework Support

Create YAML model in `models/<language>/`:
```yaml
framework: Spring
sources:
  - pattern: "@RequestParam"
    type: http_param
sinks:
  - pattern: "JdbcTemplate.query"
    type: sql_query
    argument: 0
sanitizers:
  - pattern: "PreparedStatement"
```

---

## Future Roadmap

### Phase 4: SSA Construction
- Enable strong updates (kill taint on reassignment)
- Precise alias analysis
- Expected: +10% recall

### Phase 5: Enhanced MaD
- Sanitization preservation through transformations
- Generic type tracking
- Expected: +5% precision

### Phase 6: IDE Integration
- Language Server Protocol (LSP)
- Real-time analysis
- Quick fixes

---

## References

- **CodeQL**: https://codeql.github.com/
- **Tree-sitter**: https://tree-sitter.github.io/
- **SARIF**: https://sarifweb.azurewebsites.net/
- **OWASP Benchmark**: https://owasp.org/www-project-benchmark/
- **Taint Analysis**: Livshits & Lam, "Finding Security Vulnerabilities in Java Applications with Static Analysis" (2005)
- **k-CFA**: Shivers, "Control-Flow Analysis of Higher-Order Languages" (1991)
