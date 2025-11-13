# KodeCD SAST Engine

A high-performance Static Application Security Testing (SAST) engine written in Rust - a CodeQL competitor with a custom query language (KQL).

## Features

- **Multi-language support**: Rust, Python, JavaScript, TypeScript, Java, Go, C, C++, C#, Ruby, PHP
- **Tree-sitter based parsing**: Fast and accurate AST generation
- **Control Flow Graph (CFG)**: Advanced program analysis
- **Data Flow Analysis**: Track data through your application
- **Taint Analysis**: Detect data flow from sources to dangerous sinks
- **Custom Query Language (KQL)**: Write declarative security queries
- **Multiple output formats**: Text, JSON, SARIF
- **Built-in security queries**: Pre-built queries for OWASP Top 10

## Architecture

```
┌─────────────────────────────────────────────┐
│ KodeCD SAST Engine (Rust-based)            │
├─────────────────────────────────────────────┤
│ 1. Parser (Tree-sitter)                     │
│    - Language grammars                      │
│    - AST generation                         │
│                                             │
│ 2. Analyzer                                 │
│    - Data flow analysis                     │
│    - Taint tracking                         │
│    - Control flow graphs                    │
│                                             │
│ 3. Query Engine                             │
│    - Custom query language (KQL)            │
│    - Pre-built security queries             │
│    - User-defined queries                   │
│                                             │
│ 4. Reporter                                 │
│    - SARIF format output                    │
│    - Line-level findings                    │
│    - Fix suggestions                        │
└─────────────────────────────────────────────┘
```

## Installation

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))

### Build from source

```bash
git clone https://github.com/your-org/kodecd-sast
cd kodecd-sast
cargo build --release
```

The binary will be available at `target/release/kodecd`

## Quick Start

### Scan a file with built-in queries

```bash
kodecd scan src/main.rs
```

### Analyze with a specific query

```bash
kodecd analyze src/main.rs --query queries/sql-injection.kql
```

### List available built-in queries

```bash
kodecd list-queries
```

### Output to different formats

```bash
# JSON format
kodecd scan src/main.rs --format json --output report.json

# SARIF format (for IDE integration)
kodecd scan src/main.rs --format sarif --output report.sarif
```

## KQL Query Language

KQL (KodeCD Query Language) is a declarative language for writing security queries.

### Example: Detect SQL Injection

```kql
// Detect SQL injection vulnerabilities
from MethodCall mc
where mc.method_name = "execute"
  and mc.is_database_call()
  and mc.argument(0).is_tainted_by_user_input()
select mc, "SQL injection vulnerability: user input not sanitized"
```

### Example: Detect Command Injection

```kql
// Detect command injection
from CallExpression call
where call.callee = "exec"
  and call.arguments_count > 0
select call, "Potential command injection"
```

### Query Structure

```kql
from <EntityType> <variable>
where <predicates>
select <variable>, "<message>"
```

**Supported Entity Types:**
- `MethodCall` - Method invocations
- `FunctionDeclaration` - Function definitions
- `VariableDeclaration` - Variable declarations
- `CallExpression` - Function calls
- `BinaryExpression` - Binary operations
- `AnyNode` - Any AST node

**Predicates:**
- `method_name = "value"` - Match method names
- `is_database_call()` - Check if it's a database operation
- `is_tainted_by_user_input()` - Taint analysis
- `argument(N)` - Access specific arguments

## Project Structure

```
kodecd-sast/
├── src/                    # Main CLI application
│   └── main.rs
├── crates/
│   ├── parser/            # AST parsing with Tree-sitter
│   │   ├── src/
│   │   │   ├── ast.rs          # AST node definitions
│   │   │   ├── language.rs     # Language support
│   │   │   ├── parser.rs       # Parser implementation
│   │   │   └── visitor.rs      # AST visitor pattern
│   │   └── Cargo.toml
│   │
│   ├── analyzer/          # Data flow & taint analysis
│   │   ├── src/
│   │   │   ├── cfg.rs          # Control flow graphs
│   │   │   ├── dataflow.rs     # Data flow framework
│   │   │   ├── taint.rs        # Taint analysis
│   │   │   └── symbol_table.rs # Symbol tracking
│   │   └── Cargo.toml
│   │
│   ├── query/             # KQL query language
│   │   ├── src/
│   │   │   ├── ast.rs          # Query AST
│   │   │   ├── lexer.rs        # Tokenization
│   │   │   ├── parser.rs       # Query parsing
│   │   │   ├── executor.rs     # Query execution
│   │   │   └── stdlib.rs       # Built-in queries
│   │   └── Cargo.toml
│   │
│   └── reporter/          # Output formatting
│       ├── src/
│       │   ├── formats.rs      # Format handlers
│       │   └── sarif.rs        # SARIF support
│       └── Cargo.toml
│
├── queries/               # Example KQL queries
│   ├── sql-injection.kql
│   ├── xss.kql
│   └── command-injection.kql
│
├── Cargo.toml
└── README.md
```

## Performance

KodeCD is designed for speed:

- **Rust-based**: 10-100x faster than Ruby/Python SAST tools
- **Parallel analysis**: Multi-threaded processing
- **Incremental parsing**: Only re-parse changed files
- **Memory efficient**: Minimal allocations with zero-copy parsing

## Roadmap

### Phase 1: Core Engine (Current)
- [x] Multi-language AST parsing
- [x] Control flow graph generation
- [x] Data flow analysis framework
- [x] Taint tracking
- [x] KQL query language
- [x] SARIF output

### Phase 2: Enhanced Analysis
- [ ] Interprocedural analysis
- [ ] Points-to analysis
- [ ] Symbolic execution
- [ ] Path-sensitive analysis

### Phase 3: Developer Experience
- [ ] IDE integrations (VS Code, IntelliJ)
- [ ] Git hooks for pre-commit scanning
- [ ] CI/CD integration (GitHub Actions, GitLab CI)
- [ ] Query marketplace

### Phase 4: Advanced Features
- [ ] Machine learning-based pattern detection
- [ ] Auto-fix suggestions
- [ ] Custom sanitizer definitions
- [ ] Configuration profiles

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for guidelines.

## License

MIT OR Apache-2.0

## Comparison with CodeQL

| Feature | KodeCD | CodeQL |
|---------|--------|--------|
| Language | Rust | C++ |
| Performance | 10-100x faster | Baseline |
| Query Language | KQL (simpler) | QL (complex) |
| Languages Supported | 11+ | 10+ |
| Open Source | Yes | Partially |
| WebAssembly Support | Yes | No |
| Custom Queries | Yes | Yes |
| Taint Analysis | Yes | Yes |
| Data Flow | Yes | Yes |

## Example Output

```
KodeCD SAST Analysis Results
==================================================

Summary:
  Total Findings: 3
  Critical: 1
  High: 1
  Medium: 1
  Low: 0

Findings:
--------------------------------------------------

1. Potential SQL injection vulnerability
   Location: src/db.rs:42:5
   Severity: Critical
   Code: let query = format!("SELECT * FROM users WHERE id = {}", user_id);

2. Potential command injection vulnerability
   Location: src/utils.rs:18:9
   Severity: High
   Code: Command::new("sh").arg("-c").arg(user_input).output()

3. Potential XSS vulnerability
   Location: src/web.rs:56:13
   Severity: Medium
   Code: element.innerHTML = user_data;
```

## Support

- Documentation: https://docs.kodecd.com
- Issues: https://github.com/your-org/kodecd-sast/issues
- Discussions: https://github.com/your-org/kodecd-sast/discussions
