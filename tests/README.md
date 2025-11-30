# Gittera SAST Test Suite

## Directory Structure

```
tests/
├── README.md                           # This file
├── fixtures/                           # Test data files
│   ├── vulnerable/                     # Files with known vulnerabilities
│   │   ├── javascript_vulnerabilities.js
│   │   ├── swift_vulnerabilities.swift
│   │   └── real_world_example.js
│   ├── clean/                          # Files without vulnerabilities
│   │   ├── safe_javascript.js
│   │   └── safe_python.py
│   ├── multi-language/                 # Multi-language test projects
│   │   └── test_project/              # Sample project structure
│   └── queries/                        # Custom test queries
├── test_results.json                   # Expected test results
├── test_arena_parser.rs               # Arena parser tests
├── test_call_graph.ts                 # Call graph tests
├── test_clean.ts                      # Clean code tests
├── test_interprocedural.ts            # Interprocedural analysis tests
├── test_gql_e2e.rs                    # GQL end-to-end tests
├── test_parser.rs                     # Parser tests
├── test_symbol_table.ts               # Symbol table tests
├── test_taint_analysis.ts             # Taint analysis tests
├── test_vulnerabilities.ts            # Vulnerability detection tests
└── test.rs                            # Basic tests
```

## Test Categories

### 1. Unit Tests
Located in `crates/*/tests/` directories for each crate:
- `crates/parser/tests/` - Parser unit tests
- `crates/analyzer/tests/` - Analyzer unit tests
- `crates/query/tests/` - Query engine unit tests
- `crates/reporter/tests/` - Reporter unit tests

### 2. Integration Tests
Located in `tests/` directory (this directory):
- Parser integration tests
- End-to-end analysis tests
- Multi-component tests

### 3. Fixture Files

#### Vulnerable Test Files
Files in `fixtures/vulnerable/` contain **intentional security vulnerabilities** for testing detection:

**javascript_vulnerabilities.js**
- SQL Injection
- Command Injection
- XSS (innerHTML)
- Hardcoded credentials
- Weak cryptography (MD5, DES)

**swift_vulnerabilities.swift**
- Hardcoded API keys
- SQL injection potential
- Weak cryptography (MD5)

**real_world_example.js**
- Real-world vulnerability patterns
- Complex data flow scenarios

#### Clean Test Files
Files in `fixtures/clean/` contain **secure code** to verify no false positives:

**safe_javascript.js**
- Parameterized queries
- Proper input sanitization
- Safe DOM manipulation
- Secure coding patterns

**safe_python.py**
- Strong cryptography (SHA-256)
- Input validation
- Path traversal prevention
- Parameterized queries

## Running Tests

### Run All Tests
```bash
cargo test
```

### Run Specific Test File
```bash
cargo test --test test_parser
cargo test --test test_taint_analysis
```

### Run Tests with Output
```bash
cargo test -- --nocapture
```

### Run Integration Tests Only
```bash
cargo test --test '*'
```

### Run Unit Tests for Specific Crate
```bash
cargo test -p gittera-parser
cargo test -p gittera-analyzer
cargo test -p gittera-query
```

## Testing Against Fixtures

### Scan Vulnerable Files (Should Find Issues)
```bash
# Should find multiple vulnerabilities
./target/release/gittera-sast scan tests/fixtures/vulnerable/javascript_vulnerabilities.js

# Should find Swift vulnerabilities
./target/release/gittera-sast scan tests/fixtures/vulnerable/swift_vulnerabilities.swift
```

### Scan Clean Files (Should Find Nothing)
```bash
# Should report 0 findings
./target/release/gittera-sast scan tests/fixtures/clean/safe_javascript.js

# Should report 0 findings
./target/release/gittera-sast scan tests/fixtures/clean/safe_python.py
```

### Scan Multi-Language Project
```bash
# Scan entire project directory
./target/release/gittera-sast scan tests/fixtures/multi-language/test_project/
```

## Adding New Tests

### Adding a Vulnerable Test File
1. Create file in `tests/fixtures/vulnerable/`
2. Add known vulnerabilities with comments
3. Document expected findings in comments
4. Run scan to verify detection

Example:
```javascript
// tests/fixtures/vulnerable/new_vulnerability.js

// EXPECTED: js/sql-injection - Critical
const query = "SELECT * FROM users WHERE id = " + userId;
db.execute(query);

// EXPECTED: js/xss - High
element.innerHTML = userInput;
```

### Adding a Clean Test File
1. Create file in `tests/fixtures/clean/`
2. Implement secure patterns
3. Run scan to verify 0 findings

### Adding Integration Test
1. Create `test_*.rs` or `test_*.ts` file in `tests/`
2. Implement test cases
3. Run with `cargo test --test test_name`

## Test Coverage Goals

- ✅ Parser: All 12 supported languages
- ✅ Symbol Table: Scopes, variables, functions
- ✅ Call Graph: Inter-function relationships
- ✅ CFG: Control flow analysis
- ✅ Taint Analysis: Data flow tracking
- ✅ Query Engine: All 75+ queries
- ⏳ False Positive Rate: Target < 5%
- ⏳ Detection Rate: Target > 95% for OWASP Top 10

## Benchmark Tests

Performance benchmarks are located in `benches/`:
```bash
cargo bench
```

## Continuous Integration

Tests run automatically on:
- Every commit (via CI/CD)
- Pull requests
- Release builds

## Test Data Attribution

Vulnerable test files are created for educational purposes and should **never** be used in production. They contain intentional security vulnerabilities.

Clean test files demonstrate secure coding practices recommended by:
- OWASP Secure Coding Practices
- CWE/SANS Top 25
- Language-specific security guidelines
