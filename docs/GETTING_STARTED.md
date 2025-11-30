# Getting Started with Gittera SAST

## Quick Start (5 minutes)

### 1. Build the Project

```bash
cd /Users/nick/code/startup/sast
cargo build --release
```

Build time: ~8-9 seconds

### 2. Run Your First Scan

```bash
./target/release/gittera-sast scan test.rs
```

You should see output like:
```
Gittera SAST Analysis Results
==================================================

Summary:
  Total Findings: 15
  Critical: 0
  High: 0
  Medium: 15
  Low: 0
```

### 3. Try Different Output Formats

**JSON format:**
```bash
./target/release/gittera-sast scan test.rs --format json -o report.json
```

**SARIF format (for IDE integration):**
```bash
./target/release/gittera-sast scan test.rs --format sarif -o report.sarif
```

### 4. List Available Queries

```bash
./target/release/gittera-sast list-queries
```

Output:
```
Available Built-in Queries:
==================================================
  - sql-injection
  - command-injection
  - xss
```

## Testing with Example Code

### Create a Vulnerable Python File

```bash
cat > vulnerable.py << 'EOF'
import sqlite3

def get_user(user_id):
    # SQL Injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_id}"
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()

def run_command(cmd):
    # Command injection vulnerability
    import os
    os.system(cmd)
EOF
```

### Scan It

```bash
./target/release/gittera-sast scan vulnerable.py
```

## Command Reference

### scan
Scan files with built-in security queries.

```bash
gittera scan <FILE> [OPTIONS]

Options:
  -f, --format <FORMAT>   Output format: text, json, sarif [default: text]
  -o, --output <FILE>     Output file (default: stdout)
  -v, --verbose           Enable verbose logging
```

### analyze
Analyze with a custom GQL query.

```bash
gittera analyze <FILE> [OPTIONS]

Options:
  -q, --query <FILE>      Path to GQL query file
  -l, --language <LANG>   Force language (rust, python, javascript, etc.)
  -f, --format <FORMAT>   Output format
  -o, --output <FILE>     Output file
```

### list-queries
Show all built-in queries.

```bash
gittera list-queries
```

### validate-query
Validate a GQL query file.

```bash
gittera validate-query <QUERY_FILE>
```

## Writing Custom GQL Queries

Create a file `my-query.gql`:

```gql
// Find all function calls
from CallExpression call
where call.arguments_count > 0
select call, "Function call found"
```

Run it:
```bash
./target/release/gittera-sast analyze test.rs --query my-query.gql
```

## Supported Languages

- Rust (`.rs`)
- Python (`.py`, `.pyw`)
- JavaScript (`.js`, `.mjs`, `.cjs`)
- TypeScript (`.ts`)
- Java (`.java`)
- Go (`.go`)
- C (`.c`, `.h`)
- C++ (`.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx`)
- C# (`.cs`)
- Ruby (`.rb`)
- PHP (`.php`)

## Output Formats

### Text (Default)
Human-readable colored output for terminal viewing.

### JSON
Structured output for programmatic consumption.

```json
{
  "findings": [
    {
      "file_path": "test.rs",
      "line": 9,
      "column": 5,
      "message": "SQL injection vulnerability",
      "severity": "Critical",
      "code_snippet": "database.execute(&sql)"
    }
  ],
  "summary": {
    "total_findings": 1,
    "critical": 1,
    "high": 0,
    "medium": 0,
    "low": 0
  }
}
```

### SARIF
Standard format for static analysis tools. Compatible with:
- GitHub Security
- VS Code
- Azure DevOps
- GitLab

## Integration Examples

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Install Rust
        uses: actions-rs/toolchain@v1
      - name: Build Gittera
        run: cargo build --release
      - name: Scan Code
        run: |
          ./target/release/gittera-sast scan src/ \
            --format sarif \
            --output results.sarif
      - name: Upload Results
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### Pre-commit Hook

Create `.git/hooks/pre-commit`:

```bash
#!/bin/bash
./target/release/gittera-sast scan $(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(rs|py|js)$')
```

### VS Code Task

Add to `.vscode/tasks.json`:

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Gittera Scan",
      "type": "shell",
      "command": "./target/release/gittera-sast",
      "args": ["scan", "${file}", "--format", "json"],
      "problemMatcher": []
    }
  ]
}
```

## Troubleshooting

### Build Fails

```bash
# Update Rust
rustup update

# Clean build
cargo clean
cargo build --release
```

### Language Not Detected

Use the `--language` flag:

```bash
./target/release/gittera-sast analyze myfile.txt --language rust
```

### No Findings

- Check if the file contains actual code constructs
- Try with `--verbose` to see what's being parsed
- Verify the language is supported

### Performance Issues

For large codebases:
1. Scan incrementally (changed files only)
2. Use `--release` build
3. Exclude test files if not needed

## Next Steps

1. **Explore Built-in Queries**: Check `queries/*.gql` for examples
2. **Read the Full Documentation**: See `README.md`
3. **Check the Architecture**: Review `PROJECT_SUMMARY.md`
4. **Write Custom Queries**: Learn GQL syntax
5. **Contribute**: Add new language support or queries

## Support

- Documentation: `README.md`, `PROJECT_SUMMARY.md`
- Example Code: `examples/vulnerable-code/`
- Query Library: `queries/`

## Tips & Tricks

### Scan Multiple Files

```bash
find src -name "*.rs" -exec ./target/release/gittera-sast scan {} \;
```

### Filter by Severity

```bash
./target/release/gittera-sast scan src/ --format json | \
  jq '.findings[] | select(.severity == "Critical")'
```

### Watch for Changes

```bash
# Install cargo-watch
cargo install cargo-watch

# Rebuild on changes
cargo watch -x 'build --release'
```

### Benchmark Performance

```bash
time ./target/release/gittera-sast scan large-file.rs
```

Happy Scanning! 🔍
