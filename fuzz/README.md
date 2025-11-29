# Fuzzing for Gittera SAST

This directory contains fuzz targets for testing the robustness of the SAST engine using `cargo-fuzz` and libFuzzer.

## Overview

Fuzzing is an automated testing technique that feeds random or malformed inputs to the system to find crashes, panics, and unexpected behavior. This is critical for a security tool like Gittera SAST.

## Fuzz Targets

### 1. `fuzz_parser` - Parser Fuzzing

Tests the TypeScript/JavaScript parser with arbitrary input to ensure:
- No panics on malformed code
- Safe handling of invalid UTF-8
- Robust error handling
- Memory safety

**Coverage**: All tree-sitter parsers (TypeScript, JavaScript, Python, Rust, etc.)

### 2. `fuzz_query` - Query Language Fuzzing

Tests the KQL (Gittera Query Language) parser with random query strings to ensure:
- No panics on invalid query syntax
- Safe handling of malformed queries
- Robust error messages
- No undefined behavior

**Coverage**: KQL lexer, parser, and AST construction

### 3. `fuzz_taint_analysis` - Taint Analysis Fuzzing

Tests the full pipeline from parsing to taint analysis:
- Parser → AST → CFG → Taint Analysis
- Complex control flow scenarios
- Edge cases in data flow tracking
- Integration testing of multiple components

**Coverage**: Full analysis pipeline

## Prerequisites

Install `cargo-fuzz`:

```bash
cargo install cargo-fuzz
```

**Note**: Fuzzing requires a nightly Rust toolchain:

```bash
rustup install nightly
```

## Running Fuzz Targets

### Quick Start

Run a specific fuzz target:

```bash
# Fuzz the parser
cargo +nightly fuzz run fuzz_parser

# Fuzz the query language
cargo +nightly fuzz run fuzz_query

# Fuzz taint analysis
cargo +nightly fuzz run fuzz_taint_analysis
```

### With Time Limit

Run for a specific duration:

```bash
# Run for 60 seconds
cargo +nightly fuzz run fuzz_parser -- -max_total_time=60

# Run for 5 minutes
cargo +nightly fuzz run fuzz_query -- -max_total_time=300
```

### Parallel Fuzzing

Run with multiple jobs for faster coverage:

```bash
cargo +nightly fuzz run fuzz_parser -- -jobs=4 -workers=4
```

### With Corpus

Use a seed corpus for more targeted fuzzing:

```bash
# Create corpus directory
mkdir -p fuzz/corpus/fuzz_parser

# Add seed files (valid TypeScript/JavaScript)
echo "const x = 42;" > fuzz/corpus/fuzz_parser/simple.ts
echo "function foo() { return 1; }" > fuzz/corpus/fuzz_parser/function.ts

# Run with corpus
cargo +nightly fuzz run fuzz_parser
```

## Analyzing Results

### Crash Artifacts

When a crash is found, it's saved to `fuzz/artifacts/`:

```bash
# View crash
cat fuzz/artifacts/fuzz_parser/crash-<hash>

# Reproduce crash
cargo +nightly fuzz run fuzz_parser fuzz/artifacts/fuzz_parser/crash-<hash>
```

### Coverage Report

Generate coverage report:

```bash
cargo +nightly fuzz coverage fuzz_parser
```

## Continuous Fuzzing

For CI/CD integration:

```bash
# Run each target for 5 minutes
for target in fuzz_parser fuzz_query fuzz_taint_analysis; do
  cargo +nightly fuzz run $target -- -max_total_time=300 || exit 1
done
```

## Best Practices

1. **Run Regularly**: Fuzz for at least 1 hour per target weekly
2. **Use Corpus**: Maintain a corpus of valid inputs for better coverage
3. **Monitor Coverage**: Track code coverage improvements over time
4. **Fix Crashes**: Prioritize fixing any crashes or panics found
5. **Seed Corpus**: Add interesting test cases to the corpus

## Expected Behavior

All fuzz targets should:
- ✅ Never panic
- ✅ Never crash
- ✅ Handle invalid input gracefully
- ✅ Return errors (not panic) for malformed input
- ✅ Maintain memory safety

## Troubleshooting

### Nightly Toolchain Required

If you see "error: fuzz target must be built with nightly":

```bash
rustup install nightly
cargo +nightly fuzz run fuzz_parser
```

### Out of Memory

Reduce memory usage:

```bash
cargo +nightly fuzz run fuzz_parser -- -rss_limit_mb=2048
```

### Slow Execution

Increase timeout for slow inputs:

```bash
cargo +nightly fuzz run fuzz_parser -- -timeout=25
```

## Integration with CI

Example GitHub Actions workflow:

```yaml
name: Fuzz Testing

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@nightly
      - run: cargo install cargo-fuzz
      - name: Fuzz Parser
        run: cargo +nightly fuzz run fuzz_parser -- -max_total_time=300
      - name: Fuzz Query
        run: cargo +nightly fuzz run fuzz_query -- -max_total_time=300
      - name: Fuzz Taint Analysis
        run: cargo +nightly fuzz run fuzz_taint_analysis -- -max_total_time=300
```

## See Also

- [cargo-fuzz book](https://rust-fuzz.github.io/book/cargo-fuzz.html)
- [libFuzzer documentation](https://llvm.org/docs/LibFuzzer.html)
- [OSS-Fuzz](https://google.github.io/oss-fuzz/) - For long-term continuous fuzzing
