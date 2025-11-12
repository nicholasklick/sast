# KodeCD SAST Benchmarks

This directory contains comprehensive performance benchmarks for the KodeCD SAST engine using Criterion.rs.

## Overview

The benchmark suite measures performance across three main areas:
1. **Parser Performance** - Tree-sitter parsing across languages
2. **Query Execution** - KQL query parsing and execution
3. **Taint Analysis** - Data flow analysis performance

## Benchmark Suites

### 1. Parser Benchmarks (`parser_benchmark.rs`)

Tests parser performance with various code complexities and languages.

**Benchmarks:**
- `parser_simple` - Simple code (variable declarations)
- `parser_medium` - Medium complexity (functions, classes)
- `parser_complex` - Complex code (imports, interfaces, services)
- `parser_languages` - Comparison across 6 languages
- `parser_scaling` - Input size scaling (100 to 10,000 lines)

**Key Metrics:**
- Throughput (bytes/second)
- Standard vs Arena parser comparison
- Multi-language performance

### 2. Query Benchmarks (`query_benchmark.rs`)

Tests KQL query parsing and execution performance.

**Benchmarks:**
- `query_parsing` - Query parse time (simple, complex, taint)
- `query_execution` - Query execution time
- `query_stdlib` - OWASP standard library queries
- `query_operators` - Comparison operators (==, CONTAINS, MATCHES, etc.)

**Key Metrics:**
- Query parse time
- Query execution time
- Operator efficiency

### 3. Taint Analysis Benchmarks (`taint_analysis_benchmark.rs`)

Tests data flow analysis performance.

**Benchmarks:**
- `cfg_build` - Control Flow Graph construction
- `taint_analysis` - Taint tracking performance
- `taint_analysis_config` - Configuration impact
- `full_pipeline` - End-to-end parsing → CFG → taint analysis
- `taint_scaling` - Performance with varying taint flow counts

**Key Metrics:**
- CFG build time
- Taint propagation speed
- Scalability with multiple flows

## Running Benchmarks

### Run All Benchmarks

```bash
cargo bench
```

### Run Specific Suite

```bash
# Parser benchmarks only
cargo bench --bench parser_benchmark

# Query benchmarks only
cargo bench --bench query_benchmark

# Taint analysis benchmarks only
cargo bench --bench taint_analysis_benchmark
```

### Run Specific Benchmark

```bash
# Run parser simple benchmark
cargo bench --bench parser_benchmark -- parser_simple

# Run query parsing benchmark
cargo bench --bench query_benchmark -- query_parsing

# Run taint analysis scaling benchmark
cargo bench --bench taint_analysis_benchmark -- taint_scaling
```

### Filter by Name

```bash
# All benchmarks containing "simple"
cargo bench -- simple

# All benchmarks containing "complex"
cargo bench -- complex
```

## Benchmark Output

Criterion generates HTML reports in `target/criterion/`:

```bash
# View report in browser
open target/criterion/report/index.html
```

### Console Output

```
parser_simple/standard  time:   [123.45 µs 125.67 µs 127.89 µs]
                        thrpt:  [1.2345 MiB/s 1.2567 MiB/s 1.2789 MiB/s]

parser_simple/arena     time:   [98.76 µs 100.12 µs 101.34 µs]
                        thrpt:  [1.5432 MiB/s 1.5678 MiB/s 1.5901 MiB/s]
                        change: [-20.123% -18.456% -16.789%] (p = 0.00 < 0.05)
                        Performance has improved.
```

## Performance Targets

Based on benchmarks, these are the target performance metrics:

### Parser Performance
- **Simple code** (<100 lines): <1ms
- **Medium code** (100-500 lines): <5ms
- **Complex code** (500-1000 lines): <20ms
- **Throughput**: >50 MB/s for TypeScript

### Query Performance
- **Query parsing**: <1ms per query
- **Query execution**: <5ms per file
- **OWASP queries**: <10ms per query per file

### Taint Analysis Performance
- **CFG build**: <2ms for medium complexity
- **Taint analysis**: <10ms for 10 taint flows
- **Full pipeline**: <50ms for complex code

## Comparing Results

### Baseline

Save current performance as baseline:

```bash
cargo bench --bench parser_benchmark -- --save-baseline main
```

### Compare Against Baseline

```bash
cargo bench --bench parser_benchmark -- --baseline main
```

### Compare Two Baselines

```bash
# Run benchmark and save as 'new-feature'
cargo bench -- --save-baseline new-feature

# Compare
cargo bench -- --baseline main --baseline new-feature
```

## Profiling

### CPU Profiling with Flamegraph

```bash
# Install cargo-flamegraph
cargo install flamegraph

# Profile parser benchmark
cargo flamegraph --bench parser_benchmark

# View flamegraph.svg
open flamegraph.svg
```

### Memory Profiling

```bash
# Install valgrind and cargo-valgrind
cargo install cargo-valgrind

# Run with valgrind
cargo valgrind --bench parser_benchmark
```

## Continuous Benchmarking

### GitHub Actions Example

```yaml
name: Benchmarks

on:
  push:
    branches: [main]
  pull_request:

jobs:
  benchmark:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: dtolnay/rust-toolchain@stable

      - name: Run benchmarks
        run: cargo bench --all-features

      - name: Upload results
        uses: actions/upload-artifact@v3
        with:
          name: criterion-results
          path: target/criterion
```

## Optimization Tips

Based on benchmark results:

1. **Use Arena Parser** for batch processing (20-30% faster, 50-60% less memory)
2. **Cache Parsed Queries** - Query parsing is ~1ms overhead
3. **Parallel Analysis** - Use rayon for multi-file analysis
4. **Limit Taint Depth** - Deep taint tracking has quadratic complexity
5. **Profile-Guided Optimization** - Use `cargo pgo` for production builds

## Understanding Results

### Statistical Significance

Criterion uses statistical analysis to determine if performance changed:

- **p-value < 0.05**: Change is statistically significant
- **Outliers**: Marked as "mild" or "severe" in results
- **R² value**: How well the linear model fits (higher is better)

### Variance

- **Low variance** (<5%): Stable, reproducible results
- **High variance** (>10%): May need longer warm-up or sample time

### Throughput

Throughput is calculated as:
```
throughput = input_size / execution_time
```

Higher throughput means better performance.

## Troubleshooting

### Benchmarks Take Too Long

Reduce sample size:

```bash
cargo bench -- --sample-size 10
```

### Unstable Results

Increase measurement time:

```bash
cargo bench -- --measurement-time 10
```

### Memory Issues

Reduce benchmark complexity or use `--release`:

```bash
cargo bench --release
```

## See Also

- [Criterion.rs User Guide](https://bheisler.github.io/criterion.rs/book/)
- [Rust Performance Book](https://nnethercote.github.io/perf-book/)
- [cargo-flamegraph](https://github.com/flamegraph-rs/flamegraph)
