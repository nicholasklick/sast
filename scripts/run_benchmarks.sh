#!/bin/bash
# Benchmark Regression Test Runner
# Runs OWASP benchmarks and checks for precision regression

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SAST_BINARY="$PROJECT_ROOT/target/release/gittera-sast"
BASELINE_FILE="$SCRIPT_DIR/benchmark_baseline.json"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=============================================="
echo "  OWASP Benchmark Regression Test"
echo "=============================================="

# Check if binary exists
if [ ! -f "$SAST_BINARY" ]; then
    echo -e "${YELLOW}Building release binary...${NC}"
    cargo build --release
fi

# Run Python benchmark if exists
if [ -d "$PROJECT_ROOT/benchmark/owasp-python/testcode" ]; then
    echo ""
    echo "Running Python OWASP Benchmark..."
    $SAST_BINARY scan "$PROJECT_ROOT/benchmark/owasp-python/testcode" --format json 2>&1 | sed -n '/{/,$p' > /tmp/python_results.json

    python3 "$SCRIPT_DIR/benchmark_score.py" \
        --language python \
        --results /tmp/python_results.json \
        --check-regression
    PYTHON_STATUS=$?
else
    echo -e "${YELLOW}Python benchmark not found, skipping${NC}"
    PYTHON_STATUS=0
fi

# Run Java benchmark if exists
if [ -d "$PROJECT_ROOT/benchmark/owasp-benchmark/src/main/java" ]; then
    echo ""
    echo "Running Java OWASP Benchmark..."
    $SAST_BINARY scan "$PROJECT_ROOT/benchmark/owasp-benchmark/src/main/java/org/owasp/benchmark/testcode" --format json 2>&1 | sed -n '/{/,$p' > /tmp/java_results.json

    python3 "$SCRIPT_DIR/benchmark_score.py" \
        --language java \
        --results /tmp/java_results.json \
        --check-regression
    JAVA_STATUS=$?
else
    echo -e "${YELLOW}Java benchmark not found, skipping${NC}"
    JAVA_STATUS=0
fi

echo ""
echo "=============================================="
echo "  Summary"
echo "=============================================="

if [ $PYTHON_STATUS -eq 0 ] && [ $JAVA_STATUS -eq 0 ]; then
    echo -e "${GREEN}All benchmarks passed!${NC}"
    exit 0
else
    echo -e "${RED}Regression detected!${NC}"
    exit 1
fi
