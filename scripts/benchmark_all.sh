#!/bin/bash
# Run OWASP benchmarks for all supported languages
# Usage: ./scripts/benchmark_all.sh [--quick] [--lang LANG]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
OWASP_ROOT="${PROJECT_ROOT}/../owasp"
BINARY="${PROJECT_ROOT}/target/release/gittera-sast"
SCORE_SCRIPT="${SCRIPT_DIR}/benchmark_score.py"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Parse arguments
QUICK_MODE=false
LANG_FILTER=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --lang)
            LANG_FILTER="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--quick] [--lang LANG]"
            exit 1
            ;;
    esac
done

# Ensure binary is built
if [[ ! -f "$BINARY" ]]; then
    echo -e "${YELLOW}Building release binary...${NC}"
    cargo build --release
fi

# Define benchmarks
declare -A BENCHMARKS=(
    ["java"]="BenchmarkJava/src/main/java/org/owasp/benchmark/testcode|expectedresults-1.2.csv"
    ["python"]="BenchmarkPython/src/main/python|expectedresults-0.1.csv"
    ["javascript"]="BenchmarkJS/src/main/js|expectedresults-0.1.csv"
    ["typescript"]="BenchmarkTypeScript/src/main/ts|expectedresults-0.1.csv"
    ["ruby"]="BenchmarkRuby/src/main/ruby|expectedresults-0.1.csv"
    ["rust"]="BenchmarkRust/src/main/rust|expectedresults-0.1.csv"
    ["go"]="BenchmarkGolang/internal/testcases|expectedresults-0.1.csv"
)

# Results storage
declare -A RESULTS

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║           OWASP Benchmark Multi-Language Test Suite            ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Run benchmarks
for lang in "${!BENCHMARKS[@]}"; do
    # Apply language filter if specified
    if [[ -n "$LANG_FILTER" && "$lang" != "$LANG_FILTER" ]]; then
        continue
    fi

    IFS='|' read -r src_path expected_file <<< "${BENCHMARKS[$lang]}"

    benchmark_dir="${OWASP_ROOT}/$(echo $src_path | cut -d'/' -f1)"
    src_full_path="${OWASP_ROOT}/${src_path}"
    expected_full_path="${benchmark_dir}/${expected_file}"

    # Check if paths exist
    if [[ ! -d "$src_full_path" ]]; then
        echo -e "${YELLOW}⚠ Skipping ${lang}: Source path not found${NC}"
        echo "  Expected: $src_full_path"
        continue
    fi

    if [[ ! -f "$expected_full_path" ]]; then
        echo -e "${YELLOW}⚠ Skipping ${lang}: Ground truth not found${NC}"
        echo "  Expected: $expected_full_path"
        continue
    fi

    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Testing: ${lang^^}${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "Source: $src_full_path"
    echo "Ground truth: $expected_full_path"
    echo ""

    # Run scan and score
    start_time=$(date +%s)

    if $QUICK_MODE; then
        # Quick mode: just count findings
        finding_count=$(RUST_LOG=error "$BINARY" scan "$src_full_path" --output json 2>/dev/null | grep -c '"rule_id"' || echo "0")
        echo "Findings: $finding_count"
        RESULTS[$lang]="Quick mode: $finding_count findings"
    else
        # Full mode: run scoring
        output=$(RUST_LOG=error "$BINARY" scan "$src_full_path" --output json 2>/dev/null | \
                 python3 "$SCORE_SCRIPT" "$expected_full_path" 2>/dev/null || echo "FAILED")

        if [[ "$output" == "FAILED" ]]; then
            echo -e "${RED}✗ Scoring failed${NC}"
            RESULTS[$lang]="FAILED"
        else
            echo "$output"

            # Extract metrics from output
            precision=$(echo "$output" | grep -o 'Precision: [0-9.]*%' | head -1 || echo "N/A")
            recall=$(echo "$output" | grep -o 'Recall: [0-9.]*%' | head -1 || echo "N/A")
            f1=$(echo "$output" | grep -o 'F1: [0-9.]*%' | head -1 || echo "N/A")

            RESULTS[$lang]="$precision | $recall | $f1"
        fi
    fi

    end_time=$(date +%s)
    duration=$((end_time - start_time))
    echo ""
    echo "Duration: ${duration}s"
    echo ""
done

# Print summary
echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                        SUMMARY                                 ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "| Language    | Precision      | Recall         | F1 Score      |"
echo "|-------------|----------------|----------------|---------------|"

for lang in java python javascript typescript ruby rust go; do
    if [[ -n "${RESULTS[$lang]}" ]]; then
        printf "| %-11s | %-42s |\n" "$lang" "${RESULTS[$lang]}"
    fi
done

echo ""
echo -e "${GREEN}Benchmark testing complete!${NC}"
